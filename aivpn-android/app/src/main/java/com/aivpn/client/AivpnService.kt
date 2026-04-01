package com.aivpn.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*

/**
 * Android VPN service — thin orchestrator over the Rust core (libaivpn_core.so).
 *
 * Responsibilities that must stay in Kotlin (Android API only):
 *   - VpnService.Builder / TUN interface establishment
 *   - NetworkCallback for network-change detection
 *   - VpnService.protect() — called from inside Rust via JNI on this instance
 *   - Foreground notification lifecycle
 *
 * Everything else (crypto, handshake, keepalive, anti-replay, rekey) is in Rust.
 */
class AivpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT    = "com.aivpn.CONNECT"
        const val ACTION_DISCONNECT = "com.aivpn.DISCONNECT"
        private const val CHANNEL_ID      = "aivpn_vpn"
        private const val NOTIFICATION_ID = 1
        private const val TUN_MTU         = 1420
        private const val INITIAL_RETRY_DELAY_MS = 500L
        private const val MAX_RETRY_DELAY_MS     = 8_000L
        private const val TAG = "AivpnService"

        @Volatile var statusCallback:  ((Boolean, String) -> Unit)? = null
        @Volatile var trafficCallback: ((Long, Long) -> Unit)?      = null
        @Volatile var isRunning     = false
        @Volatile var lastStatusText = ""
    }

    // TUN interface wrapper (Kotlin holds PFD for lifecycle; Rust holds raw fd after detach)
    private var vpnInterface: ParcelFileDescriptor? = null

    // Coroutine lifecycle
    private var serviceJob: Job? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    @Volatile private var manualDisconnect = false

    // Saved params for reconnect
    @Volatile private var savedServerAddr: String? = null
    @Volatile private var savedServerKey: String?  = null
    @Volatile private var savedPsk: String?        = null
    @Volatile private var savedVpnIp: String?      = null

    // Whether the current session reached the running state
    @Volatile private var sessionEstablished = false

    // Monotonically-increasing session counter.  Incremented on every new tunnel session.
    // Captured in upgradePendingJob at trigger time so a stale job can't kill a newer session.
    @Volatile private var sessionId: Long = 0L

    // Network change detection
    @Volatile private var sessionNetwork: Network? = null
    @Volatile private var targetNetwork: Network?  = null
    @Volatile private var upgradePendingJob: Job?  = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    // ──────────── Service lifecycle ────────────

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val server    = intent.getStringExtra("server")     ?: return START_NOT_STICKY
                val serverKey = intent.getStringExtra("server_key") ?: return START_NOT_STICKY
                startVpn(server, serverKey,
                    intent.getStringExtra("psk"),
                    intent.getStringExtra("vpn_ip"))
            }
            ACTION_DISCONNECT -> stopVpn()
        }
        return START_STICKY
    }

    private fun startVpn(
        serverAddr: String,
        serverKeyBase64: String,
        pskBase64: String? = null,
        vpnIp: String? = null,
    ) {
        Log.d(TAG, "startVpn: server=$serverAddr")
        savedServerAddr  = serverAddr
        savedServerKey   = serverKeyBase64
        savedPsk         = pskBase64
        savedVpnIp       = vpnIp
        manualDisconnect = false

        serviceJob?.cancel()
        serviceJob = null
        closeTunnel()

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification(getString(R.string.notification_connecting)))

        unregisterNetworkCallback()
        registerNetworkCallback()

        serviceJob = serviceScope.launch {
            var retryDelayMs = INITIAL_RETRY_DELAY_MS
            try {
                while (isActive && !manualDisconnect) {
                    try {
                        sessionEstablished = false
                        runTunnel()
                        // runTunnel() returns normally only on Rust rekey trigger — reconnect fast.
                        retryDelayMs = INITIAL_RETRY_DELAY_MS
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        Log.e(TAG, "Tunnel error: ${e.message}", e)
                        isRunning = false
                        upgradePendingJob?.cancel()
                        upgradePendingJob = null
                        closeTunnel()
                        if (manualDisconnect) break
                        if (sessionEstablished) retryDelayMs = INITIAL_RETRY_DELAY_MS
                        lastStatusText = getString(R.string.status_reconnecting)
                        statusCallback?.invoke(false, lastStatusText)
                        updateNotification(getString(R.string.notification_connecting))
                        Log.d(TAG, "Reconnecting in ${retryDelayMs}ms")
                        delay(retryDelayMs)
                        retryDelayMs = (retryDelayMs * 2).coerceAtMost(MAX_RETRY_DELAY_MS)
                    }
                }
            } catch (e: CancellationException) {
                Log.d(TAG, "Service job cancelled")
            } finally {
                isRunning = false
                closeTunnel()
                serviceJob = null
                if (!manualDisconnect) {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }
    }

    // ──────────── Tunnel session ────────────

    /**
     * One tunnel session.  Blocks until the Rust core exits (error or rekey interval).
     * Any exception propagates to the reconnect loop.
     */
    private suspend fun runTunnel() {
        val network = waitForNetwork()
        sessionNetwork = network

        val (host, port) = parseServerAddr(
            savedServerAddr ?: throw Exception("No server address"))

        val serverKey = android.util.Base64.decode(
            savedServerKey ?: throw Exception("No server key"),
            android.util.Base64.DEFAULT)
        if (serverKey.size != 32) throw Exception("Invalid server key size: ${serverKey.size}")

        val psk: ByteArray? = savedPsk?.let {
            val decoded = android.util.Base64.decode(it, android.util.Base64.DEFAULT)
            if (decoded.size == 32) decoded else null
        }

        val tunAddress4 = savedVpnIp ?: "10.0.0.2"

        // Build TUN (must stay in Kotlin — Android API).
        // setBlocking(false): Rust uses epoll/AsyncFd on the raw fd.
        //
        // IPv6 strategy: we do NOT support IPv6 forwarding, but we MUST route ::/0 into the
        // TUN to prevent IPv6 leaks (traffic bypassing the VPN on the real interface).
        // A dummy ULA address is required so Android accepts the ::/0 route.
        // Rust drops all non-IPv4 packets it reads from TUN, so they go nowhere safely.
        val pfd = Builder()
            .setSession("AIVPN")
            .addAddress(tunAddress4, 24)
            .addRoute("0.0.0.0", 0)          // IPv4: route all through VPN
            .addAddress("fd00::2", 128)       // dummy ULA — required to bind ::/0 route
            .addRoute("::", 0)               // IPv6: route all through VPN (dropped in Rust)
            .addDnsServer("8.8.8.8")
            .addDnsServer("1.1.1.1")
            .addDnsServer("2001:4860:4860::8888") // Google DNS over IPv4 (reachable via v4)
            .setMtu(TUN_MTU)
            .setBlocking(false)
            .establish() ?: throw Exception("Failed to establish VPN interface")

        vpnInterface = pfd
        setUnderlyingNetworks(arrayOf(network))

        // detachFd(): raw fd ownership transfers to Rust.  pfd.close() becomes a no-op.
        val tunFd = pfd.detachFd()

        sessionEstablished = true
        isRunning          = true
        sessionId++     // new session — invalidates any queued upgradePendingJob
        lastStatusText = getString(R.string.status_connected, host)
        statusCallback?.invoke(true, lastStatusText)
        updateNotification(getString(R.string.notification_connected, host))

        // Poll Rust traffic counters once per second and forward to UI.
        val statsJob = serviceScope.launch {
            while (isActive) {
                delay(1_000L)
                trafficCallback?.invoke(AivpnJni.getUploadBytes(), AivpnJni.getDownloadBytes())
            }
        }

        try {
            val error = withContext(Dispatchers.IO) {
                AivpnJni.runTunnel(this@AivpnService, tunFd, host, port, serverKey, psk)
            }
            if (error.isNotEmpty()) throw RuntimeException(error)
        } finally {
            statsJob.cancel()
            isRunning = false
        }
    }

    // ──────────── Network callbacks ────────────

    private fun registerNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()

        val callback = object : ConnectivityManager.NetworkCallback() {

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                val session = sessionNetwork ?: return
                if (network == session) return
                // We only care about WiFi networks we could upgrade to.
                if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) return

                // Only upgrade cellular→WiFi.  WiFi→WiFi would cause needless churn.
                val sessionCaps = cm.getNetworkCapabilities(session) ?: return
                if (sessionCaps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return

                // Capture state NOW so the deferred job can detect session staleness.
                val capturedSessionId = sessionId
                val capturedSession   = session

                upgradePendingJob?.cancel()
                upgradePendingJob = serviceScope.launch {
                    delay(2_000L)
                    // Abort if a new tunnel session was started since this job was queued.
                    if (sessionId != capturedSessionId) return@launch
                    val stillValid = cm.getNetworkCapabilities(network)
                        ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
                    val stillOnSameSession = sessionNetwork == capturedSession
                    if (stillValid && stillOnSameSession) {
                        // Always upgrade cellular→WiFi when WiFi is stable.
                        // DO NOT guard on active traffic — that would permanently block the
                        // upgrade because lastRxMs is refreshed every second by keepalives.
                        Log.d(TAG, "WiFi stable — upgrading from cellular: $capturedSession -> $network")
                        targetNetwork = network
                        setUnderlyingNetworks(arrayOf(network))
                        AivpnJni.stopTunnel()
                    }
                }
            }

            override fun onLost(network: Network) {
                if (network != sessionNetwork) return
                Log.d(TAG, "Session network lost: $network")
                upgradePendingJob?.cancel()
                AivpnJni.stopTunnel()
            }
        }
        try {
            cm.registerNetworkCallback(request, callback)
            networkCallback = callback
        } catch (e: Exception) {
            Log.e(TAG, "Failed to register NetworkCallback: ${e.message}", e)
        }
    }

    private fun unregisterNetworkCallback() {
        upgradePendingJob?.cancel()
        upgradePendingJob = null
        networkCallback?.let {
            try {
                (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
                    .unregisterNetworkCallback(it)
            } catch (_: Exception) {}
            networkCallback = null
        }
    }

    // ──────────── Stop ────────────

    private fun stopVpn() {
        manualDisconnect = true
        unregisterNetworkCallback()
        AivpnJni.stopTunnel()
        serviceJob?.cancel()
        serviceJob = null
        closeTunnel()
        isRunning = false
        lastStatusText = getString(R.string.status_disconnected)
        statusCallback?.invoke(false, lastStatusText)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun closeTunnel() {
        sessionNetwork = null
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
    }

    /**
     * Called when Android revokes the VPN permission (e.g. another VPN app takes over).
     * Default VpnService.onRevoke() calls stopSelf() which kills the service with no reconnect.
     * We signal Rust to exit cleanly; the reconnect loop in serviceJob will then restart the
     * tunnel automatically (unless manualDisconnect is true).
     */
    override fun onRevoke() {
        Log.w(TAG, "onRevoke() — signalling Rust to exit, reconnect loop will restart")
        AivpnJni.stopTunnel()
        // Do NOT call super.onRevoke() — it calls stopSelf() which bypasses reconnect.
    }

    override fun onDestroy() {
        manualDisconnect = true
        unregisterNetworkCallback()
        AivpnJni.stopTunnel()
        serviceJob?.cancel()
        serviceJob = null
        closeTunnel()
        isRunning = false
        serviceScope.cancel()
        super.onDestroy()
    }

    // ──────────── Network waiting ────────────

    private suspend fun waitForNetwork(): Network {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        while (currentCoroutineContext().isActive) {
            val target = targetNetwork
            if (target != null) {
                val caps = cm.getNetworkCapabilities(target)
                if (caps != null &&
                    !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                    targetNetwork = null
                    return target
                } else {
                    targetNetwork = null
                }
            }
            // Scan allNetworks: activeNetwork may still point to the VPN interface briefly.
            // Sort by preference: WiFi > Ethernet > Cellular.
            // allNetworks order is NOT guaranteed — without sorting the first entry could be
            // cellular even when WiFi is fully available, causing the app to use mobile data.
            val best = cm.allNetworks
                .filter { net ->
                    val caps = cm.getNetworkCapabilities(net) ?: return@filter false
                    !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                }
                .maxByOrNull { net ->
                    val caps = cm.getNetworkCapabilities(net) ?: return@maxByOrNull 0
                    when {
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)     -> 2
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 1
                        else -> 0 // CELLULAR — last resort
                    }
                }
            if (best != null) return best
            delay(300L)
        }
        throw CancellationException("Cancelled while waiting for network")
    }

    // ──────────── Address parsing ────────────

    private fun parseServerAddr(serverAddr: String): Pair<String, Int> {
        if (serverAddr.startsWith("[")) {
            val bracket = serverAddr.indexOf(']')
            if (bracket > 0) {
                val host = serverAddr.substring(1, bracket)
                val port = if (bracket + 1 < serverAddr.length && serverAddr[bracket + 1] == ':')
                    serverAddr.substring(bracket + 2).toIntOrNull() ?: 443
                else 443
                return Pair(host, port)
            }
        }
        val lastColon = serverAddr.lastIndexOf(':')
        val port = if (lastColon >= 0) serverAddr.substring(lastColon + 1).toIntOrNull() else null
        return if (port != null)
            Pair(serverAddr.substring(0, lastColon), port)
        else
            Pair(serverAddr, 443)
    }

    // ──────────── Notifications ────────────

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID, getString(R.string.notification_channel),
            NotificationManager.IMPORTANCE_LOW
        ).apply { description = getString(R.string.notification_channel_desc) }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun buildNotification(text: String): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("AIVPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(text))
    }
}
