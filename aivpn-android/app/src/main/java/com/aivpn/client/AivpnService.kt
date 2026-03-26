package com.aivpn.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.*
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

/**
 * Android VPN service that tunnels all device traffic through the AIVPN server.
 *
 * Uses the standard Android VpnService API which provides a TUN file descriptor.
 * The service runs in the foreground with a persistent notification.
 */
class AivpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "com.aivpn.CONNECT"
        const val ACTION_DISCONNECT = "com.aivpn.DISCONNECT"
        private const val CHANNEL_ID = "aivpn_vpn"
        private const val NOTIFICATION_ID = 1

        // Callback to update the UI from the service
        var statusCallback: ((connected: Boolean, status: String) -> Unit)? = null
        var trafficCallback: ((uploadBytes: Long, downloadBytes: Long) -> Unit)? = null
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var serviceJob: Job? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var udpSocket: DatagramSocket? = null

    // Traffic counters
    @Volatile private var totalUploadBytes: Long = 0
    @Volatile private var totalDownloadBytes: Long = 0

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val server = intent.getStringExtra("server") ?: return START_NOT_STICKY
                val serverKey = intent.getStringExtra("server_key") ?: return START_NOT_STICKY
                startVpn(server, serverKey)
            }
            ACTION_DISCONNECT -> {
                stopVpn()
            }
        }
        return START_STICKY
    }

    private fun startVpn(serverAddr: String, serverKeyBase64: String) {
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification(getString(R.string.notification_connecting)))

        // Reset traffic counters
        totalUploadBytes = 0
        totalDownloadBytes = 0

        serviceJob = serviceScope.launch {
            try {
                statusCallback?.invoke(true, getString(R.string.status_connecting))

                // Parse server address
                val parts = serverAddr.split(":")
                val host = parts[0]
                val port = parts.getOrElse(1) { "443" }.toInt()

                // Decode server public key
                val serverKey = android.util.Base64.decode(
                    serverKeyBase64, android.util.Base64.DEFAULT
                )
                if (serverKey.size != 32) {
                    statusCallback?.invoke(false, getString(R.string.error_invalid_key))
                    stopSelf()
                    return@launch
                }

                // Initialize crypto engine
                val crypto = AivpnCrypto(serverKey)

                // Create UDP socket to the AIVPN server
                val socket = DatagramSocket()
                socket.connect(InetSocketAddress(host, port))
                udpSocket = socket

                // Protect the UDP socket from being routed through our own VPN
                protect(socket)

                // Send init handshake (eph_pub + keepalive)
                val initPacket = crypto.buildInitPacket()
                socket.send(DatagramPacket(initPacket, initPacket.size))

                // Wait for ServerHello response
                val recvBuf = ByteArray(2048)
                val response = DatagramPacket(recvBuf, recvBuf.size)
                socket.soTimeout = 5000
                socket.receive(response)

                // Process ServerHello and complete PFS ratchet
                val serverHelloData = recvBuf.copyOf(response.length)
                if (!crypto.processServerHello(serverHelloData)) {
                    statusCallback?.invoke(false, getString(R.string.error_handshake))
                    stopSelf()
                    return@launch
                }
                socket.soTimeout = 0 // Remove timeout for normal operation

                // Establish TUN interface via Android's VpnService API
                val builder = Builder()
                    .setSession("AIVPN")
                    .addAddress("10.0.0.2", 24)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer("8.8.8.8")
                    .addDnsServer("1.1.1.1")
                    .setMtu(1280)
                    .setBlocking(true)

                vpnInterface = builder.establish()
                    ?: throw Exception("Failed to establish VPN interface")

                statusCallback?.invoke(true, getString(R.string.status_connected, host))
                updateNotification(getString(R.string.notification_connected, host))

                val tunFd = vpnInterface!!
                val tunIn = FileInputStream(tunFd.fileDescriptor)
                val tunOut = FileOutputStream(tunFd.fileDescriptor)

                // Launch two coroutines for bidirectional forwarding
                val tunToUdp = launch {
                    tunToServer(tunIn, socket, crypto)
                }
                val udpToTun = launch {
                    serverToTun(socket, tunOut, crypto)
                }
                val keepaliveLoop = launch {
                    keepaliveToServer(socket, crypto)
                }

                // Wait until either direction fails or is cancelled
                tunToUdp.join()
                udpToTun.join()
                keepaliveLoop.join()

            } catch (e: CancellationException) {
                // Normal shutdown
            } catch (e: Exception) {
                statusCallback?.invoke(false, getString(R.string.status_error, e.message ?: "unknown"))
            } finally {
                cleanup()
            }
        }
    }

    /**
     * TUN → Server: read IP packets from the device, encrypt with AIVPN protocol,
     * send as UDP datagrams to the server.
     */
    private suspend fun tunToServer(
        tunIn: FileInputStream,
        socket: DatagramSocket,
        crypto: AivpnCrypto
    ) = withContext(Dispatchers.IO) {
        val buf = ByteArray(1500)
        while (isActive) {
            try {
                val n = tunIn.read(buf)
                if (n > 0) {
                    val ipPacket = buf.copyOf(n)
                    val encrypted = crypto.encryptDataPacket(ipPacket)
                    socket.send(DatagramPacket(encrypted, encrypted.size))
                    totalUploadBytes += n
                    trafficCallback?.invoke(totalUploadBytes, totalDownloadBytes)
                }
            } catch (e: Exception) {
                if (isActive) throw e
            }
        }
    }

    /**
     * Server → TUN: receive encrypted UDP datagrams from the server, decrypt,
     * extract the IP packet, write it to the TUN device.
     */
    private suspend fun serverToTun(
        socket: DatagramSocket,
        tunOut: FileOutputStream,
        crypto: AivpnCrypto
    ) = withContext(Dispatchers.IO) {
        val buf = ByteArray(2048)
        while (isActive) {
            try {
                val pkt = DatagramPacket(buf, buf.size)
                socket.receive(pkt)
                val data = buf.copyOf(pkt.length)
                val decrypted = crypto.decryptDataPacket(data)
                if (decrypted != null && decrypted.isNotEmpty()) {
                    tunOut.write(decrypted)
                    tunOut.flush()
                    totalDownloadBytes += decrypted.size
                    trafficCallback?.invoke(totalUploadBytes, totalDownloadBytes)
                }
            } catch (e: Exception) {
                if (isActive) throw e
            }
        }
    }

    /**
     * Keep the UDP mapping and server session alive while the tunnel is idle.
     */
    private suspend fun keepaliveToServer(
        socket: DatagramSocket,
        crypto: AivpnCrypto
    ) = withContext(Dispatchers.IO) {
        while (isActive) {
            try {
                delay(15_000)
                val keepalive = crypto.buildKeepalivePacket()
                socket.send(DatagramPacket(keepalive, keepalive.size))
            } catch (e: SocketTimeoutException) {
                if (isActive) throw e
            } catch (e: Exception) {
                if (isActive) throw e
            }
        }
    }

    private fun stopVpn() {
        serviceJob?.cancel()
        cleanup()
        statusCallback?.invoke(false, getString(R.string.status_disconnected))
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun cleanup() {
        try { vpnInterface?.close() } catch (_: Exception) {}
        try { udpSocket?.close() } catch (_: Exception) {}
        vpnInterface = null
        udpSocket = null
    }

    override fun onDestroy() {
        serviceJob?.cancel()
        cleanup()
        super.onDestroy()
    }

    // ──────────── Notifications ────────────

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID, getString(R.string.notification_channel),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.notification_channel_desc)
        }
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(channel)
    }

    private fun buildNotification(text: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("AIVPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }
}
