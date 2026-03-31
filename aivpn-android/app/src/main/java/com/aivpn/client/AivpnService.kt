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
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.selects.select
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException

/**
 * Android VPN service — WireGuard-like architecture.
 *
 * Принципы:
 * - Один источник правды: корутина-цикл в [startVpn]
 * - Любая ошибка сокета/TUN → исключение → cleanup → переподключение
 * - Network callback просто закрывает сокет, остальное делает нормальный путь обработки ошибок
 * - Keepalive ТОЛЬКО для NAT, НЕ рвёт соединение
 * - Нет connectionGeneration, networkChanged, keepalivePending, сложного backoff
 */
class AivpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "com.aivpn.CONNECT"
        const val ACTION_DISCONNECT = "com.aivpn.DISCONNECT"
        private const val CHANNEL_ID = "aivpn_vpn"
        private const val NOTIFICATION_ID = 1
        private const val TUN_MTU = 1420
        private const val KEEPALIVE_INTERVAL_MS = 10_000L // 10с — только для NAT
        private const val SOCKET_TIMEOUT_MS = 5_000L     // таймаут receive
        private const val DEAD_TUNNEL_TIMEOUT_MS = 15_000L // нет пакетов от сервера = туннель мёртв
        private const val RETRY_DELAY_MS = 500L          // фиксированная задержка реконнекта
        private const val NETWORK_DEBOUNCE_MS = 1_000L   // debounce для network callback
        private const val TAG = "AivpnService"

        @Volatile var statusCallback: ((connected: Boolean, status: String) -> Unit)? = null
        @Volatile var trafficCallback: ((uploadBytes: Long, downloadBytes: Long) -> Unit)? = null
        @Volatile var isRunning = false
        @Volatile var lastStatusText: String = ""
    }

    // ──── Tunnel resources ────
    private var vpnInterface: ParcelFileDescriptor? = null
    private var udpSocket: DatagramSocket? = null
    private var tunIn: FileInputStream? = null
    private var tunOut: FileOutputStream? = null

    // ──── Coroutine management ────
    private var serviceJob: Job? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    @Volatile private var manualDisconnect = false

    // ──── Network tracking ────
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var currentNetwork: Network? = null
    @Volatile private var lastNetworkChangeTime = 0L

    // ──── Saved connection params for reconnect ────
    @Volatile private var savedServerAddr: String? = null
    @Volatile private var savedServerKey: String? = null
    @Volatile private var savedPsk: String? = null
    @Volatile private var savedVpnIp: String? = null

    // ──── Traffic counters ────
    @Volatile private var totalUploadBytes: Long = 0
    @Volatile private var totalDownloadBytes: Long = 0

    // ──── Dead connection detection ────
    @Volatile private var lastReceiveTime = 0L

    // ═══════════════════════════════════════════════
    //  Lifecycle
    // ═══════════════════════════════════════════════

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val server = intent.getStringExtra("server") ?: return START_NOT_STICKY
                val serverKey = intent.getStringExtra("server_key") ?: return START_NOT_STICKY
                val pskBase64 = intent.getStringExtra("psk")
                val vpnIp = intent.getStringExtra("vpn_ip")
                startVpn(server, serverKey, pskBase64, vpnIp)
            }
            ACTION_DISCONNECT -> stopVpn()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        manualDisconnect = true
        serviceJob?.cancel()
        serviceJob = null
        closeTunnel()
        unregisterNetworkCallback()
        isRunning = false
        super.onDestroy()
    }

    // ═══════════════════════════════════════════════
    //  Main VPN loop
    // ═══════════════════════════════════════════════

    private fun startVpn(serverAddr: String, serverKeyBase64: String, pskBase64: String? = null, vpnIp: String? = null) {
        Log.d(TAG, "startVpn: server=$serverAddr")

        // Сохраняем параметры для переподключения
        savedServerAddr = serverAddr
        savedServerKey = serverKeyBase64
        savedPsk = pskBase64
        savedVpnIp = vpnIp

        // Отменяем предыдущее подключение и чистим ресурсы
        manualDisconnect = false
        serviceJob?.cancel()
        serviceJob = null
        closeTunnel()
        unregisterNetworkCallback()

        registerNetworkCallback()
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification(getString(R.string.notification_connecting)))

        totalUploadBytes = 0
        totalDownloadBytes = 0

        val job = serviceScope.launch {
            try {
                while (isActive && !manualDisconnect) {
                    try {
                        runTunnel()
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        Log.e(TAG, "Tunnel error: ${e.message}", e)
                        coroutineContext.cancelChildren()
                        closeTunnel()

                        if (manualDisconnect) break

                        // Показываем "переподключается" но НЕ "отключено"
                        statusCallback?.invoke(true, getString(R.string.status_reconnecting))
                        updateNotification(getString(R.string.notification_connecting))
                        Log.d(TAG, "Reconnecting in ${RETRY_DELAY_MS}ms...")
                        delay(RETRY_DELAY_MS)
                    }
                }
            } catch (e: CancellationException) {
                Log.d(TAG, "Service cancelled")
            } finally {
                // Чистим только если мы всё ещё активный job
                // (stopVpn/startVpn могли создать новый job)
                if (serviceJob === coroutineContext[Job]) {
                    isRunning = false
                    closeTunnel()
                    unregisterNetworkCallback()
                    serviceJob = null
                    if (!manualDisconnect) {
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                    }
                }
            }
        }
        serviceJob = job
    }

    /**
     * Одна сессия туннеля:
     *   waitForNetwork → createSocket → handshake → createTUN → forwardPackets
     *
     * Любое исключение = сессия мертва, вызывающий код делает retry.
     */
    private suspend fun runTunnel() {
        // 1. Ждём реальную (не VPN) сеть
        val network = waitForActiveNetwork()
        currentNetwork = network
        Log.d(TAG, "Using network: $network")

        // 2. Парсим адрес сервера
        val serverAddr = savedServerAddr ?: throw Exception("No server address")
        val parts = serverAddr.split(":")
        val host = parts[0]
        val port = parts.getOrElse(1) { "443" }.toInt()

        // 3. Декодируем ключи
        val serverKeyBase64 = savedServerKey ?: throw Exception("No server key")
        val serverKey = android.util.Base64.decode(serverKeyBase64, android.util.Base64.DEFAULT)
        if (serverKey.size != 32) throw Exception("Invalid server key size: ${serverKey.size}")

        val psk: ByteArray? = savedPsk?.let {
            val decoded = android.util.Base64.decode(it, android.util.Base64.DEFAULT)
            if (decoded.size == 32) decoded else null
        }

        // 4. Создаём crypto
        val crypto = AivpnCrypto(serverKey, psk)

        // 5. Создаём UDP сокет и привязываем к сети
        Log.d(TAG, "Creating UDP socket to $host:$port")
        // Явно создаём новый socket с новым портом (не reuse!)
        val socket = DatagramSocket(null)
        socket.reuseAddress = false
        socket.bind(null) // гарантирует случайный свободный порт

        // Проверяем что сеть не устарела между waitForActiveNetwork() и bindSocket()
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNow = cm.activeNetwork
        if (network != activeNow) {
            Log.d(TAG, "Network changed during setup (was $network, now $activeNow) — retrying")
            socket.close()
            throw RuntimeException("Stale network")
        }

        // Проверяем что сеть реально имеет интернет (не captive portal, не переходное состояние)
        val caps = cm.getNetworkCapabilities(network)
        if (caps == null || !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
            Log.d(TAG, "Network has no internet capability — retrying")
            socket.close()
            throw RuntimeException("Network has no internet")
        }

        // protect() ДО bindSocket() — чтобы socket не попал в VPN routing loop
        protect(socket)

        // bindSocket() ОБЯЗАТЕЛЕН — без него socket уйдёт в default network (возможно VPN → loop)
        val bound = try {
            network.bindSocket(socket)
            true
        } catch (e: Exception) {
            Log.w(TAG, "Failed to bind socket to network: ${e.message}")
            false
        }
        if (!bound) {
            socket.close()
            throw RuntimeException("Failed to bind socket to network $network")
        }
        Log.d(TAG, "Socket bound to network $network")
        socket.connect(InetSocketAddress(host, port))
        socket.soTimeout = SOCKET_TIMEOUT_MS.toInt()
        udpSocket = socket

        // 6. Handshake
        Log.d(TAG, "Sending handshake...")
        statusCallback?.invoke(true, getString(R.string.status_connecting))

        val initPacket = crypto.buildInitPacket()
        socket.send(DatagramPacket(initPacket, initPacket.size))

        val recvBuf = ByteArray(2048)
        val response = DatagramPacket(recvBuf, recvBuf.size)
        socket.receive(response)
        Log.d(TAG, "ServerHello received (${response.length} bytes)")

        val serverHelloData = recvBuf.copyOf(response.length)
        if (!crypto.processServerHello(serverHelloData)) {
            throw Exception("Handshake failed (ServerHello validation)")
        }
        Log.d(TAG, "Handshake successful")

        // Инициализируем dead connection detection
        lastReceiveTime = System.currentTimeMillis()

        // 7. Создаём TUN интерфейс
        val tunAddress = savedVpnIp ?: "10.0.0.2"
        Log.d(TAG, "Creating TUN interface: $tunAddress")

        val builder = Builder()
            .setSession("AIVPN")
            .addAddress(tunAddress, 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .addDnsServer("1.1.1.1")
            .setMtu(TUN_MTU)
            .setBlocking(true)

        vpnInterface = builder.establish()
            ?: throw Exception("Failed to establish TUN interface")
        Log.d(TAG, "TUN interface established")

        val localTunIn = FileInputStream(vpnInterface!!.fileDescriptor)
        val localTunOut = FileOutputStream(vpnInterface!!.fileDescriptor)
        tunIn = localTunIn
        tunOut = localTunOut

        isRunning = true
        lastStatusText = getString(R.string.status_connected, host)
        statusCallback?.invoke(true, lastStatusText)
        updateNotification(getString(R.string.notification_connected, host))

        // 8. Форвардим пакеты до первой ошибки
        coroutineScope {
            val tunToUdp = launch { tunToServer(localTunIn, socket, crypto) }
            val udpToTun = launch { serverToTun(socket, localTunOut, crypto) }
            val keepaliveLoop = launch { keepaliveToServer(socket, crypto) }

            // Ждём завершения ЛЮБОЙ корутины (ошибка или отмена)
            select<Unit> {
                tunToUdp.onJoin { }
                udpToTun.onJoin { }
                keepaliveLoop.onJoin { }
            }

            // Одна корутина упала — отменяем остальные
            currentCoroutineContext().cancelChildren()
        }
        throw RuntimeException("Tunnel session ended")
    }

    // ═══════════════════════════════════════════════
    //  Packet forwarding
    // ═══════════════════════════════════════════════

    /**
     * TUN → Server: читаем IP-пакеты из TUN, шифруем, отправляем UDP.
     */
    private suspend fun tunToServer(
        tunIn: FileInputStream,
        socket: DatagramSocket,
        crypto: AivpnCrypto
    ) = withContext(Dispatchers.IO) {
        val buf = ByteArray(TUN_MTU + 100)
        while (isActive) {
            try {
                val n = tunIn.read(buf)
                if (n <= 0) {
                    throw RuntimeException("TUN read returned $n — TUN closed")
                }
                if (n > 0) {
                    val encrypted = crypto.encryptDataPacket(buf.copyOf(n))
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
     * Server → TUN: получаем UDP датаграммы, расшифровываем, пишем в TUN.
     */
    private suspend fun serverToTun(
        socket: DatagramSocket,
        tunOut: FileOutputStream,
        crypto: AivpnCrypto
    ) = withContext(Dispatchers.IO) {
        val buf = ByteArray(TUN_MTU + 200)
        while (isActive) {
            try {
                val pkt = DatagramPacket(buf, buf.size)
                socket.receive(pkt)

                // Любой пакет от сервера = туннель жив
                lastReceiveTime = System.currentTimeMillis()

                val decrypted = crypto.decryptDataPacket(buf.copyOf(pkt.length))
                if (decrypted != null && decrypted.isNotEmpty()) {
                    tunOut.write(decrypted)
                    totalDownloadBytes += decrypted.size
                    trafficCallback?.invoke(totalUploadBytes, totalDownloadBytes)
                }
            } catch (e: SocketTimeoutException) {
                // Таймаут receive — проверяем не мёртв ли туннель
                val silence = System.currentTimeMillis() - lastReceiveTime
                if (silence > DEAD_TUNNEL_TIMEOUT_MS) {
                    Log.w(TAG, "Dead tunnel: no packets from server for ${silence}ms — reconnecting")
                    throw RuntimeException("Dead tunnel (no server packets for ${silence}ms)")
                }
            } catch (e: Exception) {
                if (isActive) throw e
            }
        }
    }

    /**
     * Keepalive: ТОЛЬКО для поддержания NAT-маппинга.
     * НЕ проверяет живость соединения — это делают socket errors.
     */
    private suspend fun keepaliveToServer(
        socket: DatagramSocket,
        crypto: AivpnCrypto
    ) = withContext(Dispatchers.IO) {
        while (isActive) {
            delay(KEEPALIVE_INTERVAL_MS)
            try {
                val keepalive = crypto.buildKeepalivePacket()
                socket.send(DatagramPacket(keepalive, keepalive.size))
            } catch (e: Exception) {
                if (isActive) throw e
            }
        }
    }

    // ═══════════════════════════════════════════════
    //  Network
    // ═══════════════════════════════════════════════

    /**
     * Ждём появления реальной (не VPN) сети.
     * Поллинг раз в секунду — просто и надёжно.
     */
    private suspend fun waitForActiveNetwork(): Network {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        while (currentCoroutineContext().isActive) {
            val network = cm.activeNetwork
            if (network != null && !isVpnNetwork(network)) {
                return network
            }
            Log.d(TAG, "No active network, waiting...")
            delay(300L)
        }
        throw CancellationException("Cancelled while waiting for network")
    }

    /**
     * Проверяем, является ли сеть VPN-сетью.
     * Используется для фильтрации событий от VPN-интерфейса.
     */
    private fun isVpnNetwork(network: Network): Boolean {
        return (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
            .getNetworkCapabilities(network)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }

    /**
     * Регистрируем callback для отслеживания изменений дефолтной сети.
     *
     * При изменении сети — просто закрываем туннель (сокет + TUN).
     * Нормальный путь обработки ошибок в [runTunnel] сделает всё остальное:
     * корутины упадут → select вернётся → cleanup → retry с новой сетью.
     */
    private fun registerNetworkCallback() {
        try {
            unregisterNetworkCallback()
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

            networkCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    // Фильтруем VPN-события — нас интересуют только реальные сети
                    if (isVpnNetwork(network)) return
                    Log.d(TAG, "onAvailable: $network (current=$currentNetwork)")

                    if (!isRunning) {
                        // Ещё не подключены — просто запоминаем сеть
                        currentNetwork = network
                        return
                    }

                    // Сеть действительно изменилась — закрываем туннель (с debounce)
                    if (network != currentNetwork) {
                        val now = System.currentTimeMillis()
                        if (now - lastNetworkChangeTime < NETWORK_DEBOUNCE_MS) {
                            Log.d(TAG, "Network change debounced (${now - lastNetworkChangeTime}ms)")
                            currentNetwork = network
                            return
                        }
                        lastNetworkChangeTime = now
                        Log.d(TAG, "Network changed: $currentNetwork -> $network — closing tunnel")
                        currentNetwork = network
                        closeTunnel()
                    }
                }

                override fun onLost(network: Network) {
                    if (isVpnNetwork(network)) return
                    Log.d(TAG, "onLost: $network (current=$currentNetwork)")

                    // Текущая сеть потеряна — закрываем туннель
                    if (network == currentNetwork && isRunning) {
                        Log.d(TAG, "Current network lost — closing tunnel")
                        currentNetwork = null
                        closeTunnel()
                    }
                }
            }

            cm.registerDefaultNetworkCallback(networkCallback!!)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to register network callback", e)
        }
    }

    private fun unregisterNetworkCallback() {
        try {
            networkCallback?.let { cb ->
                (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
                    .unregisterNetworkCallback(cb)
                networkCallback = null
            }
        } catch (_: Exception) {}
    }

    // ═══════════════════════════════════════════════
    //  Cleanup
    // ═══════════════════════════════════════════════

    /**
     * Закрываем все ресурсы туннеля. Thread-safe:
     * каждый close() синхронизирован на объекте, null-присвоения атомарны.
     *
     * Вызывается из:
     * - корутины (IO thread) при ошибке
     * - network callback (main thread) при смене сети
     * - stopVpn() / onDestroy() (main thread)
     */
    private fun closeTunnel() {
        // 1. Сначала закрываем VPN интерфейс (ParcelFileDescriptor) — это закрывает fd,
        //    что ГАРАНТИРОВАННО разблокирует tunIn.read() в корутине tunToServer.
        //    Без этого tunToServer может зависнуть навсегда даже если сокет уже мёртв.
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null

        // 2. Закрываем TUN потоки (fd уже закрыт, но streams тоже нужно закрыть)
        try { tunIn?.close() } catch (_: Exception) {}
        try { tunOut?.close() } catch (_: Exception) {}
        tunIn = null
        tunOut = null

        // 3. Закрываем UDP сокет — разблокирует serverToTun (receive) и keepalive (send)
        try { udpSocket?.close() } catch (_: Exception) {}
        udpSocket = null
    }

    private fun stopVpn() {
        manualDisconnect = true
        serviceJob?.cancel()
        serviceJob = null
        closeTunnel()
        unregisterNetworkCallback()
        isRunning = false
        lastStatusText = getString(R.string.status_disconnected)
        statusCallback?.invoke(false, lastStatusText)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    // ═══════════════════════════════════════════════
    //  Notifications
    // ═══════════════════════════════════════════════

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID, getString(R.string.notification_channel),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.notification_channel_desc)
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
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
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification(text))
    }
}
