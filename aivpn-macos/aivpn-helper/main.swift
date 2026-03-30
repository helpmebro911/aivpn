#!/usr/bin/env swift
// ═══════════════════════════════════════════════════════════════
// AIVPN Privileged Helper Daemon v1.1.0
//
// Manages aivpn-client process on behalf of the AIVPN GUI app.
// Communicates via JSON over Unix domain socket.
// Installed as LaunchDaemon — runs as root, no password prompts.
// ═══════════════════════════════════════════════════════════════

import Foundation
import Darwin

// MARK: - Constants

let SOCKET_PATH = "/var/run/aivpn/helper.sock"
let DEFAULT_CLIENT_PATH = "/Library/Application Support/AIVPN/aivpn-client"
let LOG_PATH = "/var/run/aivpn/client.log"
let PID_PATH = "/var/run/aivpn/client.pid"
let HELPER_VERSION = "1.1.0"

// MARK: - Protocol Types

struct HelperRequest: Codable {
    let action: String       // connect, disconnect, status, ping, log
    let key: String?         // connection key (for connect)
    let fullTunnel: Bool?    // full tunnel mode (for connect)
    let binaryPath: String?  // custom binary path (for connect/dev)
}

struct HelperResponse: Codable {
    let status: String       // ok, error
    let message: String
    let connected: Bool?
    let pid: Int?
    let version: String?
    let log: String?

    init(status: String, message: String,
         connected: Bool? = nil, pid: Int? = nil,
         version: String? = nil, log: String? = nil) {
        self.status = status
        self.message = message
        self.connected = connected
        self.pid = pid
        self.version = version
        self.log = log
    }
}

// MARK: - Global State

var managedPID: pid_t = 0
var isConnected = false

// MARK: - Logging

func log(_ message: String) {
    let ts = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
    fputs("[\(ts)] \(message)\n", stderr)
}

// MARK: - Shell Escaping

func shellEscape(_ str: String) -> String {
    return "'" + str.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
}

// MARK: - Process Management

/// Kill any existing aivpn-client process
func killExistingClient() {
    if managedPID > 0 {
        if kill(managedPID, 0) == 0 {
            log("Stopping aivpn-client (PID: \(managedPID))")
            kill(managedPID, SIGTERM)
            for _ in 0..<10 {
                usleep(100_000)
                if kill(managedPID, 0) != 0 { break }
            }
            if kill(managedPID, 0) == 0 {
                kill(managedPID, SIGKILL)
            }
        }
        managedPID = 0
        isConnected = false
    }

    // Check PID file for orphaned processes
    if let pidStr = try? String(contentsOfFile: PID_PATH, encoding: .utf8) {
        let trimmed = pidStr.trimmingCharacters(in: .whitespacesAndNewlines)
        if let pid = Int32(trimmed), pid > 0 {
            if kill(pid, 0) == 0 {
                log("Stopping orphaned aivpn-client (PID: \(pid))")
                kill(pid, SIGTERM)
                usleep(500_000)
                if kill(pid, 0) == 0 {
                    kill(pid, SIGKILL)
                }
            }
        }
    }

    try? FileManager.default.removeItem(atPath: PID_PATH)
    
    // Restore IPv6 after stopping client
    restoreIPv6()
}

/// Restore IPv6 routing after VPN disconnect
func restoreIPv6() {
    log("Restoring IPv6 routing...")
    
    // Remove blackhole route if it exists
    let _ = runCommand("/sbin/route", args: ["-n", "delete", "-inet6", "-net", "::/0", "-blackhole"])
    
    // Restore default IPv6 route via en0
    let _ = runCommand("/sbin/route", args: ["-n", "add", "-inet6", "default", "-interface", "en0"])
    
    log("IPv6 routing restored")
}

/// Run a command and return success
func runCommand(_ path: String, args: [String]) -> Bool {
    let task = Process()
    task.launchPath = path
    task.arguments = args
    do {
        try task.run()
        task.waitUntilExit()
        return task.terminationStatus == 0
    } catch {
        log("Command failed: \(path) \(args.joined(separator: " ")) - \(error)")
        return false
    }
}

/// Start aivpn-client with the given configuration using posix_spawn
func startClient(key: String, fullTunnel: Bool, binaryPath: String?) -> HelperResponse {
    killExistingClient()

    let clientPath = binaryPath ?? DEFAULT_CLIENT_PATH

    guard FileManager.default.isExecutableFile(atPath: clientPath) else {
        log("ERROR: aivpn-client not found at \(clientPath)")
        return HelperResponse(status: "error",
                              message: "aivpn-client binary not found at \(clientPath)")
    }

    // Ensure directories exist
    try? FileManager.default.createDirectory(
        atPath: (LOG_PATH as NSString).deletingLastPathComponent,
        withIntermediateDirectories: true
    )

    // Clear log
    try? Data().write(to: URL(fileURLWithPath: LOG_PATH))

    // Build arguments
    var args: [String] = [clientPath, "-k", key]
    if fullTunnel {
        args.append("--full-tunnel")
    }

    // Use posix_spawn for reliable process management
    var fileActions: posix_spawn_file_actions_t?
    posix_spawn_file_actions_init(&fileActions)

    // Redirect stdout/stderr to log file (world-readable for debugging)
    let logFd = open(LOG_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
    if logFd >= 0 {
        posix_spawn_file_actions_adddup2(&fileActions, logFd, STDOUT_FILENO)
        posix_spawn_file_actions_adddup2(&fileActions, logFd, STDERR_FILENO)
        posix_spawn_file_actions_addclose(&fileActions, logFd)
        // Ensure log is readable
        chmod(LOG_PATH, 0o644)
    }

    // Set RUST_LOG=info so tracing outputs info-level logs (default is ERROR only)
    // Preserve the existing PATH so we can find system binaries like ifconfig/route
    var envp: [UnsafeMutablePointer<CChar>?] = []
    
    // Copy current environment first
    var currentEnv = ProcessInfo.processInfo.environment
    for (key, value) in currentEnv {
        envp.append(strdup("\(key)=\(value)"))
    }
    
    // Add/override RUST_LOG=info
    envp.append(strdup("RUST_LOG=info"))
    envp.append(nil)

    var pid: pid_t = 0
    let argv = args.map { strdup($0) } + [nil]

    let spawnResult = argv.withUnsafeBufferPointer { ptr in
        envp.withUnsafeMutableBufferPointer { envPtr in
            posix_spawn(&pid, clientPath, &fileActions, nil,
                        UnsafeMutablePointer(mutating: ptr.baseAddress),
                        UnsafeMutablePointer(mutating: envPtr.baseAddress))
        }
    }

    // Free strdup'd strings
    for arg in argv { free(arg) }
    for envVar in envp {
        if let ptr = envVar {
            free(ptr)
        }
    }
    posix_spawn_file_actions_destroy(&fileActions)
    if logFd >= 0 { close(logFd) }

    if spawnResult != 0 {
        log("ERROR: posix_spawn failed: \(String(cString: strerror(spawnResult)))")
        return HelperResponse(status: "error",
                              message: "Failed to start client: \(String(cString: strerror(spawnResult)))")
    }

    managedPID = pid
    isConnected = false
    try? "\(pid)".write(toFile: PID_PATH, atomically: true, encoding: .utf8)
    log("Started aivpn-client (PID: \(pid))")
    return HelperResponse(status: "ok", message: "Client started", pid: Int(pid))
}

/// Stop the managed aivpn-client process
func stopClient() -> HelperResponse {
    let wasConnected = isConnected
    killExistingClient()
    log("Client stopped")
    return HelperResponse(status: "ok",
                          message: wasConnected ? "Disconnected" : "No active connection")
}

/// Get current connection status
func getStatus() -> HelperResponse {
    if managedPID > 0 && kill(managedPID, 0) == 0 {
        if isConnected {
            return HelperResponse(status: "ok", message: "Connected",
                                  connected: true, pid: Int(managedPID),
                                  version: HELPER_VERSION)
        }
        // Check log for connection status
        if let logContent = try? String(contentsOfFile: LOG_PATH, encoding: .utf8) {
            if logContent.contains("Connected to server") ||
               logContent.contains("PFS ratchet complete") ||
               logContent.contains("forward secrecy established") {
                isConnected = true
                return HelperResponse(status: "ok", message: "Connected",
                                      connected: true, pid: Int(managedPID),
                                      version: HELPER_VERSION)
            }
            if logContent.contains("Created TUN device") {
                return HelperResponse(status: "ok", message: "Establishing tunnel...",
                                      connected: false, pid: Int(managedPID),
                                      version: HELPER_VERSION)
            }

            // Check for repeated errors — if last non-empty line is an error, report it
            let lines = logContent.components(separatedBy: "\n").filter { !$0.isEmpty }
            if let lastLine = lines.last {
                // Strip ANSI escape codes (actual \x1b byte, not literal text)
                let cleanLine = lastLine.replacingOccurrences(
                    of: "\u{001b}\\[[0-9;]*m", with: "", options: .regularExpression
                )
                if cleanLine.contains("ERROR") || cleanLine.contains("Failed") {
                    // Extract just the error message
                    let errorMsg: String
                    if let range = cleanLine.range(of: "ERROR") {
                        errorMsg = String(cleanLine[range.lowerBound...]).trimmingCharacters(
                            in: .whitespacesAndNewlines
                        )
                    } else {
                        errorMsg = cleanLine.trimmingCharacters(in: .whitespacesAndNewlines)
                    }
                    return HelperResponse(status: "ok", message: errorMsg,
                                          connected: false, pid: Int(managedPID),
                                          version: HELPER_VERSION)
                }
            }
        }
        return HelperResponse(status: "ok", message: "Connecting...",
                              connected: false, pid: Int(managedPID),
                              version: HELPER_VERSION)
    }

    // Process not running
    if managedPID > 0 {
        managedPID = 0
        isConnected = false
        try? FileManager.default.removeItem(atPath: PID_PATH)

        var errorMsg = "Process exited"
        if let logContent = try? String(contentsOfFile: LOG_PATH, encoding: .utf8) {
            let lines = logContent.components(separatedBy: "\n").filter { !$0.isEmpty }
            if let last = lines.last,
               last.contains("ERROR") || last.contains("error") || last.contains("Failed") {
                errorMsg = String(last.prefix(200))
            }
        }
        return HelperResponse(status: "ok", message: errorMsg,
                              connected: false, version: HELPER_VERSION)
    }

    return HelperResponse(status: "ok", message: "Idle",
                          connected: false, version: HELPER_VERSION)
}

/// Get recent log entries
func getLog() -> HelperResponse {
    guard let logContent = try? String(contentsOfFile: LOG_PATH, encoding: .utf8) else {
        return HelperResponse(status: "ok", message: "No log",
                              connected: isConnected,
                              pid: managedPID > 0 ? Int(managedPID) : nil, log: "")
    }
    let lines = logContent.components(separatedBy: "\n")
    let recent = lines.suffix(50).joined(separator: "\n")
    return HelperResponse(status: "ok", message: "Log retrieved",
                          connected: isConnected,
                          pid: managedPID > 0 ? Int(managedPID) : nil,
                          log: recent)
}

/// Get traffic statistics
func getTrafficStats() -> HelperResponse {
    // Try to read stats file first
    let statsPath = "/var/run/aivpn/traffic.stats"
    if let statsContent = try? String(contentsOfFile: statsPath, encoding: .utf8) {
        // Format: "sent:X,received:Y"
        let trimmed = statsContent.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.contains("sent:") && trimmed.contains("received:") {
            return HelperResponse(status: "ok", message: trimmed)
        }
    }
    
    // Fallback: parse last 100 lines of log
    guard let logContent = try? String(contentsOfFile: LOG_PATH, encoding: .utf8) else {
        return HelperResponse(status: "ok", message: "sent:0,received:0")
    }
    
    let lines = logContent.components(separatedBy: "\n")
    let recentLines = lines.suffix(100)
    
    var totalSent: Int64 = 0
    var totalReceived: Int64 = 0
    
    for line in recentLines {
        if line.contains("Sent") {
            let parts = line.components(separatedBy: " ")
            for (i, part) in parts.enumerated() {
                if part == "Sent" && i + 1 < parts.count {
                    if let bytes = Int64(parts[i + 1]) {
                        totalSent += bytes
                    }
                }
            }
        }
        if line.contains("received") || line.contains("Read") {
            let parts = line.components(separatedBy: " ")
            for (i, part) in parts.enumerated() {
                if (part == "received" || part == "Read") && i + 1 < parts.count {
                    if let bytes = Int64(parts[i + 1]) {
                        totalReceived += bytes
                    }
                }
            }
        }
    }
    
    // Trim log file if too large
    if lines.count > 500 {
        let trimmed = lines.suffix(500).joined(separator: "\n")
        try? trimmed.write(toFile: LOG_PATH, atomically: true, encoding: .utf8)
    }
    
    return HelperResponse(status: "ok", message: "sent:\(totalSent),received:\(totalReceived)")
}

// MARK: - Socket Helpers

/// Build a raw sockaddr_un buffer for the given path
func makeSockAddr(_ path: String) -> [Int8] {
    var buf = [Int8](repeating: 0, count: 106)
    buf[0] = 0              // sun_len (0 = let kernel compute)
    buf[1] = Int8(AF_UNIX)  // sun_family
    let pathBytes = Array(path.utf8)
    for (i, byte) in pathBytes.enumerated() where i + 2 < buf.count {
        buf[i + 2] = Int8(bitPattern: byte)
    }
    return buf
}

// MARK: - Socket Server

/// Create and bind the Unix domain socket
func createSocket() -> Int32 {
    let socketDir = (SOCKET_PATH as NSString).deletingLastPathComponent
    do {
        try FileManager.default.createDirectory(atPath: socketDir,
                                                withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o755],
                                              ofItemAtPath: socketDir)
    } catch {
        log("WARNING: Could not create socket dir: \(error)")
    }

    // Remove stale socket
    try? FileManager.default.removeItem(atPath: SOCKET_PATH)

    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else {
        log("ERROR: socket() failed: \(String(cString: strerror(errno)))")
        return -1
    }

    let addrBuf = makeSockAddr(SOCKET_PATH)
    let bindResult = addrBuf.withUnsafeBufferPointer { ptr in
        bind(fd, UnsafeRawPointer(ptr.baseAddress!).assumingMemoryBound(to: sockaddr.self),
             socklen_t(addrBuf.count))
    }
    guard bindResult == 0 else {
        log("ERROR: bind() failed: \(String(cString: strerror(errno)))")
        close(fd)
        return -1
    }

    guard listen(fd, 5) == 0 else {
        log("ERROR: listen() failed: \(String(cString: strerror(errno)))")
        close(fd)
        return -1
    }

    // Make socket accessible to all users
    try? FileManager.default.setAttributes([.posixPermissions: 0o666],
                                          ofItemAtPath: SOCKET_PATH)

    return fd
}

/// Handle a single client connection
func handleConnection(_ clientFD: Int32) {
    // 5-second read timeout
    var timeout = timeval(tv_sec: 5, tv_usec: 0)
    setsockopt(clientFD, SOL_SOCKET, SO_RCVTIMEO,
               &timeout, socklen_t(MemoryLayout<timeval>.size))

    var buffer = [UInt8](repeating: 0, count: 8192)
    let bytesRead = read(clientFD, &buffer, buffer.count)
    guard bytesRead > 0 else { return }

    let data = Data(bytes: buffer, count: bytesRead)
    guard let requestStr = String(data: data, encoding: .utf8) else {
        sendResponse(clientFD, HelperResponse(status: "error", message: "Invalid encoding"))
        return
    }

    guard let requestData = requestStr.data(using: .utf8),
          let request = try? JSONDecoder().decode(HelperRequest.self, from: requestData) else {
        sendResponse(clientFD, HelperResponse(status: "error", message: "Invalid JSON"))
        return
    }

    log("Action: \(request.action)")

    let response: HelperResponse
    switch request.action {
    case "connect":
        guard let key = request.key, !key.isEmpty else {
            response = HelperResponse(status: "error", message: "Missing connection key")
            break
        }
        response = startClient(key: key,
                               fullTunnel: request.fullTunnel ?? false,
                               binaryPath: request.binaryPath)

    case "disconnect":
        response = stopClient()

    case "status":
        response = getStatus()

    case "ping":
        response = HelperResponse(status: "ok", message: "pong", version: HELPER_VERSION)

    case "log":
        response = getLog()

    case "traffic":
        response = getTrafficStats()

    default:
        response = HelperResponse(status: "error",
                                  message: "Unknown action: \(request.action)")
    }

    sendResponse(clientFD, response)
}

/// Send a JSON response to the client
func sendResponse(_ clientFD: Int32, _ response: HelperResponse) {
    guard let responseData = try? JSONEncoder().encode(response),
          let responseStr = String(data: responseData, encoding: .utf8) else { return }

    _ = responseStr.withCString { ptr in
        write(clientFD, ptr, Int(strlen(ptr)))
    }
}

// MARK: - Signal Handling

func signalHandler(_ sig: Int32) {
    log("Signal \(sig), shutting down...")
    killExistingClient()
    try? FileManager.default.removeItem(atPath: SOCKET_PATH)
    exit(0)
}

func setupSignals() {
    signal(SIGTERM, signalHandler)
    signal(SIGINT, signalHandler)
    signal(SIGHUP, SIG_IGN)
}

// MARK: - Recovery

/// Recover existing aivpn-client from a previous helper instance
func recoverExistingClient() {
    guard let pidStr = try? String(contentsOfFile: PID_PATH, encoding: .utf8) else { return }
    let trimmed = pidStr.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let pid = Int32(trimmed), pid > 0 else { return }

    if kill(pid, 0) == 0 {
        managedPID = pid
        log("Recovered aivpn-client (PID: \(pid))")
        if let logContent = try? String(contentsOfFile: LOG_PATH, encoding: .utf8) {
            if logContent.contains("PFS ratchet complete") ||
               logContent.contains("forward secrecy established") {
                isConnected = true
            }
        }
    } else {
        try? FileManager.default.removeItem(atPath: PID_PATH)
    }
}

// MARK: - Main

func main() {
    setupSignals()
    recoverExistingClient()

    let sockFD = createSocket()
    guard sockFD >= 0 else {
        log("FATAL: Could not create helper socket")
        exit(1)
    }
    defer {
        close(sockFD)
        try? FileManager.default.removeItem(atPath: SOCKET_PATH)
    }

    log("AIVPN Helper v\(HELPER_VERSION) started (socket: \(SOCKET_PATH))")

    // Main accept loop — runs forever (LaunchDaemon manages lifecycle)
    while true {
        var clientBuf = [Int8](repeating: 0, count: 106)
        var clientLen = socklen_t(106)
        let clientFD = clientBuf.withUnsafeMutableBufferPointer { ptr in
            accept(sockFD,
                   UnsafeMutableRawPointer(ptr.baseAddress!).assumingMemoryBound(to: sockaddr.self),
                   &clientLen)
        }

        guard clientFD >= 0 else {
            if errno == EINTR { continue }
            break
        }

        handleConnection(clientFD)
        close(clientFD)
    }

    log("AIVPN Helper exiting")
}

main()
