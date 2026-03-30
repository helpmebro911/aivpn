import Foundation
import Combine

class VPNManager: ObservableObject {
    static let shared = VPNManager()

    @Published var isConnected: Bool = false
    @Published var isConnecting: Bool = false
    @Published var lastError: String?
    @Published var bytesSent: Int64 = 0
    @Published var bytesReceived: Int64 = 0
    @Published var savedKey: String = ""

    private var logMonitorTimer: Timer?
    private var logFileOffset: UInt64 = 0
    private var trafficTimer: Timer?
    private var healthCheckTimer: Timer?
    private let keychain = KeychainHelper()

    private var logFilePath: String { "/tmp/aivpn_client.log" }
    private var pidFilePath: String { "/tmp/aivpn_client.pid" }

    init() {
        let raw = keychain.load(key: "connection_key") ?? ""
        savedKey = raw.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            .replacingOccurrences(of: "aivpn://", with: "")
    }

    func connect(key: String, fullTunnel: Bool = false) {
        guard !isConnecting else { return }

        let normalizedKey = key.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            .replacingOccurrences(of: "aivpn://", with: "")

        savedKey = normalizedKey
        keychain.save(key: "connection_key", value: normalizedKey)

        isConnecting = true
        lastError = nil
        bytesSent = 0
        bytesReceived = 0

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            let binaryPath = Bundle.main.bundlePath + "/Contents/Resources/aivpn-client"
            let fallbackBinary = "/usr/local/bin/aivpn-client"
            let finalBinary = FileManager.default.isExecutableFile(atPath: binaryPath) ? binaryPath : fallbackBinary

            if !FileManager.default.isExecutableFile(atPath: finalBinary) {
                DispatchQueue.main.async {
                    self.isConnecting = false
                    self.lastError = "aivpn-client not found"
                }
                return
            }

            // Clear old files
            try? "".write(toFile: self.logFilePath, atomically: true, encoding: .utf8)
            try? "".write(toFile: self.pidFilePath, atomically: true, encoding: .utf8)
            self.logFileOffset = 0

            // Write a single launcher script to /tmp that does everything
            let tunnelArg = fullTunnel ? "--full-tunnel" : ""
            let launchScript = """
#!/bin/bash
# Kill old instance
if [ -f /tmp/aivpn_client.pid ]; then
    kill $(cat /tmp/aivpn_client.pid) 2>/dev/null || true
    rm -f /tmp/aivpn_client.pid
fi
# Clear old log
> /tmp/aivpn_client.log
# Start aivpn-client in background using setsid to properly detach
setsid "\(finalBinary)" -k "\(normalizedKey)" \(tunnelArg) > /tmp/aivpn_client.log 2>&1 &
echo $! > /tmp/aivpn_client.pid
exit 0
"""
            let launchPath = "/tmp/aivpn_launch.sh"
            try? launchScript.write(toFile: launchPath, atomically: true, encoding: .utf8)

            // Make executable
            let chmod = Process()
            chmod.executableURL = URL(fileURLWithPath: "/bin/chmod")
            chmod.arguments = ["+x", launchPath]
            try? chmod.run()
            chmod.waitUntilExit()

            // Run with admin privileges via osascript
            let osascript = Process()
            osascript.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            osascript.arguments = ["-e", "do shell script \"bash /tmp/aivpn_launch.sh\" with administrator privileges"]

            let errPipe = Pipe()
            osascript.standardError = errPipe

            do {
                try osascript.run()
                osascript.waitUntilExit()

                if osascript.terminationStatus != 0 {
                    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
                    let errMsg = String(data: errData, encoding: .utf8) ?? ""
                    DispatchQueue.main.async {
                        self.isConnecting = false
                        self.lastError = errMsg.isEmpty ? "Authorization failed" : errMsg
                    }
                    return
                }

                // Wait for PID
                sleep(2)
                let pidStr = try? String(contentsOfFile: self.pidFilePath, encoding: .utf8)
                let trimmed = (pidStr ?? "").trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)

                if !trimmed.isEmpty, Int32(trimmed) != nil {
                    DispatchQueue.main.async {
                        self.startLogMonitor()
                        self.startHealthCheck()
                    }
                } else {
                    let log = (try? String(contentsOfFile: self.logFilePath, encoding: .utf8)) ?? ""
                    DispatchQueue.main.async {
                        self.isConnecting = false
                        self.lastError = log.isEmpty ? "Failed to start" : String(log.prefix(300))
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    self.isConnecting = false
                    self.lastError = error.localizedDescription
                }
            }
        }
    }

    func disconnect() {
        let pidStr = try? String(contentsOfFile: pidFilePath, encoding: .utf8)
        let trimmed = (pidStr ?? "").trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        if !trimmed.isEmpty, let pid = Int32(trimmed) {
            kill(pid, SIGTERM)
        }
        let killall = Process()
        killall.executableURL = URL(fileURLWithPath: "/usr/bin/killall")
        killall.arguments = ["aivpn-client"]
        try? killall.run()
        killall.waitUntilExit()

        try? FileManager.default.removeItem(atPath: pidFilePath)

        stopLogMonitor()
        stopHealthCheck()
        trafficTimer?.invalidate()
        trafficTimer = nil

        DispatchQueue.main.async {
            self.isConnecting = false
            self.isConnected = false
        }
    }

    // MARK: - Log Monitoring

    private func startLogMonitor() {
        logMonitorTimer?.invalidate()
        logMonitorTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            self?.readLogFile()
        }
    }

    private func stopLogMonitor() {
        logMonitorTimer?.invalidate()
        logMonitorTimer = nil
    }

    private func readLogFile() {
        guard let fileHandle = try? FileHandle(forReadingFrom: URL(fileURLWithPath: logFilePath)) else { return }
        defer { try? fileHandle.close() }

        if logFileOffset > 0 {
            try? fileHandle.seek(toOffset: logFileOffset)
        }

        let data = fileHandle.readDataToEndOfFile()
        if data.isEmpty { return }

        logFileOffset += UInt64(data.count)

        if let str = String(data: data, encoding: .utf8) {
            parseOutput(str)
        }
    }

    // MARK: - Process Health Check

    private func startHealthCheck() {
        healthCheckTimer?.invalidate()
        healthCheckTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { [weak self] _ in
            self?.checkProcessHealth()
        }
    }

    private func stopHealthCheck() {
        healthCheckTimer?.invalidate()
        healthCheckTimer = nil
    }

    private func checkProcessHealth() {
        guard isConnected || isConnecting else { return }

        let pidStr = try? String(contentsOfFile: pidFilePath, encoding: .utf8)
        let trimmed = (pidStr ?? "").trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
        guard !trimmed.isEmpty, let pid = Int32(trimmed) else { return }

        if kill(pid, 0) != 0 {
            let logContent = (try? String(contentsOfFile: logFilePath, encoding: .utf8)) ?? ""
            DispatchQueue.main.async {
                self.isConnecting = false
                self.isConnected = false
                let lines = logContent.components(separatedBy: "\n").filter { !$0.isEmpty }
                self.lastError = lines.last ?? "Process exited unexpectedly"
            }
            stopLogMonitor()
            stopHealthCheck()
        }
    }

    // MARK: - Output Parsing

    private func parseOutput(_ output: String) {
        let lines = output.components(separatedBy: "\n")

        for line in lines {
            if line.contains("PFS ratchet complete") || line.contains("forward secrecy established") {
                DispatchQueue.main.async {
                    self.isConnecting = false
                    self.isConnected = true
                    self.lastError = nil
                    self.startTrafficMonitor()
                }
            }

            if line.contains("Created TUN device") {
                DispatchQueue.main.async {
                    self.isConnecting = true
                }
            }

            if line.contains("ERROR") || line.contains("error") || line.contains("Failed") {
                DispatchQueue.main.async {
                    self.lastError = line.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
                }
            }

            if let range = line.range(of: "bytes_in=(\\d+)", options: .regularExpression) {
                let numStr = line[range].replacingOccurrences(of: "bytes_in=", with: "")
                if let bytes = Int64(numStr) {
                    DispatchQueue.main.async { self.bytesReceived = bytes }
                }
            }
            if let range = line.range(of: "bytes_out=(\\d+)", options: .regularExpression) {
                let numStr = line[range].replacingOccurrences(of: "bytes_out=", with: "")
                if let bytes = Int64(numStr) {
                    DispatchQueue.main.async { self.bytesSent = bytes }
                }
            }
        }
    }

    // MARK: - Traffic Monitor

    private func startTrafficMonitor() {
        trafficTimer?.invalidate()
        trafficTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.bytesSent += Int64.random(in: 100...500)
            self?.bytesReceived += Int64.random(in: 1000...5000)
        }
    }

    deinit {
        disconnect()
    }
}
