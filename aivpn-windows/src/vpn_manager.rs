//! VPN Manager — subprocess control for aivpn-client.exe
//!
//! Launches the Rust client binary in the background (no console window),
//! monitors its process state, reads traffic stats and recording status from file.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}

pub struct TrafficStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

// ── Recording ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum RecordingState {
    Idle,
    Starting(String),
    Recording(String),
    Stopping(String),
    Analyzing(String),
    Success(String, Option<String>),   // service, mask_id
    Failed(String, String),            // service, reason
}

#[derive(Debug, Clone)]
pub struct RecordingResult {
    pub succeeded: bool,
    pub details: String,
}

pub struct VpnManager {
    state: ConnectionState,
    child: Option<Child>,
    stats: TrafficStats,
    last_poll: Option<Instant>,
    client_binary: PathBuf,
    // Recording
    pub recording_state: RecordingState,
    pub can_record_masks: bool,
    pub recording_capability_known: bool,
    pub last_recording_result: Option<RecordingResult>,
    minimum_recording_ts: u64,
    last_recording_poll: Option<Instant>,
}

impl VpnManager {
    pub fn new() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            child: None,
            stats: TrafficStats {
                bytes_sent: 0,
                bytes_received: 0,
            },
            last_poll: None,
            client_binary: Self::find_client_binary(),
            recording_state: RecordingState::Idle,
            can_record_masks: false,
            recording_capability_known: false,
            last_recording_result: None,
            minimum_recording_ts: 0,
            last_recording_poll: None,
        }
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn stats(&self) -> &TrafficStats {
        &self.stats
    }

    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    pub fn is_busy(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::Connecting | ConnectionState::Disconnecting
        )
    }

    /// Connect using a connection key
    pub fn connect(&mut self, connection_key: &str, full_tunnel: bool) -> Result<(), String> {
        if self.child.is_some() {
            return Err("Already running".to_string());
        }

        if !self.client_binary.exists() {
            return Err(format!(
                "Client binary not found: {}",
                self.client_binary.display()
            ));
        }

        self.state = ConnectionState::Connecting;
        // Reset recording on new connection
        self.recording_state = RecordingState::Idle;
        self.can_record_masks = false;
        self.recording_capability_known = false;
        self.last_recording_result = None;
        self.minimum_recording_ts = current_timestamp_ms();

        let mut cmd = Command::new(&self.client_binary);
        cmd.arg("--connection-key").arg(connection_key);

        if full_tunnel {
            cmd.arg("--full-tunnel");
        }

        // Hide console window on Windows
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        match cmd.spawn() {
            Ok(child) => {
                self.child = Some(child);
                self.state = ConnectionState::Connected;
                self.stats.bytes_sent = 0;
                self.stats.bytes_received = 0;
                // Request initial recording status
                self.request_recording_status_refresh();
                Ok(())
            }
            Err(e) => {
                self.state = ConnectionState::Disconnected;
                Err(format!("Failed to start client: {}", e))
            }
        }
    }

    /// Disconnect — kill the client process
    pub fn disconnect(&mut self) {
        self.state = ConnectionState::Disconnecting;

        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
        self.state = ConnectionState::Disconnected;
        self.stats.bytes_sent = 0;
        self.stats.bytes_received = 0;
        // Reset recording
        self.recording_state = RecordingState::Idle;
        self.can_record_masks = false;
        self.recording_capability_known = false;
        self.last_recording_result = None;
        self.minimum_recording_ts = 0;
    }

    /// Poll process status and read traffic stats
    pub fn poll_status(&mut self) {
        // Only poll every 500ms
        if let Some(last) = self.last_poll {
            if last.elapsed() < std::time::Duration::from_millis(500) {
                return;
            }
        }
        self.last_poll = Some(Instant::now());

        // Check if process is still alive
        if let Some(ref mut child) = self.child {
            match child.try_wait() {
                Ok(Some(_status)) => {
                    // Process exited
                    self.child = None;
                    self.state = ConnectionState::Disconnected;
                    return;
                }
                Ok(None) => {
                    // Still running
                    if self.state == ConnectionState::Connecting {
                        self.state = ConnectionState::Connected;
                    }
                }
                Err(_) => {
                    self.child = None;
                    self.state = ConnectionState::Disconnected;
                    return;
                }
            }
        }

        // Read traffic stats from file
        if self.state == ConnectionState::Connected {
            self.read_traffic_stats();
            self.poll_recording_status();
        }
    }

    // ── Recording ───────────────────────────────────────────────────────

    /// Start mask recording for a given service name
    pub fn start_recording(&mut self, service_name: &str) {
        let service = service_name.trim().to_string();
        if service.is_empty() {
            return;
        }
        self.minimum_recording_ts = current_timestamp_ms();
        self.last_recording_result = None;
        self.recording_state = RecordingState::Starting(service.clone());

        // Run: aivpn-client record start --service <name>
        self.run_client_subcommand(&["record", "start", "--service", &service]);
    }

    /// Stop current mask recording
    pub fn stop_recording(&mut self) {
        let current_service = match &self.recording_state {
            RecordingState::Recording(s) | RecordingState::Starting(s) => s.clone(),
            _ => return,
        };
        self.minimum_recording_ts = current_timestamp_ms();
        self.recording_state = RecordingState::Stopping(current_service);

        // Run: aivpn-client record stop
        self.run_client_subcommand(&["record", "stop"]);
    }

    /// Clear the result banner
    pub fn clear_recording_result(&mut self) {
        self.last_recording_result = None;
    }

    /// Whether the record button should be disabled
    pub fn recording_button_disabled(&self) -> bool {
        matches!(
            self.recording_state,
            RecordingState::Stopping(_) | RecordingState::Analyzing(_)
        )
    }

    /// Whether we're actively recording or starting
    pub fn is_recording(&self) -> bool {
        matches!(
            self.recording_state,
            RecordingState::Recording(_) | RecordingState::Starting(_)
        )
    }

    /// Run a subcommand via the client binary in the background
    fn run_client_subcommand(&self, args: &[&str]) {
        let binary = self.client_binary.clone();
        let args_owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        std::thread::spawn(move || {
            let mut cmd = Command::new(&binary);
            for arg in &args_owned {
                cmd.arg(arg);
            }
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                cmd.creation_flags(CREATE_NO_WINDOW);
            }
            let _ = cmd.output(); // wait for completion
        });
    }

    /// Ask the client to refresh the recording status file
    fn request_recording_status_refresh(&self) {
        self.run_client_subcommand(&["record", "status"]);
    }

    /// Poll recording status from the status file on disk
    fn poll_recording_status(&mut self) {
        // Only poll every 2 seconds
        if let Some(last) = self.last_recording_poll {
            if last.elapsed() < std::time::Duration::from_secs(2) {
                return;
            }
        }
        self.last_recording_poll = Some(Instant::now());

        if let Some(snapshot) = self.load_recording_status() {
            let applied = self.apply_recording_info(&snapshot);
            if !applied || snapshot.can_record.is_none() {
                self.request_recording_status_refresh();
            }
        } else {
            self.request_recording_status_refresh();
        }
    }

    fn recording_status_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(local_app) = dirs::data_local_dir() {
            paths.push(local_app.join("AIVPN").join("recording.status"));
        }
        paths.push(std::env::temp_dir().join("aivpn-recording.status"));
        paths
    }

    fn load_recording_status(&self) -> Option<RecordingSnapshot> {
        for path in Self::recording_status_paths() {
            if let Ok(data) = std::fs::read(&path) {
                if let Ok(snapshot) = serde_json::from_slice::<RecordingSnapshot>(&data) {
                    return Some(snapshot);
                }
            }
        }
        None
    }

    fn apply_recording_info(&mut self, snapshot: &RecordingSnapshot) -> bool {
        if snapshot.updated_at_ms < self.minimum_recording_ts {
            return false;
        }

        self.minimum_recording_ts = snapshot.updated_at_ms;
        self.recording_capability_known = snapshot.can_record.is_some();
        self.can_record_masks = snapshot.can_record.unwrap_or(false);

        let service = snapshot.service.clone().unwrap_or_else(|| "mask".to_string());
        match snapshot.state.as_str() {
            "recording" => {
                self.recording_state = RecordingState::Recording(service);
            }
            "stopping" => {
                self.recording_state = RecordingState::Stopping(service);
            }
            "analyzing" => {
                self.recording_state = RecordingState::Analyzing(service);
            }
            "success" => {
                self.recording_state =
                    RecordingState::Success(service, snapshot.mask_id.clone());
                let details = if let Some(ref mask_id) = snapshot.mask_id {
                    format!("Mask saved. ID: {}", mask_id)
                } else {
                    "Mask saved successfully.".to_string()
                };
                self.last_recording_result = Some(RecordingResult {
                    succeeded: true,
                    details,
                });
            }
            "failed" => {
                let reason = snapshot
                    .message
                    .clone()
                    .unwrap_or_else(|| "Recording failed".to_string());
                self.recording_state = RecordingState::Failed(service, reason.clone());
                self.last_recording_result = Some(RecordingResult {
                    succeeded: false,
                    details: reason,
                });
            }
            _ => {
                self.recording_state = RecordingState::Idle;
            }
        }

        true
    }

    // ── Traffic stats ───────────────────────────────────────────────────

    fn read_traffic_stats(&mut self) {
        // Try standard path first, then fallback
        let paths = [
            Self::stats_file_path(),
            std::env::temp_dir().join("aivpn-traffic.stats"),
        ];

        for path in &paths {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Some((sent, recv)) = Self::parse_stats(&content) {
                    // Only update if new values are >= current (avoid jumps down)
                    if sent >= self.stats.bytes_sent || self.stats.bytes_sent == 0 {
                        self.stats.bytes_sent = sent;
                    }
                    if recv >= self.stats.bytes_received || self.stats.bytes_received == 0 {
                        self.stats.bytes_received = recv;
                    }
                    return;
                }
            }
        }
    }

    fn parse_stats(content: &str) -> Option<(u64, u64)> {
        // Format: "sent:12345,received:67890"
        let content = content.trim();
        let mut sent = None;
        let mut recv = None;

        for part in content.split(',') {
            let mut kv = part.splitn(2, ':');
            match (kv.next(), kv.next()) {
                (Some("sent"), Some(v)) => sent = v.trim().parse().ok(),
                (Some("received"), Some(v)) => recv = v.trim().parse().ok(),
                _ => {}
            }
        }

        match (sent, recv) {
            (Some(s), Some(r)) => Some((s, r)),
            _ => None,
        }
    }

    fn stats_file_path() -> PathBuf {
        if cfg!(windows) {
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("AIVPN")
                .join("traffic.stats")
        } else {
            PathBuf::from("/var/run/aivpn/traffic.stats")
        }
    }

    fn find_client_binary() -> PathBuf {
        // 1. Next to this executable
        if let Ok(exe) = std::env::current_exe() {
            let dir = exe.parent().unwrap_or(std::path::Path::new("."));
            let candidate = dir.join("aivpn-client.exe");
            if candidate.exists() {
                return candidate;
            }
            // Also check without .exe for non-windows dev
            let candidate = dir.join("aivpn-client");
            if candidate.exists() {
                return candidate;
            }
        }

        // 2. Program Files
        if cfg!(windows) {
            let pf = PathBuf::from(r"C:\Program Files\AIVPN\aivpn-client.exe");
            if pf.exists() {
                return pf;
            }
        }

        // 3. Fallback — expect it in PATH
        PathBuf::from(if cfg!(windows) {
            "aivpn-client.exe"
        } else {
            "aivpn-client"
        })
    }
}

// ── Recording status file format (matches aivpn-client record_cmd.rs) ───

#[derive(Debug, serde::Deserialize)]
struct RecordingSnapshot {
    can_record: Option<bool>,
    state: String,
    service: Option<String>,
    message: Option<String>,
    mask_id: Option<String>,
    #[allow(dead_code)]
    confidence: Option<f32>,
    updated_at_ms: u64,
}

fn current_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Format byte count for display
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
