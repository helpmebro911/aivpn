//! Gateway Engine - Full Implementation
//! 
//! Handles:
//! - UDP packet reception with O(1) tag validation
//! - Decryption and de-mimicry
//! - NAT forwarding to internet
//! - Bidirectional traffic shaping
//! - Neural Resonance validation (Patent 1)
//! - Automatic mask rotation on compromise (Patent 3)

use std::net::{Ipv4Addr, SocketAddr, IpAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use bytes::BytesMut;
use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn, error, debug};

use aivpn_common::crypto::{
    self, encrypt_payload, decrypt_payload, SessionKeys,
    TAG_SIZE, NONCE_SIZE, CHACHA20_KEY_SIZE,
};
use aivpn_common::protocol::{
    AivpnPacket, InnerType, InnerHeader, ControlPayload, ControlSubtype,
    MAX_PACKET_SIZE, MIN_HEADER_OVERHEAD, AckPacket,
};
use aivpn_common::mask::{MaskProfile, SpoofProtocol};
use aivpn_common::error::{Error, Result};

use crate::session::{SessionManager, Session, SessionState};
use crate::nat::NatForwarder;
use crate::neural::{NeuralResonanceModule, NeuralConfig, ResonanceStatus};
use crate::metrics::MetricsCollector;
use crate::client_db::ClientDatabase;

struct QueuedPacket {
    packet_data: Vec<u8>,
    client_addr: SocketAddr,
}

/// Gateway configuration
#[derive(Clone)]
pub struct GatewayConfig {
    pub listen_addr: String,
    pub per_ip_pps_limit: u64,
    pub tun_name: String,
    pub tun_addr: String,
    pub tun_netmask: String,
    pub server_private_key: [u8; 32],
    pub signing_key: [u8; 64],
    pub enable_nat: bool,
    /// Enable neural resonance module (Patent 1)
    pub enable_neural: bool,
    /// Neural resonance configuration
    pub neural_config: NeuralConfig,
    /// Client database for PSK-based authentication
    pub client_db: Option<Arc<ClientDatabase>>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:443".to_string(),
            per_ip_pps_limit: 1000,
            tun_name: "aivpn0".to_string(),
            tun_addr: "10.0.0.1".to_string(),
            tun_netmask: "255.255.255.0".to_string(),
            server_private_key: [0u8; 32],
            signing_key: [0u8; 64],
            enable_nat: true,
            enable_neural: true,
            neural_config: NeuralConfig::default(),
            client_db: None,
        }
    }
}

/// Mask catalog for automatic rotation (Patent 3 + Patent 9)
///
/// Holds a pool of pre-generated masks. When neural resonance detects
/// that a mask is compromised by DPI, the catalog provides a replacement.
pub struct MaskCatalog {
    /// Available masks (mask_id → MaskProfile)
    masks: DashMap<String, MaskProfile>,
    /// Compromised mask IDs — never reuse
    compromised: DashMap<String, Instant>,
}

impl MaskCatalog {
    pub fn new() -> Self {
        use aivpn_common::mask::preset_masks;
        let catalog = Self {
            masks: DashMap::new(),
            compromised: DashMap::new(),
        };
        // Seed with built-in masks
        let m1 = preset_masks::webrtc_zoom_v3();
        let m2 = preset_masks::quic_https_v2();
        catalog.masks.insert(m1.mask_id.clone(), m1);
        catalog.masks.insert(m2.mask_id.clone(), m2);
        catalog
    }

    /// Register a new mask (e.g., received via passive distribution or neural unpack)
    pub fn register_mask(&self, mask: MaskProfile) {
        if !self.compromised.contains_key(&mask.mask_id) {
            self.masks.insert(mask.mask_id.clone(), mask);
        }
    }

    /// Mark a mask as compromised — remove from rotation
    pub fn mark_compromised(&self, mask_id: &str) {
        self.compromised.insert(mask_id.to_string(), Instant::now());
        self.masks.remove(mask_id);
    }

    /// Select the best non-compromised mask, excluding `current_mask_id`
    pub fn select_fallback(&self, current_mask_id: &str) -> Option<MaskProfile> {
        self.masks.iter()
            .filter(|e| e.key() != current_mask_id)
            .map(|e| e.value().clone())
            .next()
    }

    /// Get mask count
    pub fn available_count(&self) -> usize {
        self.masks.len()
    }
}

/// Hash a socket address for privacy-preserving logging (MED-4)
fn hash_addr(addr: &SocketAddr) -> String {
    let hash = crypto::blake3_hash(addr.to_string().as_bytes());
    format!("{:02x}{:02x}{:02x}{:02x}", hash[0], hash[1], hash[2], hash[3])
}

/// Gateway server
pub struct Gateway {
    config: GatewayConfig,
    session_manager: Arc<SessionManager>,
    udp_socket: Option<Arc<UdpSocket>>,
    nat_forwarder: Option<Arc<NatForwarder>>,
    /// Channel-based TUN writer (replaces Mutex for upload throughput)
    tun_write_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// Per-IP rate limiter: (packet_count, window_start)
    rate_limits: Arc<DashMap<IpAddr, (u64, Instant)>>,
    /// Neural Resonance Module (Patent 1) — periodic traffic validation
    neural_module: Arc<parking_lot::Mutex<NeuralResonanceModule>>,
    /// Mask catalog for automatic rotation (Patent 3)
    mask_catalog: Arc<MaskCatalog>,
    /// Metrics collector
    metrics: Arc<MetricsCollector>,
    /// Client database for PSK-based authentication
    client_db: Option<Arc<ClientDatabase>>,
}

impl Gateway {
    pub fn new(config: GatewayConfig) -> Result<Self> {
        use aivpn_common::mask::preset_masks::webrtc_zoom_v3;
        use rand::rngs::OsRng;
        use rand::RngCore;
        
        // Create server keypair (use config key if provided, otherwise generate ephemeral)
        let server_keys = if config.server_private_key != [0u8; 32] {
            crypto::KeyPair::from_private_key(config.server_private_key)
        } else {
            crypto::KeyPair::generate()
        };
        
        // Create Ed25519 signing key
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
        
        // Create default mask
        let default_mask = webrtc_zoom_v3();
        
        let session_manager = Arc::new(SessionManager::new(
            server_keys,
            signing_key,
            default_mask,
        ));
        
        // Initialize mask catalog (Patent 3 — fallback pool)
        let mask_catalog = Arc::new(MaskCatalog::new());
        
        // Initialize neural resonance module (Patent 1)
        let mut neural = NeuralResonanceModule::new(config.neural_config.clone())
            .map_err(|e| Error::Session(format!("Neural module init failed: {}", e)))?;
        
        if config.enable_neural {
            // Register all catalog masks for signature-based resonance checking
            for entry in mask_catalog.masks.iter() {
                let _ = neural.register_mask(entry.value());
            }
            // Load neural model (Baked Mask Encoder — ~66KB per mask)
            let _ = neural.load_model();
            info!("Neural Resonance Module initialized (Patent 1)");
        }
        
        // NAT forwarder is created lazily in run() to avoid requiring root at construction time
        Ok(Self {
            config: config.clone(),
            session_manager,
            udp_socket: None,
            nat_forwarder: None,
            tun_write_tx: None,
            rate_limits: Arc::new(DashMap::new()),
            neural_module: Arc::new(parking_lot::Mutex::new(neural)),
            mask_catalog,
            metrics: Arc::new(MetricsCollector::new()),
            client_db: config.client_db,
        })
    }
    
    /// Start the gateway
    pub async fn run(mut self) -> Result<()> {
        info!("Starting AIVPN Gateway on {}", self.config.listen_addr);
        info!("Per-IP UDP rate limit: {} pps", self.config.per_ip_pps_limit);
        
        // Create NAT forwarder (requires root — deferred from constructor for testability)
        if self.config.enable_nat {
            let mut nat = NatForwarder::new(
                &self.config.tun_name,
                &self.config.tun_addr,
                &self.config.tun_netmask,
            )?;
            nat.create()?;
            self.nat_forwarder = Some(Arc::new(nat));
            info!("TUN device: {} ({}/{})", 
                self.config.tun_name,
                self.config.tun_addr,
                self.config.tun_netmask
            );
        }
        
        // Create UDP socket with 4MB OS buffers (OPTIMIZATION)
        let bind_addr: SocketAddr = self.config.listen_addr.parse()
            .map_err(|e: std::net::AddrParseError| Error::Io(
                std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
            ))?;
            
        let socket2_sock = socket2::Socket::new(
            if bind_addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 },
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        ).map_err(Error::Io)?;
        
        socket2_sock.set_nonblocking(true).map_err(Error::Io)?;
        let _ = socket2_sock.set_recv_buffer_size(4 * 1024 * 1024);
        let _ = socket2_sock.set_send_buffer_size(4 * 1024 * 1024);
        socket2_sock.bind(&bind_addr.into()).map_err(Error::Io)?;
        
        let std_sock: std::net::UdpSocket = socket2_sock.into();
        let socket = UdpSocket::from_std(std_sock).map_err(Error::Io)?;
        
        info!("UDP listener bound to {} (4MB buffers via socket2)", self.config.listen_addr);
        
        self.udp_socket = Some(Arc::new(socket));
        
        // Spawn neural resonance check loop (Patent 1 — periodic validation)
        if self.config.enable_neural {
            let neural = self.neural_module.clone();
            let sessions = self.session_manager.clone();
            let catalog = self.mask_catalog.clone();
            let metrics = self.metrics.clone();
            let check_interval = self.config.neural_config.check_interval_secs;
            
            tokio::spawn(async move {
                Self::resonance_check_loop(neural, sessions, catalog, metrics, check_interval).await;
            });
            info!("Neural resonance check loop spawned (interval: {}s)", check_interval);
        }
        
        // Spawn TUN → Client read loop (reads packets from TUN, routes back to clients)
        // Also set up channel-based TUN writer for upload path (avoids Mutex contention)
        if let Some(ref nat) = self.nat_forwarder {
            if let Some(tun_reader) = nat.take_reader().await {
                let sessions = self.session_manager.clone();
                let socket = self.udp_socket.as_ref().unwrap().clone();
                let mask = aivpn_common::mask::preset_masks::webrtc_zoom_v3();
                let tun_addr = self.config.tun_addr.clone();
                
                // Channel for writing packets to TUN device (upload + ICMP replies)
                let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(4096);
                self.tun_write_tx = Some(tun_tx.clone());
                
                // Spawn dedicated TUN writer task — owns the DeviceWriter, no Mutex needed
                if let Some(tun_writer) = nat.take_writer().await {
                    tokio::spawn(async move {
                        Self::tun_write_loop(tun_writer, tun_rx).await;
                    });
                    info!("TUN write loop spawned (channel-based, no Mutex)");
                } else {
                    warn!("Could not take TUN writer — falling back to forward_packet");
                }
                
                tokio::spawn(async move {
                    Self::tun_read_loop(tun_reader, tun_tx, sessions, socket, mask, tun_addr).await;
                });
                info!("TUN read loop spawned");
            }
        }
        
        // Spawn periodic session cleanup task (remove expired/idle sessions)
        {
            let sessions = self.session_manager.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    sessions.cleanup_expired();
                }
            });
            info!("Session cleanup task spawned (60s interval)");
        }
        
        // Spawn client DB stats flush task (persist traffic stats every 5 min)
        if let Some(ref db) = self.client_db {
            let db = db.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(300)).await;
                    db.flush_stats();
                }
            });
            info!("Client stats flush task spawned (300s interval)");
        }
        
        // Spawn client DB hot-reload task (pick up new clients without restart)
        if let Some(ref db) = self.client_db {
            let db = db.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    db.reload_if_changed();
                }
            });
            info!("Client DB hot-reload task spawned (10s interval)");
        }
        
        // Use session-aware receive sharding: preserve ordering within one
        // session, but allow different sessions to make progress in parallel.
        let gateway = Arc::new(self);
        Self::process_packets_concurrent(gateway).await?;
        
        Ok(())
    }
    
    /// Background task: periodic neural resonance checks (Patent 1)
    ///
    /// For each active session, computes reconstruction error between
    /// observed traffic features and the assigned mask's signature vector.
    /// If MSE exceeds threshold → mask is detected as compromised by DPI.
    /// Triggers automatic mask rotation (Patent 3).
    async fn resonance_check_loop(
        neural: Arc<parking_lot::Mutex<NeuralResonanceModule>>,
        sessions: Arc<SessionManager>,
        catalog: Arc<MaskCatalog>,
        metrics: Arc<MetricsCollector>,
        check_interval_secs: u64,
    ) {
        let interval = Duration::from_secs(check_interval_secs);
        
        loop {
            tokio::time::sleep(interval).await;
            
            // Collect session IDs and their mask IDs
            let session_checks: Vec<([u8; 16], String)> = sessions.iter_sessions()
                .filter_map(|entry| {
                    let sess = entry.value().lock();
                    let mask_id = sess.mask.as_ref().map(|m| m.mask_id.clone())
                        .unwrap_or_else(|| "webrtc_zoom_v3".to_string());
                    Some((sess.session_id, mask_id))
                })
                .collect();
            
            if session_checks.is_empty() {
                continue;
            }
            
            let neural_guard = neural.lock();
            
            for (session_id, mask_id) in &session_checks {
                // Check neural resonance (Patent 1: Signal Reconstruction Resonance)
                match neural_guard.check_resonance(*session_id, mask_id) {
                    Ok(result) => {
                        metrics.record_neural_check(result.status == ResonanceStatus::Compromised);
                        
                        match result.status {
                            ResonanceStatus::Compromised => {
                                warn!(
                                    "Mask '{}' compromised (MSE={:.4}) — triggering rotation (Patent 3)",
                                    mask_id, result.mse
                                );
                                
                                // Mark mask as compromised in catalog
                                catalog.mark_compromised(mask_id);
                                
                                // Select fallback mask
                                if let Some(new_mask) = catalog.select_fallback(mask_id) {
                                    info!(
                                        "Auto-rotating to mask '{}' ({} masks remaining)",
                                        new_mask.mask_id,
                                        catalog.available_count()
                                    );
                                    
                                    // Update session's mask
                                    sessions.update_session_mask(session_id, new_mask.clone());
                                    
                                    metrics.record_mask_rotation();
                                } else {
                                    error!("No fallback masks available! All masks compromised.");
                                }
                            }
                            ResonanceStatus::Warning => {
                                debug!(
                                    "Mask '{}' warning (MSE={:.4}) — monitoring",
                                    mask_id, result.mse
                                );
                            }
                            ResonanceStatus::Healthy => {
                                // All good
                            }
                            ResonanceStatus::Skip => {
                                // Not enough data or model not loaded
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Resonance check error for session: {}", e);
                    }
                }
                
                // Check anomaly detection (DPI blocking indicators)
                if neural_guard.is_mask_anomalous(mask_id) {
                    warn!("Anomaly detected for mask '{}' (packet loss / RTT spike)", mask_id);
                    metrics.record_dpi_attack();
                    catalog.mark_compromised(mask_id);
                    
                    if let Some(new_mask) = catalog.select_fallback(mask_id) {
                        info!(
                            "Anomaly-triggered rotation to mask '{}'",
                            new_mask.mask_id
                        );
                        sessions.update_session_mask(session_id, new_mask);
                        metrics.record_mask_rotation();
                    }
                }
            }
        }
    }
    
    /// TUN read loop: reads packets from TUN device and routes them back to clients
    async fn tun_read_loop(
        mut tun_reader: tun::DeviceReader,
        tun_writer: tokio::sync::mpsc::Sender<Vec<u8>>,
        sessions: Arc<SessionManager>,
        socket: Arc<UdpSocket>,
        mask: MaskProfile,
        tun_addr: String,
    ) {
        use aivpn_common::crypto::POLY1305_TAG_SIZE;
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let server_ip: Ipv4Addr = tun_addr.parse().unwrap_or(Ipv4Addr::new(10, 0, 0, 1));
        
        loop {
            match tun_reader.read(&mut buf).await {
                Ok(0) => continue,
                Ok(n) => {
                    let packet = &buf[..n];
                    
                    // Parse destination IP from IP header
                    if packet.len() < 20 || (packet[0] >> 4) != 4 {
                        continue; // Not IPv4
                    }
                    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                    
                    // Handle ICMP echo request to server's own IP (ping to gateway)
                    if dst_ip == server_ip && packet.len() >= 28 && packet[9] == 1 {
                        // ICMP packet to server — generate echo reply
                        if let Some(reply) = Self::build_icmp_echo_reply(packet, &server_ip) {
                            let _ = tun_writer.send(reply).await;
                        }
                        continue;
                    }
                    
                    // Find session by VPN IP
                    let session = match sessions.get_session_by_vpn_ip(&dst_ip) {
                        Some(s) => s,
                        None => {
                            debug!("TUN: no session for VPN IP {}", dst_ip);
                            continue;
                        }
                    };
                    
                    // Build encrypted response packet
                    // Minimize lock duration: extract only what we need under lock, then encrypt outside
                    let (client_addr, nonce, tag, mdh, ciphertext) = {
                        let mut sess = session.lock();
                        let client_addr = sess.client_addr;
                        let seq_num = sess.next_seq() as u16;
                        let (nonce, counter) = sess.next_send_nonce();
                        let key = sess.keys.session_key.clone();
                        let tag_secret = sess.keys.tag_secret;
                        drop(sess); // Release lock BEFORE expensive encryption
                        
                        // Build inner payload: Data type + IP packet
                        let inner_header = InnerHeader {
                            inner_type: InnerType::Data,
                            seq_num,
                        };
                        let mut inner_payload = inner_header.encode().to_vec();
                        inner_payload.extend_from_slice(packet);
                        
                        // Build MDH (no eph_pub for data packets)
                        let mdh = mask.header_template.clone();
                        
                        // Pad and encrypt (outside lock)
                        let pad_len: u16 = 0;
                        let mut padded = Vec::with_capacity(2 + inner_payload.len());
                        padded.extend_from_slice(&pad_len.to_le_bytes());
                        padded.extend_from_slice(&inner_payload);
                        
                        let ciphertext = match encrypt_payload(&key, &nonce, &padded) {
                            Ok(ct) => ct,
                            Err(e) => {
                                debug!("TUN: encrypt error: {}", e);
                                continue;
                            }
                        };
                        
                        // Generate tag (outside lock)
                        let time_window = crypto::compute_time_window(
                            crypto::current_timestamp_ms(),
                            aivpn_common::crypto::DEFAULT_WINDOW_MS,
                        );
                        let tag = crypto::generate_resonance_tag(
                            &tag_secret,
                            counter,
                            time_window,
                        );
                        
                        (client_addr, nonce, tag, mdh, ciphertext)
                    };
                    
                    // Assemble: TAG | MDH | ciphertext
                    let mut aivpn_packet = Vec::with_capacity(TAG_SIZE + mdh.len() + ciphertext.len());
                    aivpn_packet.extend_from_slice(&tag);
                    aivpn_packet.extend_from_slice(&mdh);
                    aivpn_packet.extend_from_slice(&ciphertext);
                    
                    // Send to client
                    if let Err(e) = socket.send_to(&aivpn_packet, client_addr).await {
                        debug!("TUN: send failed: {}", e);
                    }
                }
                Err(e) => {
                    error!("TUN read error: {}", e);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }
    
    /// Build ICMP Echo Reply from Echo Request
    fn build_icmp_echo_reply(request: &[u8], server_ip: &Ipv4Addr) -> Option<Vec<u8>> {
        if request.len() < 28 {
            return None;
        }
        
        // Parse source IP
        let src_ip = Ipv4Addr::new(request[12], request[13], request[14], request[15]);
        
        // Parse ICMP type and code
        let icmp_type = request[20];
        if icmp_type != 8 {
            return None; // Not echo request
        }
        
        // Build reply: swap src/dst IP, change ICMP type to 0 (echo reply)
        let mut reply = Vec::with_capacity(request.len());
        
        // IP header
        reply.push(0x45); // Version 4, IHL 5
        reply.push(0x00); // DSCP/ECN
        let total_len = (request.len() as u16).to_be_bytes();
        reply.extend_from_slice(&total_len);
        reply.extend_from_slice(&request[4..6]); // Identification
        reply.extend_from_slice(&request[6..8]); // Flags/Fragment
        reply.push(64); // TTL
        reply.push(1);  // Protocol: ICMP
        reply.push(0);  // Header checksum (will be computed by kernel)
        reply.push(0);
        reply.extend_from_slice(&server_ip.octets()); // Source IP (server)
        reply.extend_from_slice(&src_ip.octets());    // Dest IP (client)
        
        // ICMP header
        reply.push(0);  // Type: Echo Reply
        reply.push(request[21]); // Code
        reply.push(0);  // Checksum placeholder
        reply.push(0);
        reply.extend_from_slice(&request[24..28]); // ID + Sequence
        reply.extend_from_slice(&request[28..]);   // Data
        
        // Compute ICMP checksum
        let checksum = Self::compute_checksum(&reply[20..]);
        reply[22] = (checksum >> 8) as u8;
        reply[23] = (checksum & 0xFF) as u8;
        
        Some(reply)
    }
    
    /// Compute Internet checksum (RFC 1071)
    fn compute_checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        
        // Process 16-bit words
        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }
        
        // Add remaining byte
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        
        // Fold 32-bit sum to 16 bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        !sum as u16
    }
    
    /// Dedicated TUN writer task — owns the DeviceWriter, no Mutex contention
    async fn tun_write_loop(mut writer: tun::DeviceWriter, mut rx: mpsc::Receiver<Vec<u8>>) {
        while let Some(packet) = rx.recv().await {
            if let Err(e) = writer.write_all(&packet).await {
                error!("TUN write error: {}", e);
            }
            // No flush() — let the OS buffer writes for throughput
        }
        warn!("TUN write loop ended — channel closed");
    }
    
    fn receive_worker_count() -> usize {
        std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(4)
            .clamp(2, 16)
    }

    fn worker_index_for_packet(&self, packet_data: &[u8], client_addr: SocketAddr, worker_count: usize) -> usize {
        if worker_count <= 1 {
            return 0;
        }

        let mut shard_addr = client_addr;

        if packet_data.len() >= TAG_SIZE {
            let mut tag = [0u8; TAG_SIZE];
            tag.copy_from_slice(&packet_data[..TAG_SIZE]);

            if let Some(session) = self.session_manager.get_session_by_tag(&tag) {
                shard_addr = session.lock().client_addr;
            }
        }

        let key = match shard_addr.ip() {
            IpAddr::V4(ip) => {
                ((u32::from(ip) as u64) << 16) | shard_addr.port() as u64
            }
            IpAddr::V6(ip) => {
                let octets = ip.octets();
                u64::from_le_bytes(octets[..8].try_into().unwrap()) ^ shard_addr.port() as u64
            }
        };

        (key as usize) % worker_count
    }

    /// Concurrent packet processing loop with shard workers.
    /// Packets for the same session stay on the same worker and preserve order,
    /// while different sessions can be processed in parallel.
    async fn process_packets_concurrent(gateway: Arc<Self>) -> Result<()> {
        let socket = gateway.udp_socket.as_ref().unwrap().clone();
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let worker_count = Self::receive_worker_count();
        let queue_depth = 4096;
        let mut worker_txs = Vec::with_capacity(worker_count);

        for worker_id in 0..worker_count {
            let (tx, mut rx) = mpsc::channel::<QueuedPacket>(queue_depth);
            worker_txs.push(tx);

            let gw = gateway.clone();
            tokio::spawn(async move {
                while let Some(packet) = rx.recv().await {
                    if let Err(e) = gw.handle_packet(&packet.packet_data, packet.client_addr).await {
                        debug!(
                            "Worker {} packet error from {}: {}",
                            worker_id,
                            hash_addr(&packet.client_addr),
                            e
                        );
                    }
                }
                warn!("Receive worker {} ended — channel closed", worker_id);
            });
        }
        
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, client_addr)) => {
                    // Per-IP rate limiting (fast, stays in recv task)
                    {
                        let now = Instant::now();
                        let mut entry = gateway.rate_limits.entry(client_addr.ip()).or_insert((0, now));
                        if entry.1.elapsed() > Duration::from_secs(1) {
                            entry.0 = 0;
                            entry.1 = now;
                        }
                        entry.0 += 1;
                        if entry.0 > gateway.config.per_ip_pps_limit {
                            continue;
                        }
                    }
                    
                    let packet_data = buf[..len].to_vec();
                    let worker_idx = gateway.worker_index_for_packet(&packet_data, client_addr, worker_count);
                    let packet = QueuedPacket { packet_data, client_addr };

                    if worker_txs[worker_idx].send(packet).await.is_err() {
                        return Err(Error::Channel(format!("Receive worker {worker_idx} channel closed")));
                    }
                }
                Err(e) => {
                    error!("UDP recv error: {}", e);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }
    
    /// Main packet processing loop (legacy sequential — unused, kept for reference)
    #[allow(dead_code)]
    async fn process_packets(&self) -> Result<()> {
        let socket = self.udp_socket.as_ref().unwrap();
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, client_addr)) => {
                    // Per-IP rate limiting.
                    {
                        let now = Instant::now();
                        let mut entry = self.rate_limits.entry(client_addr.ip()).or_insert((0, now));
                        if entry.1.elapsed() > Duration::from_secs(1) {
                            entry.0 = 0;
                            entry.1 = now;
                        }
                        entry.0 += 1;
                        if entry.0 > self.config.per_ip_pps_limit {
                            continue;
                        }
                    }
                    
                    let packet_data = &buf[..len];
                    
                    // Process packet
                    if let Err(e) = self.handle_packet(packet_data, client_addr).await {
                        debug!("Packet error from {}: {}", hash_addr(&client_addr), e);
                        // Silent drop - no response for invalid packets
                    }
                }
                Err(e) => {
                    error!("UDP recv error: {}", e);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }
    
    /// Handle incoming packet
    async fn handle_packet(&self, packet_data: &[u8], client_addr: SocketAddr) -> Result<()> {
        // Minimum packet size check
        if packet_data.len() < TAG_SIZE + 2 {
            return Err(Error::InvalidPacket("Too short"));
        }
        
        // Extract resonance tag
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&packet_data[0..TAG_SIZE]);
        
        // O(1) tag validation - find session
        let mdh_len = 4; // Default for MVP
        let mut is_new_session = false;
        let (session, counter, is_ratcheted_tag) = if let Some(session) = self.session_manager.get_session_by_tag(&tag) {
            // Existing session — validate tag
            let (counter, is_ratcheted) = {
                let sess = session.lock();
                sess.validate_tag(&tag)
                    .ok_or(Error::InvalidPacket("Invalid tag"))?
            };
            (session, counter, is_ratcheted)
        } else if let Some((session, counter, is_ratcheted)) = self.session_manager.refresh_and_find_by_tag(&tag) {
            // Tag not in map — time window may have advanced. Refresh all sessions and retry.
            debug!("Tag matched after refresh (counter={}, ratcheted={})", counter, is_ratcheted);
            (session, counter, is_ratcheted)
        } else if let Some((session, counter, is_ratcheted)) = self.session_manager.recover_session_by_tag(&tag, &client_addr.ip()) {
            // Counter drift recovery — client counter was out of range but session keys match
            (session, counter, is_ratcheted)
        } else {
            // Small packets from a competing endpoint on the same public IP are
            // usually stale duplicate control/init traffic after a successful
            // ratcheted session has already been established. Dropping them is
            // safer than spawning another ServerHello loop.
            if packet_data.len() <= 160
                && self
                    .session_manager
                    .has_recent_ratcheted_session_on_other_endpoint(&client_addr, Duration::from_secs(30))
            {
                debug!(
                    "Dropping duplicate-endpoint control/init packet from {} (packet_len={})",
                    hash_addr(&client_addr),
                    packet_data.len()
                );
                return Err(Error::InvalidPacket("Stale duplicate-endpoint packet"));
            }

            // No session found — try handshake
            // Try to establish a new one from eph_pub in MDH
            if packet_data.len() < TAG_SIZE + mdh_len + 32 {
                return Err(Error::InvalidPacket("Too short for session init"));
            }
            let eph_start = TAG_SIZE + mdh_len;
            if packet_data.len() < eph_start + 32 {
                return Err(Error::InvalidPacket("Missing eph_pub for new session"));
            }
            let mut eph_pub = [0u8; 32];
            eph_pub.copy_from_slice(&packet_data[eph_start..eph_start + 32]);
            
            // Deobfuscate eph_pub (HIGH-9)
            crypto::obfuscate_eph_pub(&mut eph_pub, &self.session_manager.server_public_key());
            
            // Try to create session with each registered client's PSK.
            // If client_db is configured, iterate registered clients and try
            // DH + PSK to find one whose derived tags match.
            // Falls back to no-PSK for backward compatibility.
            let (session, matched_client_id) = if let Some(ref db) = self.client_db {
                let clients = db.list_clients();
                let mut found = None;
                for client_cfg in &clients {
                    if !client_cfg.enabled { continue; }
                    let psk = client_cfg.psk;
                    match self.session_manager.create_session(
                        client_addr,
                        eph_pub,
                        Some(psk),
                        Some(client_cfg.vpn_ip),
                    ) {
                        Ok(sess) => {
                            let validation = sess.lock().validate_tag(&tag);
                            if validation.is_some() {
                                found = Some((sess, Some(client_cfg.id.clone())));
                                break;
                            } else {
                                // PSK mismatch — rollback this attempt
                                let sid = sess.lock().session_id;
                                self.session_manager.rollback_failed_session(&sid);
                            }
                        }
                        Err(e) => {
                            debug!("create_session failed: {}", e);
                            continue;
                        }
                    }
                }
                match found {
                    Some(f) => f,
                    None => {
                        return Err(Error::InvalidPacket("No registered client matches this handshake"));
                    }
                }
            } else {
                // No client DB — legacy mode without PSK
                let sess = self.session_manager.create_session(
                    client_addr,
                    eph_pub,
                    None,
                    None,
                )?;
                (sess, None)
            };
            
            // Validate the tag against the session.
            let validation = {
                let sess = session.lock();
                sess.validate_tag(&tag)
            };
            let (counter, is_ratcheted) = match validation {
                Some(result) => result,
                None => {
                    let session_id = session.lock().session_id;
                    self.session_manager.rollback_failed_session(&session_id);
                    return Err(Error::InvalidPacket("Tag mismatch on new session"));
                }
            };
            
            // Tag is valid — this is a real handshake.
            // Clean up any old sessions from the same client IP.
            {
                let session_id = session.lock().session_id;
                self.session_manager.cleanup_old_sessions_for_ip(
                    &client_addr.ip(),
                    &session_id,
                );
            }
            
            // Record handshake in client DB
            if let (Some(ref db), Some(ref cid)) = (&self.client_db, &matched_client_id) {
                db.record_handshake(cid);
                // Store client_id in session for traffic accounting
                session.lock().client_id = Some(cid.clone());
                info!("Client '{}' authenticated via PSK", cid);
            }
            
            // Send ServerHello for PFS ratchet + server authentication (CRIT-3 + HIGH-6)
            {
                let (server_eph_pub, signature) = {
                    let sess = session.lock();
                    match (sess.server_eph_pub, sess.server_hello_signature) {
                        (Some(pub_key), Some(sig)) => (pub_key, sig),
                        _ => return Err(Error::Session("Missing ratchet data".into())),
                    }
                };
                let hello = ControlPayload::ServerHello { server_eph_pub, signature };
                let encoded = hello.encode()?;
                let inner_header = InnerHeader {
                    inner_type: InnerType::Control,
                    seq_num: 0,
                };
                let mut inner_payload = inner_header.encode().to_vec();
                inner_payload.extend_from_slice(&encoded);
                let packet = self.build_packet(&inner_payload, &session)?;
                let socket = self.udp_socket.as_ref().unwrap();
                let sent = socket.send_to(&packet, client_addr).await?;
                debug!("ServerHello sent: {} bytes to {}", sent, client_addr);
            }
            
            // NOTE: PFS ratchet is deferred until AFTER decrypting the init packet,
            // which was encrypted with pre-ratchet keys.
            
            is_new_session = true;
            info!("New session from {} (ServerHello sent)", hash_addr(&client_addr));
            (session, counter, is_ratcheted)
        };
        
        // Parse packet — pad_len is inside encrypted area (CRIT-5 fix)
        // For init packets, eph_pub (32 bytes) follows MDH before ciphertext
        let payload_offset = if is_new_session {
            TAG_SIZE + mdh_len + 32
        } else {
            TAG_SIZE + mdh_len
        };
        if packet_data.len() <= payload_offset {
            return Err(Error::InvalidPacket("Invalid length"));
        }
        
        // Decrypt with appropriate keys (initial or ratcheted)
        let encrypted_payload = &packet_data[payload_offset..];
        
        let padded_plaintext = {
            let sess = session.lock();
            let nonce = self.compute_nonce(counter);
            let key = if is_ratcheted_tag {
                &sess.ratcheted_keys.as_ref()
                    .ok_or(Error::InvalidPacket("Ratcheted keys missing"))?
                    .session_key
            } else {
                &sess.keys.session_key
            };
            decrypt_payload(key, &nonce, encrypted_payload)?
        };
        
        // Complete PFS ratchet only when the CLIENT proves it has ratcheted
        // by sending a packet with ratcheted-key tags.
        // Do NOT ratchet on is_new_session — the client hasn't received
        // ServerHello yet and will keep sending packets with initial keys.
        if is_ratcheted_tag {
            let session_id = session.lock().session_id;
            self.session_manager.complete_session_ratchet(&session_id);
            self.session_manager.refresh_session_tags(&session_id);
            let sess = session.lock();
            info!("PFS ratchet complete for {} — send_counter={}, counter={}", 
                hash_addr(&client_addr), sess.send_counter, sess.counter);
        }
        
        // Extract pad_len from inside decrypted data and strip padding
        if padded_plaintext.len() < 2 {
            return Err(Error::InvalidPacket("Decrypted payload too short"));
        }
        let pad_len = u16::from_le_bytes([padded_plaintext[0], padded_plaintext[1]]) as usize;
        if 2 + pad_len > padded_plaintext.len() {
            return Err(Error::InvalidPacket("Invalid padding length"));
        }
        let plaintext = &padded_plaintext[2..padded_plaintext.len() - pad_len];
        
        // Update session state. Avoid expensive O(window) tag-map rebuild on every packet.
        let mut client_db_flush: Option<(String, u64)> = None;
        let (session_id, refresh_tags) = {
            let mut sess = session.lock();
            sess.mark_tag_received(counter);
            sess.last_seen = std::time::Instant::now();

            // IP migration: update stored client address when a validated packet
            // arrives from a different endpoint (e.g. WiFi → cellular switchover).
            // Safe because the packet passed full cryptographic validation.
            if !is_new_session && sess.client_addr != client_addr {
                info!("Client endpoint migrated: {} → {} (session keepalive active)",
                    hash_addr(&sess.client_addr), hash_addr(&client_addr));
                sess.client_addr = client_addr;
            }

            // Refresh precomputed tag window only when we've moved far enough.
            // Window size is 256; refreshing every 64 packets keeps enough headroom
            // while reducing CPU spent in HashMap/tag_map maintenance.
            let refresh_tags = counter.saturating_sub(sess.tag_window_base) >= 64;
            if refresh_tags {
                sess.update_tag_window();
            }

            // Batch client stats updates to avoid taking a global write lock per packet.
            sess.pending_bytes_in = sess.pending_bytes_in.saturating_add(packet_data.len() as u64);
            if sess.pending_bytes_in >= 16 * 1024 {
                if let Some(cid) = sess.client_id.clone() {
                    client_db_flush = Some((cid, sess.pending_bytes_in));
                }
                sess.pending_bytes_in = 0;
            }

            sess.update_fsm();
            (sess.session_id, refresh_tags)
        };
        
        // Refresh tag_map only when the precomputed window moves.
        if refresh_tags {
            self.session_manager.refresh_session_tags(&session_id);
        }
        
        // Record traffic stats for neural resonance (Patent 1)
        if self.config.enable_neural {
            let packet_size = packet_data.len() as u16;
            // Compute byte-level entropy of the encrypted payload
            let entropy = Self::compute_entropy(encrypted_payload);
            // IAT is approximated by the last_seen timing
            let iat_ms = 0.0; // Will be calculated from session timestamps in check loop
            // Neural model update is expensive under lock. Sampling every 16th packet
            // preserves trends while reducing lock contention in the receive hot path.
            if counter & 0x0f == 0 {
                self.neural_module.lock().record_traffic(
                    session_id, packet_size, iat_ms, entropy,
                );
            }
            self.metrics.record_packet_received(packet_data.len());
        }
        
        // Record traffic in client DB in batches (see pending_bytes_in above).
        if let (Some(ref db), Some((cid, bytes_in))) = (&self.client_db, client_db_flush) {
            db.record_traffic(&cid, bytes_in, 0);
        }
        
        // Process inner payload (skip for new sessions — ServerHello is already the response,
        // and any ControlAck sent here would use pre-ratchet keys that the client can't validate)
        if !is_new_session {
            self.process_inner_payload(plaintext, &session, client_addr).await?;
        }
        
        Ok(())
    }
    
    /// Compute nonce from counter
    fn compute_nonce(&self, counter: u64) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..8].copy_from_slice(&counter.to_le_bytes());
        nonce
    }
    
    /// Process decrypted inner payload
    async fn process_inner_payload(
        &self,
        plaintext: &[u8],
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
    ) -> Result<()> {
        if plaintext.len() < 4 {
            return Err(Error::InvalidPacket("Inner payload too short"));
        }
        
        let inner_header = InnerHeader::decode(plaintext)?;
        let payload = &plaintext[4..];
        
        match inner_header.inner_type {
            InnerType::Data => {
                // Forward to NAT/internet via TUN write channel (lock-free)
                debug!("DATA packet from {} ({} bytes)", hash_addr(&client_addr), payload.len());
                
                if let Some(ref tx) = self.tun_write_tx {
                    if tx.send(payload.to_vec()).await.is_err() {
                        debug!("TUN write channel closed, dropping packet");
                    }
                } else if let Some(ref nat) = self.nat_forwarder {
                    nat.forward_packet(payload).await?;
                } else {
                    debug!("NAT disabled, dropping packet");
                }
            }
            InnerType::Control => {
                self.handle_control_message(payload, session, client_addr).await?;
            }
            InnerType::Fragment => {
                // TODO: Implement fragmentation
                debug!("FRAGMENT packet (not implemented)");
            }
            InnerType::Ack => {
                // Handle ACK
                debug!("ACK packet received");
            }
        }
        
        Ok(())
    }
    
    /// Handle control message
    async fn handle_control_message(
        &self,
        payload: &[u8],
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
    ) -> Result<()> {
        let control = ControlPayload::decode(payload)?;
        
        match control {
            ControlPayload::KeyRotate { new_eph_pub } => {
                info!("Key rotation request from {}", hash_addr(&client_addr));
                // TODO: Implement key rotation
            }
            ControlPayload::MaskUpdate { .. } => {
                warn!("Unexpected MASK_UPDATE from client");
            }
            ControlPayload::Keepalive => {
                debug!("Keepalive from {}", hash_addr(&client_addr));
                // Send ACK
                let ack = ControlPayload::ControlAck {
                    ack_seq: 0,
                    ack_for_subtype: ControlSubtype::Keepalive as u8,
                };
                self.send_control_message(&ack, session).await?;
            }
            ControlPayload::TelemetryRequest { metric_flags } => {
                debug!("Telemetry request from {}", hash_addr(&client_addr));
                // Send response
                let response = ControlPayload::TelemetryResponse {
                    packet_loss: 0,
                    rtt_ms: 10,
                    jitter_ms: 2,
                    buffer_pct: 25,
                };
                self.send_control_message(&response, session).await?;
            }
            ControlPayload::TelemetryResponse { .. } => {
                debug!("Telemetry response received");
            }
            ControlPayload::TimeSync { .. } => {
                debug!("Time sync request");
            }
            ControlPayload::Shutdown { reason } => {
                info!("Shutdown request from {} (reason: {})", hash_addr(&client_addr), reason);
                // Close session
                let session_id = session.lock().session_id;
                self.session_manager.remove_session(&session_id);
            }
            ControlPayload::ControlAck { .. } => {
                // ACK received, nothing to do
            }
            ControlPayload::ServerHello { .. } => {
                warn!("Unexpected ServerHello from client {}", hash_addr(&client_addr));
            }
        }
        
        Ok(())
    }
    
    /// Send control message to client
    async fn send_control_message(
        &self,
        payload: &ControlPayload,
        session: &Arc<parking_lot::Mutex<Session>>,
    ) -> Result<()> {
        let socket = self.udp_socket.as_ref().unwrap();
        
        let encoded = payload.encode()?;
        let mut inner_payload = {
            let mut sess = session.lock();
            let inner_header = InnerHeader {
                inner_type: InnerType::Control,
                seq_num: sess.next_seq() as u16,
            };
            inner_header.encode().to_vec()
        };
        inner_payload.extend_from_slice(&encoded);
        let packet = self.build_packet(&inner_payload, session)?;
        
        // Extract client_addr before dropping the guard to avoid holding
        // MutexGuard across .await (which would cause deadlock)
        let client_addr = session.lock().client_addr;
        socket.send_to(&packet, client_addr).await?;
        
        Ok(())
    }
    
    /// Build AIVPN packet
    /// Wire format: TAG | MDH | encrypt(pad_len_u16 || plaintext || random_padding)
    fn build_packet(
        &self,
        plaintext: &[u8],
        session: &Arc<parking_lot::Mutex<Session>>,
    ) -> Result<Vec<u8>> {
        let mut sess = session.lock();
        
        // Use unified counter for both nonce and tag
        let (nonce, counter) = sess.next_send_nonce();
        
        // Build padded plaintext: pad_len(u16) || plaintext || random_padding
        // pad_len is inside encryption — invisible to DPI (CRIT-5 fix)
        let pad_len = 16u16;
        let mut padded = Vec::with_capacity(2 + plaintext.len() + pad_len as usize);
        padded.extend_from_slice(&pad_len.to_le_bytes());
        padded.extend_from_slice(plaintext);
        use rand::Rng;
        let mut rng = rand::thread_rng();
        for _ in 0..pad_len {
            padded.push(rng.gen::<u8>());
        }
        
        let ciphertext = encrypt_payload(&sess.keys.session_key, &nonce, &padded)?;
        
        // Generate tag
        let time_window = crypto::compute_time_window(
            crypto::current_timestamp_ms(),
            aivpn_common::crypto::DEFAULT_WINDOW_MS,
        );
        let tag = crypto::generate_resonance_tag(
            &sess.keys.tag_secret,
            counter,
            time_window,
        );
        
        // Build MDH (simple for MVP)
        let mdh = vec![0u8; 4];
        
        // Assemble packet: TAG | MDH | ciphertext (no cleartext padding)
        let mut packet = Vec::with_capacity(TAG_SIZE + mdh.len() + ciphertext.len());
        packet.extend_from_slice(&tag);
        packet.extend_from_slice(&mdh);
        packet.extend_from_slice(&ciphertext);
        
        Ok(packet)
    }
    
    /// Compute Shannon entropy of a byte slice (0.0 = uniform, 8.0 = max)
    fn compute_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut counts = [0u32; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &c in &counts {
            if c > 0 {
                let p = c as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
    
    /// Get mask catalog reference
    pub fn mask_catalog(&self) -> &Arc<MaskCatalog> {
        &self.mask_catalog
    }
    
    /// Get metrics reference
    pub fn metrics(&self) -> &Arc<MetricsCollector> {
        &self.metrics
    }
}
