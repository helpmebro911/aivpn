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
use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn, error, debug};

use aivpn_common::crypto::{
    self, encrypt_payload, decrypt_payload,
    TAG_SIZE, NONCE_SIZE,
};
use aivpn_common::protocol::{
    InnerType, InnerHeader, ControlPayload, ControlSubtype,
    MAX_PACKET_SIZE,
};
use aivpn_common::mask::{
    current_unix_secs, derive_bootstrap_candidates, BootstrapDescriptor, MaskProfile,
};
use aivpn_common::error::{Error, Result};
use aivpn_common::network_config::VpnNetworkConfig;

use crate::session::{SessionManager, Session};
use crate::nat::NatForwarder;
use crate::neural::{NeuralResonanceModule, NeuralConfig, ResonanceStatus};
use crate::metrics::MetricsCollector;
use crate::client_db::ClientDatabase;
use crate::recording::RecordingManager;
use crate::recording::{RecordingStopOutcome, RecordingStopReason};
use crate::mask_gen::generate_and_store_mask;
use crate::mask_store::MaskStore;

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
    pub network_config: VpnNetworkConfig,
    pub server_private_key: [u8; 32],
    pub signing_key: [u8; 64],
    pub enable_nat: bool,
    /// Enable neural resonance module (Patent 1)
    pub enable_neural: bool,
    /// Neural resonance configuration
    pub neural_config: NeuralConfig,
    /// Client database for PSK-based authentication
    pub client_db: Option<Arc<ClientDatabase>>,
    /// Directory for mask storage (default: /var/lib/aivpn/masks)
    pub mask_dir: std::path::PathBuf,
    /// Session hard timeout in seconds (default: 7 days). `None` uses the default.
    pub session_timeout_secs: Option<u64>,
    /// Session idle timeout in seconds (default: 300). `None` uses the default.
    pub idle_timeout_secs: Option<u64>,
    /// Optional custom bootstrap masks embedded into signed descriptors.
    pub bootstrap_masks: Vec<MaskProfile>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:443".to_string(),
            per_ip_pps_limit: 1000,
            tun_name: "aivpn0".to_string(),
            tun_addr: "10.0.0.1".to_string(),
            tun_netmask: "255.255.255.0".to_string(),
            network_config: VpnNetworkConfig::default(),
            server_private_key: [0u8; 32],
            signing_key: [0u8; 64],
            enable_nat: true,
            enable_neural: true,
            neural_config: NeuralConfig::default(),
            client_db: None,
            mask_dir: std::path::PathBuf::from("/var/lib/aivpn/masks"),
            session_timeout_secs: None,
            idle_timeout_secs: None,
            bootstrap_masks: Vec::new(),
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
    /// Primary mask used for initial handshake parsing.
    primary_mask_id: parking_lot::Mutex<String>,
}

impl MaskCatalog {
    pub fn new() -> Self {
        Self {
            masks: DashMap::new(),
            compromised: DashMap::new(),
            primary_mask_id: parking_lot::Mutex::new(String::new()),
        }
    }

    /// Set the primary mask ID (first mask loaded from disk)
    pub fn set_primary_mask_id(&self, mask_id: String) {
        *self.primary_mask_id.lock() = mask_id;
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

    /// Remove a mask from live rotation without marking it as compromised.
    pub fn remove_mask(&self, mask_id: &str) {
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

    /// Get the primary packet layout for client->server traffic.
    /// Returns `(packet_mdh_len, handshake_mdh_len, eph_offset, eph_len)`.
    /// Normal packets use only the protocol header, while the initial
    /// handshake embeds `eph_pub` inside the MDH at `eph_offset`.
    pub fn packet_layout(&self) -> (usize, usize, usize, usize) {
        let fallback = (20usize, 52usize, 20usize, 32usize);
        let Some(mask) = self.primary_mask() else {
            return fallback;
        };

        packet_layout_for_mask(&mask)
    }

    /// Get the regular MDH bytes used for server->client packets.
    /// Uses HeaderSpec for dynamic per-packet generation when available (Issue #30 fix).
    pub fn packet_mdh_bytes(&self) -> Vec<u8> {
        self.primary_mask()
            .map(|mask| packet_mdh_bytes_for_mask(&mask))
            .unwrap_or_else(|| vec![0u8; 20])
    }

    pub fn primary_mask(&self) -> Option<MaskProfile> {
        let primary_id = self.primary_mask_id.lock().clone();
        self.masks.get(&primary_id)
            .map(|entry| entry.value().clone())
            .or_else(|| self.masks.iter().next().map(|entry| entry.value().clone()))
    }
}

fn packet_layout_for_mask(mask: &MaskProfile) -> (usize, usize, usize, usize) {
    let eph_offset = mask.eph_pub_offset as usize;
    let eph_len = mask.eph_pub_length as usize;
    let packet_mdh_len = mask.header_spec
        .as_ref()
        .map(|spec| spec.min_length())
        .unwrap_or_else(|| mask.header_template.len());
    let handshake_mdh_len = packet_mdh_len.max(eph_offset.saturating_add(eph_len));
    (packet_mdh_len, handshake_mdh_len, eph_offset, eph_len)
}

fn packet_mdh_bytes_for_mask(mask: &MaskProfile) -> Vec<u8> {
    if let Some(ref spec) = mask.header_spec {
        let mut rng = rand::thread_rng();
        spec.generate(&mut rng)
    } else {
        mask.header_template.clone()
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
    /// Per-IP handshake failure cooldown: (failure_count, last_failure_time)
    /// Prevents rapid session-creation loops when client retries with stale keys
    handshake_cooldowns: Arc<DashMap<IpAddr, (u32, Instant)>>,
    /// Neural Resonance Module (Patent 1) — periodic traffic validation
    neural_module: Arc<parking_lot::Mutex<NeuralResonanceModule>>,
    /// Mask catalog for automatic rotation (Patent 3)
    mask_catalog: Arc<MaskCatalog>,
    /// Metrics collector
    metrics: Arc<MetricsCollector>,
    /// Client database for PSK-based authentication
    client_db: Option<Arc<ClientDatabase>>,
    /// Recording manager for auto mask recording
    recording_manager: Option<Arc<RecordingManager>>,
    /// Mask store for auto-generated masks
    #[allow(dead_code)]
    mask_store: Option<Arc<MaskStore>>,
    /// Active bootstrap descriptors for previous/current/next epochs.
    bootstrap_descriptors: Vec<BootstrapDescriptor>,
}

const BOOTSTRAP_ROTATION_SECS: u64 = 24 * 3600;
const BOOTSTRAP_DESCRIPTOR_CANDIDATES: u8 = 4;

fn bootstrap_epoch(unix_secs: u64) -> u64 {
    unix_secs / BOOTSTRAP_ROTATION_SECS
}

pub fn derive_server_signing_key(server_private_key: &[u8; 32]) -> ed25519_dalek::SigningKey {
    let seed = blake3::derive_key("aivpn-ed25519-signing-v1", server_private_key);
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

fn sign_bootstrap_descriptor(
    mut descriptor: BootstrapDescriptor,
    signing_key: &ed25519_dalek::SigningKey,
) -> BootstrapDescriptor {
    use ed25519_dalek::Signer;
    descriptor.signature = signing_key.sign(&descriptor.signing_bytes()).to_bytes();
    descriptor
}

fn build_bootstrap_descriptor(
    server_seed: &[u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
    epoch: u64,
    bootstrap_masks: &[MaskProfile],
) -> BootstrapDescriptor {
    let mut hasher = blake3::Hasher::new_keyed(server_seed);
    hasher.update(&epoch.to_le_bytes());
    let hash = hasher.finalize();
    let mut kdf_salt = [0u8; 32];
    kdf_salt.copy_from_slice(&hash.as_bytes()[..32]);
    let created_at = epoch * BOOTSTRAP_ROTATION_SECS;
    let expires_at = created_at + (2 * BOOTSTRAP_ROTATION_SECS);
    let (base_mask_ids, embedded_masks) = if bootstrap_masks.is_empty() {
        (
            aivpn_common::mask::preset_masks::all()
                .into_iter()
                .map(|mask| mask.mask_id)
                .collect(),
            Vec::new(),
        )
    } else {
        (Vec::new(), bootstrap_masks.to_vec())
    };

    sign_bootstrap_descriptor(
        BootstrapDescriptor {
            descriptor_id: format!("epoch-{}", epoch),
            version: 1,
            created_at,
            expires_at,
            base_mask_ids,
            embedded_masks,
            candidate_count: BOOTSTRAP_DESCRIPTOR_CANDIDATES,
            kdf_salt,
            signature: [0u8; 64],
        },
        signing_key,
    )
}

pub fn build_bootstrap_descriptors(
    server_seed: &[u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
    bootstrap_masks: &[MaskProfile],
) -> Vec<BootstrapDescriptor> {
    let epoch = bootstrap_epoch(current_unix_secs());
    [epoch.saturating_sub(1), epoch, epoch.saturating_add(1)]
        .into_iter()
        .map(|value| build_bootstrap_descriptor(server_seed, signing_key, value, bootstrap_masks))
        .collect()
}

impl Gateway {
    fn can_start_recording(&self, client_id: Option<&str>) -> bool {
        let Some(client_id) = client_id else {
            return false;
        };

        if client_id == "admin" {
            return true;
        }

        self.client_db
            .as_ref()
            .and_then(|db| db.find_by_id(client_id))
            .map(|client| client.name.starts_with("recording-admin"))
            .unwrap_or(false)
    }

    async fn handle_recording_outcome(
        socket: &Arc<UdpSocket>,
        sessions: &Arc<SessionManager>,
        store: &Arc<MaskStore>,
        mdh: &[u8],
        outcome: RecordingStopOutcome,
        notify_session: Option<Arc<parking_lot::Mutex<Session>>>,
    ) {
        match outcome {
            RecordingStopOutcome::Completed(completed) => {
                if let Some(ref session) = notify_session {
                    let ack = ControlPayload::RecordingAck {
                        session_id: completed.session_id,
                        status: "analyzing".into(),
                    };
                    if let Err(e) = Self::send_control_message_via(socket.as_ref(), mdh, &ack, session).await {
                        warn!("Failed to send RecordingAck: {}", e);
                    }
                }

                info!(
                    "Recording stopped for '{}' ({} packets, {}s), analyzing...",
                    completed.service, completed.total_packets, completed.duration_secs
                );

                let socket = socket.clone();
                let sessions = sessions.clone();
                let store = store.clone();
                let mdh = mdh.to_vec();
                tokio::spawn(async move {
                    match generate_and_store_mask(&completed.service, &completed.packets, &store).await {
                        Ok(mask_id) => {
                            info!(
                                "✅ Mask generated: '{}' for service '{}' by {}",
                                mask_id, completed.service, completed.admin_key_id
                            );
                            if let Some(target_session) = sessions.get_session(&completed.session_id) {
                                let confidence = store
                                    .get_mask(&mask_id)
                                    .map(|entry| entry.stats.confidence)
                                    .unwrap_or(0.0);
                                let payload = ControlPayload::RecordingComplete {
                                    service: completed.service.clone(),
                                    mask_id,
                                    confidence,
                                };
                                if let Err(e) = Self::send_control_message_via(socket.as_ref(), &mdh, &payload, &target_session).await {
                                    warn!("Failed to send RecordingComplete: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Mask generation failed for '{}': {}", completed.service, e);
                            if let Some(target_session) = sessions.get_session(&completed.session_id) {
                                let payload = ControlPayload::RecordingFailed {
                                    reason: e.to_string(),
                                };
                                if let Err(send_err) = Self::send_control_message_via(socket.as_ref(), &mdh, &payload, &target_session).await {
                                    warn!("Failed to send RecordingFailed: {}", send_err);
                                }
                            }
                        }
                    }
                });
            }
            RecordingStopOutcome::Incomplete(incomplete) => {
                let reason = match incomplete.reason {
                    RecordingStopReason::IdleTimeout => "Recording stopped after idle timeout before enough traffic was captured",
                    RecordingStopReason::SessionEnded => "Recording ended with the session before enough traffic was captured",
                    _ => "Too few packets or too short duration",
                };
                if let Some(ref session) = notify_session {
                    let payload = ControlPayload::RecordingFailed {
                        reason: reason.into(),
                    };
                    if let Err(e) = Self::send_control_message_via(socket.as_ref(), mdh, &payload, session).await {
                        warn!("Failed to send RecordingFailed: {}", e);
                    }
                }
                warn!(
                    "Recording for '{}' ended without mask generation: {} packets, {}s ({:?})",
                    incomplete.service, incomplete.total_packets, incomplete.duration_secs, incomplete.reason
                );
            }
            RecordingStopOutcome::NotFound => {}
        }
    }

    pub fn new(config: GatewayConfig) -> Result<Self> {
        // Create server keypair (use config key if provided, otherwise generate ephemeral)
        let server_keys = if config.server_private_key != [0u8; 32] {
            crypto::KeyPair::from_private_key(config.server_private_key)
        } else {
            crypto::KeyPair::generate()
        };
        
        // Create Ed25519 signing key
        let signing_key = derive_server_signing_key(&config.server_private_key);
        let bootstrap_descriptors = build_bootstrap_descriptors(&config.server_private_key, &signing_key, &config.bootstrap_masks);
        
        // Initialize mask catalog (empty — populated from disk only)
        let mask_catalog = Arc::new(MaskCatalog::new());
        
        // Initialize mask store — loads masks from disk into catalog
        let mask_store = Arc::new(MaskStore::new(
            mask_catalog.clone(),
            config.mask_dir.clone(),
        ));
        
        // Runtime primary mask is selected from the masks loaded on disk.
        // Bootstrap compatibility is handled separately using built-in presets.
        let primary_id = if let Some(first) = mask_catalog.masks.iter().next() {
            let id = first.key().clone();
            id
        } else {
            String::new()
        };
        if !primary_id.is_empty() {
            info!("Primary mask set to '{}' (loaded from disk)", primary_id);
            mask_catalog.set_primary_mask_id(primary_id);
        } else {
            warn!("No masks found in {:?} — server will not accept connections until masks are recorded", config.mask_dir);
        }
        
        // Get default mask from catalog (required — at least one mask must exist on disk)
        let default_mask = mask_catalog.primary_mask()
            .ok_or_else(|| Error::Session(
                format!("No masks found in {:?} — place mask JSON files there before starting the server", config.mask_dir)
            ))?;
        
        let session_manager = Arc::new(SessionManager::with_timeouts(
            server_keys,
            signing_key,
            default_mask,
            config.session_timeout_secs,
            config.idle_timeout_secs,
        ));
        
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
        
        let recording_manager = Arc::new(RecordingManager::new(mask_store.clone()));
        info!("Auto Mask Recording system initialized ({} masks loaded from disk)", mask_catalog.available_count());

        Ok(Self {
            config: config.clone(),
            session_manager,
            udp_socket: None,
            nat_forwarder: None,
            tun_write_tx: None,
            rate_limits: Arc::new(DashMap::new()),
            handshake_cooldowns: Arc::new(DashMap::new()),
            neural_module: Arc::new(parking_lot::Mutex::new(neural)),
            mask_catalog,
            metrics: Arc::new(MetricsCollector::new()),
            client_db: config.client_db,
            recording_manager: Some(recording_manager),
            mask_store: Some(mask_store),
            bootstrap_descriptors,
        })
    }

    async fn send_bootstrap_descriptors(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
    ) -> Result<()> {
        for descriptor in &self.bootstrap_descriptors {
            let payload = ControlPayload::BootstrapDescriptorUpdate {
                descriptor_data: rmp_serde::to_vec(descriptor)
                    .map_err(|e| Error::Session(format!("Failed to serialize bootstrap descriptor: {}", e)))?,
            };
            self.send_control_message(&payload, session).await?;
        }
        Ok(())
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
                self.config.network_config,
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
            let socket = self.udp_socket.as_ref().unwrap().clone();
            
            tokio::spawn(async move {
                Self::resonance_check_loop(neural, sessions, catalog, metrics, check_interval, socket).await;
            });
            info!("Neural resonance check loop spawned (interval: {}s)", check_interval);
        }
        
        // Spawn TUN → Client read loop (reads packets from TUN, routes back to clients)
        // Also set up channel-based TUN writer for upload path (avoids Mutex contention)
        if let Some(ref nat) = self.nat_forwarder {
            if let Some(tun_reader) = nat.take_reader().await {
                let sessions = self.session_manager.clone();
                let socket = self.udp_socket.as_ref().unwrap().clone();
                let mask = self.mask_catalog.masks.iter().next()
                    .map(|e| e.value().clone())
                    .expect("at least one mask must be loaded");
                let server_vpn_ip = self.config.network_config.server_vpn_ip;
                let recorder = self.recording_manager.clone();
                
                // Channel for writing packets to TUN device (upload + ICMP replies)
                let (tun_tx, tun_rx) = mpsc::channel::<Vec<u8>>(4096);
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
                
                let client_db = self.client_db.clone();
                tokio::spawn(async move {
                    Self::tun_read_loop(tun_reader, tun_tx, sessions, socket, mask, server_vpn_ip, recorder, client_db).await;
                });
                info!("TUN read loop spawned");
            }
        }
        
        // Spawn periodic session cleanup task (remove expired/idle sessions and stop recordings)
        {
            let sessions = self.session_manager.clone();
            let recorder = self.recording_manager.clone();
            let socket = self.udp_socket.as_ref().unwrap().clone();
            let mdh = self.mask_catalog.packet_mdh_bytes();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    if let Some(ref rec) = recorder {
                        let store = rec.store();
                        for outcome in rec.take_ready_or_stale(aivpn_common::recording::RECORDING_IDLE_TIMEOUT_SECS) {
                            let notify_session = match &outcome {
                                RecordingStopOutcome::Completed(completed) => sessions.get_session(&completed.session_id),
                                RecordingStopOutcome::Incomplete(incomplete) => sessions.get_session(&incomplete.session_id),
                                RecordingStopOutcome::NotFound => None,
                            };
                            Self::handle_recording_outcome(&socket, &sessions, &store, &mdh, outcome, notify_session).await;
                        }
                    }

                    let removed = sessions.cleanup_expired();
                    // Stop active recordings for removed sessions
                    if let Some(ref rec) = recorder {
                        let store = rec.store();
                        for session_id in removed {
                            let outcome = rec.stop_for_session_end(session_id);
                            Self::handle_recording_outcome(&socket, &sessions, &store, &mdh, outcome, None).await;
                        }
                    }
                }
            });
            info!("Session cleanup / recording auto-finish task spawned (5s interval)");
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
        socket: Arc<UdpSocket>,
    ) {
        let interval = Duration::from_secs(check_interval_secs);
        
        loop {
            tokio::time::sleep(interval).await;
            
            // Collect session IDs and their mask IDs
            let session_checks: Vec<([u8; 16], String)> = sessions.iter_sessions()
                .filter_map(|entry| {
                    let sess = entry.value().lock();
                    let mask_id = sess.mask.as_ref().map(|m| m.mask_id.clone())
                        .unwrap_or_else(|| "unknown".to_string());
                    Some((sess.session_id, mask_id))
                })
                .collect();
            
            if session_checks.is_empty() {
                continue;
            }
            
            // Collect mask update packets to send AFTER releasing the neural lock
            // (parking_lot::MutexGuard is !Send, cannot hold across .await)
            let mut pending_sends: Vec<(Vec<u8>, std::net::SocketAddr, [u8; 16], MaskProfile)> = Vec::new();
            
            {
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
                                        
                                        if let Some(session) = sessions.get_session(session_id) {
                                            let client_addr = session.lock().client_addr;
                                            match sessions.build_mask_update_packet(&session, &new_mask) {
                                                Ok(packet) => {
                                                    pending_sends.push((packet, client_addr, *session_id, new_mask.clone()));
                                                }
                                                Err(e) => {
                                                    warn!("Failed to build MaskUpdate packet: {}", e);
                                                }
                                            }
                                        }
                                        
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
                            if let Some(session) = sessions.get_session(session_id) {
                                let client_addr = session.lock().client_addr;
                                if let Ok(packet) = sessions.build_mask_update_packet(&session, &new_mask) {
                                    pending_sends.push((packet, client_addr, *session_id, new_mask.clone()));
                                }
                            }
                            metrics.record_mask_rotation();
                        }
                    }
                }
            } // neural_guard dropped here
            
            // Send collected MaskUpdate packets (async, safe now)
            for (packet, client_addr, session_id, new_mask) in pending_sends {
                if let Err(e) = socket.send_to(&packet, client_addr).await {
                    warn!("Failed to send MaskUpdate to {}: {}", client_addr, e);
                } else {
                    sessions.update_session_mask(&session_id, new_mask);
                    info!("MaskUpdate control message sent to {}", client_addr);
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
        server_vpn_ip: Ipv4Addr,
        recorder: Option<Arc<RecordingManager>>,
        client_db: Option<Arc<ClientDatabase>>,
    ) {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        let server_ip = server_vpn_ip;
        
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
                    let (session_id, client_addr, downlink_iat_ms, tag, mdh, ciphertext) = {
                        let mut sess = session.lock();
                        // Commit deferred mask switch if grace period has elapsed
                        sess.commit_pending_mask();
                        let session_id = sess.session_id;
                        let client_addr = sess.client_addr;
                        let seq_num = sess.next_seq() as u16;
                        let (nonce, counter) = sess.next_send_nonce();
                        let key = sess.keys.session_key.clone();
                        let tag_secret = sess.keys.tag_secret;
                        let downlink_iat_ms = sess.last_server_send.elapsed().as_secs_f64() * 1000.0;
                        sess.last_server_send = Instant::now();
                        // Use the session's own mask for MDH so the client can
                        // decode with the mask it currently expects (bootstrap
                        // or runtime after MaskUpdate is processed).
                        let session_mdh = sess.mask.as_ref()
                            .map(packet_mdh_bytes_for_mask)
                            .unwrap_or_else(|| mask.header_template.clone());
                        // Pre-accumulate downlink bytes estimate (IP packet + overhead)
                        // This avoids a second lock after send_to
                        let estimated_out = (n + 64) as u64; // packet + AIVPN overhead
                        sess.pending_bytes_out = sess.pending_bytes_out.saturating_add(estimated_out);
                        // Flush downlink-only traffic to client_db when threshold reached
                        let flush_out = if sess.pending_bytes_out >= 64 * 1024 {
                            let bytes = sess.pending_bytes_out;
                            let cid = sess.client_id.clone();
                            sess.pending_bytes_out = 0;
                            cid.map(|c| (c, bytes))
                        } else {
                            None
                        };
                        drop(sess); // Release lock BEFORE expensive encryption
                        // Flush outside lock
                        if let (Some(ref db), Some((cid, bytes))) = (&client_db, flush_out) {
                            db.record_traffic(&cid, 0, bytes);
                        }
                        
                        // Build inner payload: Data type + IP packet
                        let inner_header = InnerHeader {
                            inner_type: InnerType::Data,
                            seq_num,
                        };
                        let mut inner_payload = inner_header.encode().to_vec();
                        inner_payload.extend_from_slice(packet);
                        
                        // Build MDH using session mask (not global runtime mask)
                        let mdh = session_mdh;
                        
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
                        
                        (session_id, client_addr, downlink_iat_ms, tag, mdh, ciphertext)
                    };
                    
                    // Assemble: TAG | MDH | ciphertext
                    let mut aivpn_packet = Vec::with_capacity(TAG_SIZE + mdh.len() + ciphertext.len());
                    aivpn_packet.extend_from_slice(&tag);
                    aivpn_packet.extend_from_slice(&mdh);
                    aivpn_packet.extend_from_slice(&ciphertext);
                    
                    // Send to client
                    if let Err(e) = socket.send_to(&aivpn_packet, client_addr).await {
                        debug!("TUN: send failed: {}", e);
                    } else {
                        // bytes_out already tracked inside the earlier lock scope
                        if let Some(ref recorder) = recorder {
                            if recorder.is_recording(&session_id) {
                                let meta = aivpn_common::recording::PacketMetadata {
                                    direction: aivpn_common::recording::Direction::Downlink,
                                    size: aivpn_packet.len() as u16,
                                    iat_ms: downlink_iat_ms,
                                    entropy: Self::compute_entropy(&ciphertext) as f32,
                                    header_prefix: aivpn_packet[TAG_SIZE..TAG_SIZE + 16.min(aivpn_packet.len() - TAG_SIZE)].to_vec(),
                                    timestamp_ns: std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_nanos() as u64,
                                };
                                recorder.record_packet(session_id, meta);
                            }
                        }
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
        
        // Default layout from runtime primary mask (used for handshake fallback).
        let (catalog_mdh_len, catalog_hs_mdh_len, _eph_offset, _eph_len) = self.mask_catalog.packet_layout();
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
            // NOTE: We intentionally do NOT drop packets from the same public IP
            // on a different port. Multiple clients behind the same NAT must be
            // able to handshake independently (different PSKs → different sessions).

            // No session found — try handshake
            // Rate-limit failed handshake attempts to prevent rapid session-creation loops.
            // After mask rotation or session timeout, stale clients may flood the server
            // with packets that consistently fail tag validation (issue #21).
            // TEMPORARILY DISABLED cooldown for debugging - client cannot handshake
            // {
            //     let ip = client_addr.ip();
            //     if let Some(entry) = self.handshake_cooldowns.get(&ip) {
            //         let (fail_count, last_fail) = *entry;
            //         // Increased cooldown: start with 2s, max 30s to avoid blocking legitimate clients
            //         let cooldown = Duration::from_millis(
            //             (2000 * (1 << fail_count.min(3))) as u64
            //         );
            //         if last_fail.elapsed() < cooldown {
            //             debug!("Handshake cooldown active for {}: fail_count={}, elapsed={:?}, cooldown={:?}",
            //                 hash_addr(&client_addr), fail_count, last_fail.elapsed(), cooldown);
            //             return Err(Error::InvalidPacket("Handshake cooldown active"));
            //         } else {
            //             debug!("Handshake cooldown expired for {}: elapsed={:?} >= cooldown={:?}",
            //                 hash_addr(&client_addr), last_fail.elapsed(), cooldown);
            //         }
            //     }
            // }

            // Try to establish a new session using one of the built-in bootstrap masks.
            // Runtime masks can be server-generated, but bootstrap must remain compatible
            // with clients that only know the shipped presets.
            // If client_db is configured, iterate registered clients and try
            // DH + PSK to find one whose derived tags match.
            // Falls back to no-PSK for backward compatibility.
            let builtin_bootstrap_masks = aivpn_common::mask::preset_masks::all();
            let (session, matched_client_id, bootstrap_mask) = if let Some(ref db) = self.client_db {
                let clients = db.list_clients();
                let mut found = None;
                'bootstrap: for client_cfg in &clients {
                    if !client_cfg.enabled {
                        continue;
                    }

                    let psk = client_cfg.psk;
                    let candidate_masks = self.bootstrap_descriptors.iter()
                        .flat_map(|descriptor| derive_bootstrap_candidates(descriptor, Some(&psk)))
                        .chain(builtin_bootstrap_masks.clone().into_iter())
                        .collect::<Vec<_>>();

                    for bootstrap_mask in candidate_masks {
                        let (_, candidate_handshake_mdh_len, candidate_eph_offset, candidate_eph_len) =
                            packet_layout_for_mask(&bootstrap_mask);
                        if packet_data.len() < TAG_SIZE + candidate_handshake_mdh_len {
                            continue;
                        }
                        let eph_start = TAG_SIZE + candidate_eph_offset;
                        if packet_data.len() < eph_start + candidate_eph_len {
                            continue;
                        }

                        let mut eph_pub = [0u8; 32];
                        eph_pub.copy_from_slice(&packet_data[eph_start..eph_start + candidate_eph_len]);
                        crypto::obfuscate_eph_pub(&mut eph_pub, &self.session_manager.server_public_key());

                        match self.session_manager.create_session(
                            client_addr,
                            eph_pub,
                            Some(psk),
                            Some(client_cfg.vpn_ip),
                        ) {
                            Ok(sess) => {
                                let validation = sess.lock().validate_tag(&tag);
                                if validation.is_some() {
                                    debug!(
                                        "Tag validation SUCCESS for client {} via bootstrap mask {}",
                                        client_cfg.id,
                                        bootstrap_mask.mask_id
                                    );
                                    found = Some((sess, Some(client_cfg.id.clone()), bootstrap_mask));
                                    break 'bootstrap;
                                }
                                let sid = sess.lock().session_id;
                                self.session_manager.rollback_failed_session(&sid);
                            }
                            Err(e) => {
                                debug!("create_session failed: {}", e);
                                continue;
                            }
                        }
                    }
                }
                match found {
                    Some(f) => f,
                    None => {
                        // Track failed handshake for cooldown
                        let ip = client_addr.ip();
                        let fail_count = self.handshake_cooldowns
                            .get(&ip)
                            .map(|e| e.0)
                            .unwrap_or(0);
                        self.handshake_cooldowns.insert(ip, (fail_count + 1, Instant::now()));
                        warn!(
                            "Handshake failed for {} (attempt #{}) — tag mismatch for all {} registered clients",
                            hash_addr(&client_addr),
                            fail_count + 1,
                            clients.len()
                        );
                        return Err(Error::InvalidPacket("No registered client matches this handshake"));
                    }
                }
            } else {
                // No client DB — legacy mode without PSK
                let mut found = None;
                let candidate_masks = self.bootstrap_descriptors.iter()
                    .flat_map(|descriptor| derive_bootstrap_candidates(descriptor, None))
                    .chain(builtin_bootstrap_masks.clone().into_iter())
                    .collect::<Vec<_>>();
                for bootstrap_mask in candidate_masks {
                    let (_, candidate_handshake_mdh_len, candidate_eph_offset, candidate_eph_len) =
                        packet_layout_for_mask(&bootstrap_mask);
                    if packet_data.len() < TAG_SIZE + candidate_handshake_mdh_len {
                        continue;
                    }
                    let eph_start = TAG_SIZE + candidate_eph_offset;
                    if packet_data.len() < eph_start + candidate_eph_len {
                        continue;
                    }

                    let mut eph_pub = [0u8; 32];
                    eph_pub.copy_from_slice(&packet_data[eph_start..eph_start + candidate_eph_len]);
                    crypto::obfuscate_eph_pub(&mut eph_pub, &self.session_manager.server_public_key());

                    let sess = self.session_manager.create_session(
                        client_addr,
                        eph_pub,
                        None,
                        None,
                    )?;
                    let validation = sess.lock().validate_tag(&tag);
                    if validation.is_some() {
                        found = Some((sess, None, bootstrap_mask));
                        break;
                    }
                    let sid = sess.lock().session_id;
                    self.session_manager.rollback_failed_session(&sid);
                }

                found.ok_or_else(|| Error::InvalidPacket("No bootstrap mask matched this handshake"))?
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
            // Clean up old sessions for the SAME CLIENT (by VPN IP), not
            // all sessions from this source IP — different clients behind
            // the same NAT must coexist.
            {
                let (session_id, vpn_ip) = {
                    let sess_lock = session.lock();
                    (sess_lock.session_id, sess_lock.vpn_ip)
                };
                if let Some(vpn_ip) = vpn_ip {
                    let removed = self.session_manager.cleanup_old_sessions_for_vpn_ip(
                        &vpn_ip,
                        &session_id,
                    );
                    // Stop active recordings for removed stale sessions
                    if let Some(ref recorder) = self.recording_manager {
                        let socket = self.udp_socket.as_ref().unwrap().clone();
                        let store = recorder.store();
                        let mdh = self.mask_catalog.packet_mdh_bytes();
                        for sid in removed {
                            let outcome = recorder.stop_for_session_end(sid);
                            Self::handle_recording_outcome(&socket, &self.session_manager, &store, &mdh, outcome, None).await;
                        }
                    }
                }
            }
            
            // Successful handshake — clear cooldown for this IP
            self.handshake_cooldowns.remove(&client_addr.ip());

            {
                let mut sess = session.lock();
                sess.mask = Some(bootstrap_mask.clone());
            }

            // Record handshake in client DB
            if let (Some(ref db), Some(ref cid)) = (&self.client_db, &matched_client_id) {
                db.record_handshake(cid);
                // Store client_id in session for traffic accounting
                session.lock().client_id = Some(cid.clone());
                debug!("Client '{}' authenticated via PSK", cid);
            }
            
            self.send_server_hello(&session, client_addr).await?;
            self.send_bootstrap_descriptors(&session).await?;

            if let Some(runtime_mask) = self.mask_catalog.primary_mask() {
                if runtime_mask.mask_id != bootstrap_mask.mask_id {
                    match self.session_manager.build_mask_update_packet(&session, &runtime_mask) {
                        Ok(packet) => {
                            self.udp_socket.as_ref().unwrap().send_to(&packet, client_addr).await?;
                            // NOTE: Do NOT call update_session_mask here.
                            // The client still sends packets with bootstrap mask layout
                            // until it processes MaskUpdate. Keep sess.mask = bootstrap
                            // so per-session decryption uses bootstrap layout, with
                            // catalog (runtime) layout as fallback for transition.
                        }
                        Err(e) => {
                            warn!("Failed to send initial runtime MaskUpdate: {}", e);
                        }
                    }
                }
            }
            
            // NOTE: PFS ratchet is deferred until AFTER decrypting the init packet,
            // which was encrypted with pre-ratchet keys.
            
            is_new_session = true;
            debug!("New session from {} (ServerHello sent)", hash_addr(&client_addr));
            (session, counter, is_ratcheted)
        };
        
        // Parse packet — pad_len is inside encrypted area (CRIT-5 fix).
        // Use the session's own mask layout for decryption. This is critical
        // because the client may still be using its bootstrap mask before
        // receiving and applying a MaskUpdate from the server.
        // We try both the session mask layout AND the catalog (runtime) layout
        // to handle the transition window.
        let (session_mdh_len, session_hs_mdh_len) = {
            let sess = session.lock();
            if let Some(ref mask) = sess.mask {
                let (p, h, _, _) = packet_layout_for_mask(mask);
                (p, h)
            } else {
                (catalog_mdh_len, catalog_hs_mdh_len)
            }
        };
        let packet_mdh_len = session_mdh_len;
        let handshake_mdh_len = session_hs_mdh_len;
        // Android retransmits the initial handshake packet with the client
        // eph_pub still embedded inside the MDH. Once a session already exists,
        // those retries validate against the existing tag window, so the
        // ciphertext still starts immediately after the full MDH.
        let is_pre_ratchet_retry = !is_new_session && !is_ratcheted_tag && {
            let sess = session.lock();
            !sess.is_ratcheted && packet_data.len() >= TAG_SIZE + handshake_mdh_len + 16
        };
        let mut payload_offsets: Vec<usize> = if is_new_session {
            vec![TAG_SIZE + handshake_mdh_len]
        } else if is_pre_ratchet_retry && handshake_mdh_len != packet_mdh_len {
            vec![TAG_SIZE + packet_mdh_len, TAG_SIZE + handshake_mdh_len]
        } else {
            vec![TAG_SIZE + packet_mdh_len]
        };
        // During mask transition (bootstrap → runtime), also try the catalog
        // (runtime) layout in case the client already applied MaskUpdate.
        if catalog_mdh_len != session_mdh_len {
            let catalog_offset = TAG_SIZE + catalog_mdh_len;
            if !payload_offsets.contains(&catalog_offset) {
                payload_offsets.push(catalog_offset);
            }
        }

        let (payload_offset, padded_plaintext) = {
            let sess = session.lock();
            let nonce = self.compute_nonce(counter);
            // For new sessions, always use initial keys for decryption since the
            // client hasn't received ServerHello yet and is still sending with
            // initial keys. Only use ratcheted keys when the client proves it
            // has switched by sending a ratcheted tag on an existing session.
            let key = if is_new_session {
                &sess.keys.session_key
            } else if is_ratcheted_tag {
                &sess.ratcheted_keys.as_ref()
                    .ok_or(Error::InvalidPacket("Ratcheted keys missing"))?
                    .session_key
            } else {
                &sess.keys.session_key
            };

            let mut decrypted = None;
            let mut last_error = None;
            for payload_offset in payload_offsets {
                if packet_data.len() <= payload_offset {
                    continue;
                }
                let encrypted_payload = &packet_data[payload_offset..];
                match decrypt_payload(key, &nonce, encrypted_payload) {
                    Ok(padded_plaintext) => {
                        decrypted = Some((payload_offset, padded_plaintext));
                        break;
                    }
                    Err(err) => last_error = Some(err),
                }
            }

            match decrypted {
                Some(result) => result,
                None => return Err(last_error.unwrap_or_else(|| Error::InvalidPacket("Invalid length"))),
            }
        };
        let encrypted_payload = &packet_data[payload_offset..];
        
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
        let mut client_db_flush: Option<(String, u64, u64)> = None;
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
            if sess.pending_bytes_in >= 16 * 1024 || sess.pending_bytes_out >= 16 * 1024 {
                if let Some(cid) = sess.client_id.clone() {
                    client_db_flush = Some((cid, sess.pending_bytes_in, sess.pending_bytes_out));
                }
                sess.pending_bytes_in = 0;
                sess.pending_bytes_out = 0;
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
            // Compute real IAT from session's last_seen timestamp
            let iat_ms = {
                let sess = session.lock();
                let elapsed = sess.last_seen.elapsed();
                elapsed.as_secs_f64() * 1000.0
            };
            // Neural model update is expensive under lock. Sampling every 16th packet
            // preserves trends while reducing lock contention in the receive hot path.
            if counter & 0x0f == 0 {
                self.neural_module.lock().record_traffic(
                    session_id, packet_size, iat_ms, entropy,
                );
            }
            self.metrics.record_packet_received(packet_data.len());
        }

        // Record uplink packet metadata for auto mask recording
        if let Some(ref recorder) = self.recording_manager {
            let session_id = session.lock().session_id;
            if recorder.is_recording(&session_id) {
                let iat_ms = {
                    let sess = session.lock();
                    sess.last_seen.elapsed().as_secs_f64() * 1000.0
                };
                let meta = aivpn_common::recording::PacketMetadata {
                    direction: aivpn_common::recording::Direction::Uplink,
                    size: packet_data.len() as u16,
                    iat_ms,
                    entropy: Self::compute_entropy(encrypted_payload) as f32,
                    header_prefix: packet_data[TAG_SIZE..TAG_SIZE + 16.min(packet_data.len() - TAG_SIZE)].to_vec(),
                    timestamp_ns: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as u64,
                };
                recorder.record_packet(session_id, meta);
            }
        }
        
        // Record traffic in client DB in batches (see pending_bytes_in/out above).
        if let (Some(ref db), Some((cid, bytes_in, bytes_out))) = (&self.client_db, client_db_flush) {
            db.record_traffic(&cid, bytes_in, bytes_out);
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
            ControlPayload::KeyRotate { new_eph_pub: _ } => {
                info!("Key rotation request from {}", hash_addr(&client_addr));
                // TODO: Implement key rotation
            }
            ControlPayload::MaskUpdate { .. } => {
                warn!("Unexpected MASK_UPDATE from client");
            }
            ControlPayload::Keepalive => {
                debug!("Keepalive from {}", hash_addr(&client_addr));
                if !session.lock().is_ratcheted {
                    // The client is still retrying the initial handshake. If the
                    // first ServerHello was lost, replying with a normal pre-ratchet
                    // ControlAck leaves the client stuck forever.
                    self.send_server_hello(session, client_addr).await?;
                    return Ok(());
                }
                // Send ACK
                let ack = ControlPayload::ControlAck {
                    ack_seq: 0,
                    ack_for_subtype: ControlSubtype::Keepalive as u8,
                };
                self.send_control_message(&ack, session).await?;
            }
            ControlPayload::TelemetryRequest { metric_flags: _ } => {
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
                // Close session and stop active recording if any
                let session_id = session.lock().session_id;
                self.session_manager.remove_session(&session_id);
                if let Some(ref recorder) = self.recording_manager {
                    let socket = self.udp_socket.as_ref().unwrap().clone();
                    let store = recorder.store();
                    let mdh = self.mask_catalog.packet_mdh_bytes();
                    let outcome = recorder.stop_for_session_end(session_id);
                    Self::handle_recording_outcome(&socket, &self.session_manager, &store, &mdh, outcome, None).await;
                }
            }
            ControlPayload::ControlAck { .. } => {
                // ACK received, nothing to do
            }
            ControlPayload::ServerHello { .. } => {
                warn!("Unexpected ServerHello from client {}", hash_addr(&client_addr));
            }
            ControlPayload::RecordingStart { service } => {
                // Only allow from admin sessions (check client_id)
                let admin_key_id = {
                    let sess = session.lock();
                    sess.client_id.clone()
                };
                if !self.can_start_recording(admin_key_id.as_deref()) {
                    warn!("Recording rejected: unauthenticated client {}", hash_addr(&client_addr));
                    let failed = ControlPayload::RecordingFailed {
                        reason: "Recording requires a recording-admin key".into(),
                    };
                    self.send_control_message(&failed, session).await?;
                    return Ok(());
                }
                if let Some(ref recorder) = self.recording_manager {
                    let session_id = session.lock().session_id;
                    recorder.start(session_id, service.clone(), admin_key_id.unwrap_or_else(|| "admin".into()));
                    let ack = ControlPayload::RecordingAck {
                        session_id,
                        status: "started".into(),
                    };
                    self.send_control_message(&ack, session).await?;
                    info!("Recording started for '{}' from {}", service, hash_addr(&client_addr));
                }
            }
            ControlPayload::RecordingStop { session_id: rec_session_id } => {
                if let Some(ref recorder) = self.recording_manager {
                    let owner_session_id = session.lock().session_id;
                    if rec_session_id != owner_session_id {
                        let failed = ControlPayload::RecordingFailed {
                            reason: "Recording session does not belong to this client".into(),
                        };
                        self.send_control_message(&failed, session).await?;
                        return Ok(());
                    }

                    let socket = self.udp_socket.as_ref().unwrap().clone();
                    let store = recorder.store();
                    let mdh = self.mask_catalog.packet_mdh_bytes();
                    let outcome = recorder.stop(owner_session_id);
                    Self::handle_recording_outcome(&socket, &self.session_manager, &store, &mdh, outcome, Some(session.clone())).await;
                }
            }
            ControlPayload::RecordingStatusRequest => {
                let client_id = {
                    let sess = session.lock();
                    sess.client_id.clone()
                };
                let can_record = self.can_start_recording(client_id.as_deref());
                let active_service = self.recording_manager
                    .as_ref()
                    .and_then(|recorder| recorder.status(&session.lock().session_id))
                    .map(|status| status.service);
                let response = ControlPayload::RecordingStatus {
                    can_record,
                    active_service,
                };
                self.send_control_message(&response, session).await?;
            }
            ControlPayload::RecordingAck { .. } => {
                // Client-side only, ignore on server
            }
            ControlPayload::RecordingComplete { .. } => {
                // Client-side only, ignore on server
            }
            ControlPayload::RecordingFailed { .. } => {
                // Client-side only, ignore on server
            }
            ControlPayload::RecordingStatus { .. } => {
                // Client-side only, ignore on server
            }
            ControlPayload::BootstrapDescriptorUpdate { .. } => {
                // Client-side only, ignore on server
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
        let mdh = {
            let mut sess = session.lock();
            sess.commit_pending_mask();
            sess.mask
                .as_ref()
                .map(packet_mdh_bytes_for_mask)
                .unwrap_or_else(|| self.mask_catalog.packet_mdh_bytes())
        };
        Self::send_control_message_via(
            socket,
            &mdh,
            payload,
            session,
        ).await
    }

    async fn send_control_message_via(
        socket: &UdpSocket,
        mdh: &[u8],
        payload: &ControlPayload,
        session: &Arc<parking_lot::Mutex<Session>>,
    ) -> Result<()> {
        let encoded = payload.encode()?;
        let (mut inner_payload, nonce, counter, keys, client_addr) = {
            let mut sess = session.lock();
            let inner_header = InnerHeader {
                inner_type: InnerType::Control,
                seq_num: sess.next_seq() as u16,
            };
            let inner_payload = inner_header.encode().to_vec();
            let (nonce, counter) = sess.next_send_nonce();
            let keys = sess.keys.clone();
            let client_addr = sess.client_addr;
            (inner_payload, nonce, counter, keys, client_addr)
        };
        inner_payload.extend_from_slice(&encoded);
        let pad_len = 16u16;
        let mut padded = Vec::with_capacity(2 + inner_payload.len() + pad_len as usize);
        padded.extend_from_slice(&pad_len.to_le_bytes());
        padded.extend_from_slice(&inner_payload);
        {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            for _ in 0..pad_len {
                padded.push(rng.gen::<u8>());
            }
        }
        let ciphertext = encrypt_payload(&keys.session_key, &nonce, &padded)?;
        let time_window = crypto::compute_time_window(
            crypto::current_timestamp_ms(),
            aivpn_common::crypto::DEFAULT_WINDOW_MS,
        );
        let tag = crypto::generate_resonance_tag(&keys.tag_secret, counter, time_window);
        let mut packet = Vec::with_capacity(TAG_SIZE + mdh.len() + ciphertext.len());
        packet.extend_from_slice(&tag);
        packet.extend_from_slice(mdh);
        packet.extend_from_slice(&ciphertext);
        socket.send_to(&packet, client_addr).await?;
        Ok(())
    }

    async fn send_server_hello(
        &self,
        session: &Arc<parking_lot::Mutex<Session>>,
        client_addr: SocketAddr,
    ) -> Result<()> {
        let (server_eph_pub, signature, network_config) = {
            let sess = session.lock();
            match (sess.server_eph_pub, sess.server_hello_signature) {
                (Some(pub_key), Some(sig)) => {
                    let network_config = sess
                        .vpn_ip
                        .and_then(|vpn_ip| self.config.network_config.client_config(vpn_ip).ok());
                    (pub_key, sig, network_config)
                }
                _ => return Err(Error::Session("Missing ratchet data".into())),
            }
        };

        let hello = ControlPayload::ServerHello {
            server_eph_pub,
            signature,
            network_config,
        };
        let encoded = hello.encode()?;
        let inner_header = InnerHeader {
            inner_type: InnerType::Control,
            seq_num: 0,
        };
        let mut inner_payload = inner_header.encode().to_vec();
        inner_payload.extend_from_slice(&encoded);
        let packet = self.build_packet(&inner_payload, session)?;
        let socket = self.udp_socket.as_ref().unwrap();
        let sent = socket.send_to(&packet, client_addr).await?;
        debug!("ServerHello sent: {} bytes to {}", sent, client_addr);
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
        let current_mask = sess.mask.clone();
        drop(sess);

        // Build MDH using the session's current packet mask so the peer can
        // decode bootstrap traffic before any runtime MaskUpdate arrives.
        let mdh = current_mask
            .as_ref()
            .map(packet_mdh_bytes_for_mask)
            .unwrap_or_else(|| self.mask_catalog.packet_mdh_bytes());
        
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

#[cfg(test)]
mod tests {
    use super::MaskCatalog;
    use aivpn_common::crypto::TAG_SIZE;
    use aivpn_common::mask::preset_masks::webrtc_zoom_v3;

    #[test]
    fn packet_layout_extracts_embedded_eph_pub_from_mdh() {
        let catalog = MaskCatalog::new();
        let mask = webrtc_zoom_v3();
        catalog.register_mask(mask.clone());
        catalog.set_primary_mask_id(mask.mask_id.clone());
        let (packet_mdh_len, handshake_mdh_len, eph_offset, eph_len) = catalog.packet_layout();

        let mut mdh = mask.header_template.clone();
        if mdh.len() < handshake_mdh_len {
            mdh.resize(handshake_mdh_len, 0);
        }

        let expected_eph = [0x5au8; 32];
        mdh[eph_offset..eph_offset + eph_len].copy_from_slice(&expected_eph);

        let mut packet = vec![0u8; TAG_SIZE];
        packet.extend_from_slice(&mdh);
        packet.extend_from_slice(&[0xabu8; 24]);

        let eph_start = TAG_SIZE + eph_offset;
        let payload_start = TAG_SIZE + handshake_mdh_len;

        assert_eq!(packet_mdh_len, 20, "regular STUN packet MDH length must stay at 20 bytes");
        assert_eq!(handshake_mdh_len, 52, "handshake MDH length must include embedded eph_pub");
        assert_eq!(&packet[eph_start..eph_start + eph_len], &expected_eph);
        assert_eq!(&packet[payload_start..], &[0xabu8; 24]);
    }
}
