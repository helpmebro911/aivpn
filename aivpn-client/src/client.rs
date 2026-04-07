//! AIVPN Client - Full Implementation
//! 
//! Complete VPN client with:
//! - Real TUN device integration
//! - Mimicry Engine for traffic shaping
//! - Key exchange and session management
//! - Control plane handling

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{info, debug, error, warn};
use bytes::Bytes;

use aivpn_common::crypto::{
    self, SessionKeys, KeyPair, X25519_PUBLIC_KEY_SIZE,
};
use aivpn_common::client_wire::{
    build_inner_packet, decode_packet_with_mdh_len, obfuscate_client_eph_pub, RecvWindow,
};
use aivpn_common::protocol::{
    InnerType, ControlPayload, MAX_PACKET_SIZE,
};
use aivpn_common::mask::MaskProfile;
use aivpn_common::error::{Error, Result};
use aivpn_common::upload_pipeline::{self, PacketEncryptor, UploadConfig};

use crate::mimicry::MimicryEngine;
use crate::tunnel::{Tunnel, TunnelConfig};

/// Client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server_addr: String,
    pub server_public_key: [u8; X25519_PUBLIC_KEY_SIZE],
    pub preshared_key: Option<[u8; 32]>,
    pub initial_mask: MaskProfile,
    pub tun_config: TunnelConfig,
    /// Server's Ed25519 signing public key for authentication (HIGH-6)
    pub server_signing_pub: Option<[u8; 32]>,
}

/// Client state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientState {
    Unprovisioned,
    Provisioned,
    Connecting,
    Connected,
    Reconnecting,
    Disconnected,
}

struct UploadCryptoState {
    keys: SessionKeys,
    counter: u64,
    seq: u16,
}

/// AIVPN Client instance
pub struct AivpnClient {
    config: ClientConfig,
    state: ClientState,
    tunnel: Tunnel,
    udp_socket: Option<Arc<UdpSocket>>,
    mimicry_engine: Option<MimicryEngine>,
    session_keys: Option<SessionKeys>,
    upload_state: Option<Arc<Mutex<UploadCryptoState>>>,
    transition_recv_keys: Option<SessionKeys>,
    keypair: KeyPair,
    counter: u64,
    send_seq: u32,
    recv_seq: u32,
    recv_window: RecvWindow,
    transition_recv_window: RecvWindow,
    // Traffic counters
    bytes_sent: Arc<std::sync::atomic::AtomicU64>,
    bytes_received: Arc<std::sync::atomic::AtomicU64>,
    // Pre-allocated buffers for zero-copy I/O (OPTIMIZATION)
    send_buf: Vec<u8>,
    recv_buf: Vec<u8>,
}

impl AivpnClient {
    /// Create new client
    pub fn new(config: ClientConfig) -> Result<Self> {
        let keypair = KeyPair::generate();
        let tunnel = Tunnel::new(config.tun_config.clone());
        let bytes_sent = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let bytes_received = Arc::new(std::sync::atomic::AtomicU64::new(0));

        Ok(Self {
            config,
            state: ClientState::Provisioned,
            tunnel,
            udp_socket: None,
            mimicry_engine: None,
            session_keys: None,
            upload_state: None,
            transition_recv_keys: None,
            keypair,
            counter: 0,
            send_seq: 0,
            recv_seq: 0,
            recv_window: RecvWindow::new(),
            transition_recv_window: RecvWindow::new(),
            bytes_sent: bytes_sent.clone(),
            bytes_received: bytes_received.clone(),
            // Pre-allocate buffers to MAX_PACKET_SIZE to avoid reallocations
            send_buf: Vec::with_capacity(MAX_PACKET_SIZE),
            recv_buf: Vec::with_capacity(MAX_PACKET_SIZE),
        })
    }
    
    /// Connect to server
    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to AIVPN server...");
        self.state = ClientState::Connecting;
        
        // Create TUN device first
        self.tunnel.create()?;
        
        // Parse server IP for full-tunnel bypass route
        let server_addr: SocketAddr = self.config.server_addr.parse()
            .map_err(|e: std::net::AddrParseError| Error::Io(
                std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
            ))?;
        self.tunnel.set_server_ip(server_addr.ip().to_string());
        
        // Enable full tunnel if configured
        if self.config.tun_config.full_tunnel {
            self.tunnel.enable_full_tunnel()?;
        }
        
        // Create UDP socket with 4MB OS buffers (OPTIMIZATION)
        let domain = if server_addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
        let socket2_sock = socket2::Socket::new(
            domain,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        ).map_err(Error::Io)?;
        
        socket2_sock.set_nonblocking(true).map_err(Error::Io)?;
        let _ = socket2_sock.set_recv_buffer_size(4 * 1024 * 1024);
        let _ = socket2_sock.set_send_buffer_size(4 * 1024 * 1024);
        
        // Bind to any ephemeral port
        let any_addr: SocketAddr = if server_addr.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
        socket2_sock.bind(&any_addr.into()).map_err(Error::Io)?;
        
        // Connect UDP socket
        socket2_sock.connect(&server_addr.into()).map_err(Error::Io)?;
        
        let std_sock: std::net::UdpSocket = socket2_sock.into();
        let socket = UdpSocket::from_std(std_sock).map_err(Error::Io)?;
        
        self.udp_socket = Some(Arc::new(socket));
        
        // Initialize mimicry engine
        self.mimicry_engine = Some(MimicryEngine::new(self.config.initial_mask.clone()));
        
        // Derive session keys (Zero-RTT)
        let dh_result = self.keypair.compute_shared(&self.config.server_public_key)?;
        self.session_keys = Some(crypto::derive_session_keys(
            &dh_result,
            self.config.preshared_key.as_ref(),
            &self.keypair.public_key_bytes(),
        ));
        
        self.state = ClientState::Connected;
        info!("Connected to server at {}", self.config.server_addr);
        info!("TUN device: {}", self.tunnel.name());
        
        Ok(())
    }
    
    /// Disconnect from server
    pub async fn disconnect(&mut self) {
        info!("Disconnecting...");
        
        // Send shutdown message if connected
        if self.state == ClientState::Connected {
            if self.session_keys.is_some() {
                let shutdown = ControlPayload::Shutdown { reason: 0 };
                let _ = self.send_control(&shutdown).await;
            }
        }
        
        self.state = ClientState::Disconnected;
        self.udp_socket = None;
        
        // Zeroize keys
        self.session_keys = None;
        self.upload_state = None;
        self.transition_recv_keys = None;
    }
    
    /// Run the client main loop
    pub async fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        self.connect().await?;

        // Send initial handshake packet with eph_pub to establish session
        self.send_init().await?;

        info!("Starting client main loop");
        info!("Routing traffic through AIVPN tunnel...");

        // Create channels for TUN -> upload pipeline and UDP -> main loop
        let (tun_to_udp_tx, tun_to_udp_rx) = mpsc::channel::<Vec<u8>>(8192);
        let (udp_to_tun_tx, mut udp_to_tun_rx) = mpsc::channel::<Bytes>(8192);

        // Take the TUN reader for the spawned task (no Mutex needed)
        let mut tun_reader = self.tunnel.take_reader()
            .ok_or(Error::Session("TUN reader not available".into()))?;
        let tun_to_udp_tx_clone = tun_to_udp_tx.clone();
        let shutdown_for_tasks = shutdown.clone();
        let tun_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            loop {
                if shutdown_for_tasks.load(Ordering::SeqCst) {
                    break;
                }

                match tun_reader.read(&mut buf).await {
                    Ok(n) => {
                        if n > 0 {
                            debug!("TUN read {} bytes", n);

                            #[cfg(target_os = "macos")]
                            let payload: Vec<u8> = if n > 4 && buf[0] == 0 && buf[1] == 0 {
                                buf[4..n].to_vec()
                            } else {
                                buf[..n].to_vec()
                            };

                            #[cfg(not(target_os = "macos"))]
                            let payload: Vec<u8> = buf[..n].to_vec();

                            let _ = tun_to_udp_tx_clone.send(payload).await;
                        }
                    }
                    Err(e) => {
                        error!("TUN read error: {}", e);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        });

        // Spawn UDP reader task
        let udp_socket = self.udp_socket.as_ref().unwrap().clone();
        let udp_to_tun_tx_clone = udp_to_tun_tx.clone();
        let shutdown_for_tasks = shutdown.clone();
        let udp_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            let mut consecutive_errors: u32 = 0;

            loop {
                if shutdown_for_tasks.load(Ordering::SeqCst) {
                    break;
                }

                match udp_socket.recv(&mut buf).await {
                    Ok(n) => {
                        consecutive_errors = 0;
                        if n > 0 {
                            let _ = udp_to_tun_tx_clone.send(Bytes::copy_from_slice(&buf[..n])).await;
                        }
                    }
                    Err(e) => {
                        consecutive_errors += 1;
                        error!("UDP recv error: {}", e);
                        if consecutive_errors >= 20 {
                            // Socket is likely dead; let the main loop handle reconnect.
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        });

        // Spawn stats writer task
        let stats_shutdown = shutdown.clone();
        let stats_bytes_sent = self.bytes_sent.clone();
        let stats_bytes_received = self.bytes_received.clone();
        let stats_task = tokio::spawn(async move {
            // Write initial stats to both locations (async to avoid blocking tokio thread)
            let _ = tokio::fs::write("/var/run/aivpn/traffic.stats", "sent:0,received:0").await;
            let _ = tokio::fs::write("/tmp/aivpn-traffic.stats", "sent:0,received:0").await;
            info!("Initial stats written");
            
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                if stats_shutdown.load(Ordering::SeqCst) {
                    break;
                }
                let sent = stats_bytes_sent.load(std::sync::atomic::Ordering::Relaxed);
                let received = stats_bytes_received.load(std::sync::atomic::Ordering::Relaxed);
                let stats = format!("sent:{},received:{}", sent, received);
                let _ = tokio::fs::write("/var/run/aivpn/traffic.stats", &stats).await;
                let _ = tokio::fs::write("/tmp/aivpn-traffic.stats", &stats).await;
            }
        });

        // ── Spawn upload task using the shared pipeline ──
        let upload_udp = self.udp_socket.as_ref().unwrap().clone();
        let upload_keys = self.session_keys.clone()
            .ok_or(Error::Session("No session keys".into()))?;
        let upload_engine = self.mimicry_engine.take()
            .ok_or(Error::Session("No mimicry engine".into()))?;
        let upload_seq = self.send_seq as u16;
        let upload_counter = self.counter;
        let upload_bytes_sent = self.bytes_sent.clone();
        let upload_state = Arc::new(Mutex::new(UploadCryptoState {
            keys: upload_keys,
            counter: upload_counter,
            seq: upload_seq,
        }));
        self.upload_state = Some(upload_state.clone());

        // Store mdh_len for the receive path (before moving engine into the task).
        let mdh_len = upload_engine.mask().header_template.len();

        let mut upload_task = tokio::spawn(Self::spawn_upload(
            tun_to_udp_rx,
            upload_udp,
            upload_engine,
            upload_state,
            upload_bytes_sent,
        ));

        // Main loop: download + shutdown + upload health
        let mut shutdown_tick = tokio::time::interval(Duration::from_secs(1));
        shutdown_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let run_res: Result<()> = loop {
            tokio::select! {
                biased;

                // Allow fast shutdown.
                _ = shutdown_tick.tick() => {
                    if shutdown.load(Ordering::SeqCst) {
                        info!("Shutdown requested");
                        stats_task.abort();
                        break Ok(());
                    }
                }

                // Upload task completed (error or channel closed).
                join_res = &mut upload_task => {
                    break match join_res {
                        Ok(Ok(())) => Err(Error::Channel("Upload loop ended unexpectedly".into())),
                        Ok(Err(e)) => Err(e),
                        Err(e) => Err(Error::Session(format!("Upload task panicked: {e}"))),
                    };
                }

                // UDP -> TUN (inbound traffic)
                res = udp_to_tun_rx.recv() => {
                    let packet = match res {
                        Some(p) => p,
                        None => break Err(Error::Channel("UDP->TUN channel closed".into())),
                    };

                    if let Err(e) = self.receive_and_write_packet_with_mdh(&packet, mdh_len).await {
                        match &e {
                            Error::InvalidPacket(_) => warn!("Receive invalid packet: {}", e),
                            _ => {
                                warn!("Receive error: {}", e);
                                break Err(e);
                            }
                        }
                    }
                }
            }
        };

        // Stop background tasks before disconnecting.
        tun_task.abort();
        udp_task.abort();
        let _ = tun_task.await;
        let _ = udp_task.await;

        self.disconnect().await;

        run_res
    }

    /// Spawn the upload task using the shared pipeline.
    async fn spawn_upload(
        mut rx: mpsc::Receiver<Vec<u8>>,
        udp: Arc<UdpSocket>,
        engine: MimicryEngine,
        upload_state: Arc<Mutex<UploadCryptoState>>,
        bytes_sent: Arc<std::sync::atomic::AtomicU64>,
    ) -> Result<()> {
        /// Wraps MimicryEngine to implement the shared PacketEncryptor trait.
        struct MimicryEncryptor {
            engine: MimicryEngine,
            upload_state: Arc<Mutex<UploadCryptoState>>,
            bytes_sent: Arc<std::sync::atomic::AtomicU64>,
        }

        impl PacketEncryptor for MimicryEncryptor {
            fn encrypt_data(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
                let mut state = self.upload_state.lock().expect("upload state poisoned");
                let inner = build_inner_packet(InnerType::Data, state.seq, payload);
                state.seq = state.seq.wrapping_add(1);
                let keys = state.keys.clone();
                let pkt = self.engine.build_packet(&inner, &keys, &mut state.counter, None)?;
                self.engine.update_fsm();
                Ok(pkt)
            }

            fn encrypt_keepalive(&mut self) -> Result<Vec<u8>> {
                let mut state = self.upload_state.lock().expect("upload state poisoned");
                let keepalive = ControlPayload::Keepalive.encode()?;
                let inner = build_inner_packet(InnerType::Control, state.seq, &keepalive);
                state.seq = state.seq.wrapping_add(1);
                let keys = state.keys.clone();
                self.engine.build_packet(&inner, &keys, &mut state.counter, None)
            }

            fn on_data_sent(&mut self, payload_len: usize) {
                self.bytes_sent.fetch_add(payload_len as u64, std::sync::atomic::Ordering::Relaxed);
            }
        }

        let mut enc = MimicryEncryptor { engine, upload_state, bytes_sent };
        let config = UploadConfig {
            keepalive_interval: Duration::from_secs(15),
            ..Default::default()
        };
        upload_pipeline::run_upload_loop(&mut rx, &udp, &mut enc, &config).await
    }

    /// Receive packet from server and write to TUN (using pre-computed mdh_len)
    async fn receive_and_write_packet_with_mdh(&mut self, packet: &[u8], mdh_len: usize) -> Result<()> {
        let keys = self.session_keys.as_ref()
            .ok_or(Error::Session("No session keys".into()))?;

        let decoded = match decode_packet_with_mdh_len(packet, keys, &mut self.recv_window, mdh_len) {
            Ok(decoded) => {
                if self.transition_recv_keys.take().is_some() {
                    self.transition_recv_window.reset();
                    info!("Receive ratchet complete — old inbound keys dropped");
                }
                decoded
            }
            Err(primary_err) => {
                let Some(fallback_keys) = self.transition_recv_keys.as_ref() else {
                    return Err(primary_err);
                };

                decode_packet_with_mdh_len(
                    packet,
                    fallback_keys,
                    &mut self.transition_recv_window,
                    mdh_len,
                )?
            }
        };
        let inner_header = decoded.header;
        let ip_payload = decoded.payload;

        match inner_header.inner_type {
            InnerType::Data => {
                if ip_payload.is_empty() || (ip_payload[0] >> 4 != 4 && ip_payload[0] >> 4 != 6) {
                    return Err(Error::InvalidPacket("Invalid IP version in payload"));
                }
                self.tunnel.write_packet_async(&ip_payload).await?;
                self.bytes_received.fetch_add(ip_payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
                debug!("Received {} bytes from server, wrote to TUN", ip_payload.len());
            }
            InnerType::Control => {
                let control = ControlPayload::decode(&ip_payload)?;
                self.handle_server_control(control).await?;
            }
            _ => {
                debug!("Received non-data packet type: {:?}", inner_header.inner_type);
            }
        }

        Ok(())
    }

    /// Handle control messages from server
    async fn handle_server_control(&mut self, control: ControlPayload) -> Result<()> {
        match control {
            ControlPayload::MaskUpdate { mask_data, .. } => {
                match rmp_serde::from_slice::<MaskProfile>(&mask_data) {
                    Ok(new_mask) => self.update_mask(new_mask),
                    Err(e) => warn!("Failed to parse mask update: {}", e),
                }
            }
            ControlPayload::KeyRotate { new_eph_pub: _ } => {
                debug!("Key rotation signal received");
            }
            ControlPayload::ServerHello { server_eph_pub, signature } => {
                info!("ServerHello received — completing PFS ratchet");
                
                // Verify Ed25519 signature if server signing key configured (HIGH-6)
                if let Some(signing_pub) = &self.config.server_signing_pub {
                    use ed25519_dalek::{VerifyingKey, Verifier, Signature};
                    let vk = VerifyingKey::from_bytes(signing_pub)
                        .map_err(|e| Error::Crypto(format!("Invalid server signing key: {}", e)))?;
                    let mut message = Vec::with_capacity(64);
                    message.extend_from_slice(&server_eph_pub);
                    message.extend_from_slice(&self.keypair.public_key_bytes());
                    let sig = Signature::from_bytes(&signature);
                    vk.verify(&message, &sig)
                        .map_err(|_| Error::Crypto("ServerHello signature verification failed".into()))?;
                    info!("Server authenticated via Ed25519 signature");
                }
                
                // Compute DH2 = client_eph * server_eph for PFS (CRIT-3)
                let dh2 = self.keypair.compute_shared(&server_eph_pub)?;
                
                // Derive ratcheted keys using current session_key as PSK
                let current_key = self.session_keys.as_ref()
                    .ok_or(Error::Session("No session keys for ratchet".into()))?
                    .session_key;
                let ratcheted = crypto::derive_session_keys(
                    &dh2, Some(&current_key), &self.keypair.public_key_bytes(),
                );

                // Keep accepting old inbound keys until the server proves it has
                // switched too. Outbound traffic moves to ratcheted keys now.
                self.transition_recv_keys = self.session_keys.clone();
                self.transition_recv_window = std::mem::take(&mut self.recv_window);

                // Switch to ratcheted keys — outbound uses the new keys immediately.
                self.session_keys = Some(ratcheted);
                self.counter = 0;
                self.recv_window.reset();
                if let Some(upload_state) = &self.upload_state {
                    let mut state = upload_state.lock().expect("upload state poisoned");
                    state.keys = self.session_keys.clone().expect("session keys set");
                    state.counter = 0;
                    info!("Outbound ratchet activated — upload switched to new keys");
                }
                info!("PFS ratchet complete — forward secrecy established");
            }
            ControlPayload::Keepalive => {
                debug!("Keepalive from server");
            }
            ControlPayload::TimeSync { server_ts_ms } => {
                debug!("Time sync: server_ts={}", server_ts_ms);
            }
            ControlPayload::Shutdown { reason } => {
                info!("Server requested shutdown (reason: {})", reason);
                self.disconnect().await;
            }
            _ => {}
        }
        Ok(())
    }
    
    /// Send initial handshake packet with eph_pub to establish server-side session
    async fn send_init(&mut self) -> Result<()> {
        let keys = self.session_keys.as_ref()
            .ok_or(Error::Session("No session keys".into()))?;
        
        let mimicry = self.mimicry_engine.as_mut()
            .ok_or(Error::Session("No mimicry engine".into()))?;
        
        // Build keepalive control as init payload
        let keepalive = ControlPayload::Keepalive;
        let encoded = keepalive.encode()?;
        let seq_num = self.send_seq as u16;
        self.send_seq = self.send_seq.wrapping_add(1);
        let inner_payload = build_inner_packet(InnerType::Control, seq_num, &encoded);
        
        // Include eph_pub (obfuscated) in the init packet
        let obf = obfuscate_client_eph_pub(&self.keypair, &self.config.server_public_key);
        
        let aivpn_packet = mimicry.build_packet(
            &inner_payload,
            keys,
            &mut self.counter,
            Some(&obf),
        )?;
        
        let socket = self.udp_socket.as_ref().unwrap();
        socket.send(&aivpn_packet).await?;
        
        info!("Sent init handshake ({} bytes)", aivpn_packet.len());
        Ok(())
    }
    
    /// Send control message
    async fn send_control(&mut self, payload: &ControlPayload) -> Result<()> {
        let keys = self.session_keys.as_ref()
            .ok_or(Error::Session("No session keys".into()))?;
        
        let mimicry = self.mimicry_engine.as_mut()
            .ok_or(Error::Session("No mimicry engine".into()))?;
        
        // Encode control message
        let encoded = payload.encode()?;
        
        let seq_num = self.send_seq as u16;
        self.send_seq = self.send_seq.wrapping_add(1);
        let inner_payload = build_inner_packet(InnerType::Control, seq_num, &encoded);
        
        // Build packet (no timing for control messages)
        let aivpn_packet = mimicry.build_packet(
            &inner_payload,
            keys,
            &mut self.counter,
            None,
        )?;
        
        let socket = self.udp_socket.as_ref().unwrap();
        socket.send(&aivpn_packet).await?;
        
        Ok(())
    }
    
    /// Update mask profile
    pub fn update_mask(&mut self, new_mask: MaskProfile) {
        if let Some(ref mut engine) = self.mimicry_engine {
            info!("Updating mask to {}", new_mask.mask_id);
            engine.update_mask(new_mask);
        }
    }
    
    /// Get current state
    pub fn state(&self) -> ClientState {
        self.state.clone()
    }
    
    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.state == ClientState::Connected
    }

    /// Get traffic statistics
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Drop for AivpnClient {
    fn drop(&mut self) {
        // Zeroize sensitive data
        self.session_keys = None;
    }
}
