//! AIVPN Client - Full Implementation
//! 
//! Complete VPN client with:
//! - Real TUN device integration
//! - Mimicry Engine for traffic shaping
//! - Key exchange and session management
//! - Control plane handling

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{info, debug, error, warn};
use bytes::Bytes;

use aivpn_common::crypto::{
    self, SessionKeys, KeyPair, TAG_SIZE, NONCE_SIZE, X25519_PUBLIC_KEY_SIZE,
};
use aivpn_common::protocol::{
    InnerType, InnerHeader, ControlPayload, ControlSubtype, MAX_PACKET_SIZE, AckPacket,
};
use aivpn_common::mask::MaskProfile;
use aivpn_common::error::{Error, Result};
use subtle::ConstantTimeEq;

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

/// AIVPN Client instance
pub struct AivpnClient {
    config: ClientConfig,
    state: ClientState,
    tunnel: Tunnel,
    udp_socket: Option<Arc<UdpSocket>>,
    mimicry_engine: Option<MimicryEngine>,
    session_keys: Option<SessionKeys>,
    keypair: KeyPair,
    counter: u64,
    send_seq: u32,
    recv_seq: u32,
    recv_counter: u64,
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
            keypair,
            counter: 0,
            send_seq: 0,
            recv_seq: 0,
            recv_counter: 0,
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
        
        // Create UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(server_addr).await?;
        
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
            if let Some(keys) = &self.session_keys {
                let shutdown = ControlPayload::Shutdown { reason: 0 };
                let _ = self.send_control(&shutdown).await;
            }
        }
        
        self.state = ClientState::Disconnected;
        self.udp_socket = None;
        
        // Zeroize keys
        self.session_keys = None;
    }
    
    /// Run the client main loop
    pub async fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        self.connect().await?;

        // Send initial handshake packet with eph_pub to establish session
        self.send_init().await?;

        info!("Starting client main loop");
        info!("Routing traffic through AIVPN tunnel...");

        // Create channels for TUN <-> UDP forwarding (using Bytes for zero-copy)
        let (tun_to_udp_tx, mut tun_to_udp_rx) = mpsc::channel::<Bytes>(100);
        let (udp_to_tun_tx, mut udp_to_tun_rx) = mpsc::channel::<Bytes>(100);

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
                            let payload = if n > 4 && buf[0] == 0 && buf[1] == 0 {
                                // Strip 4-byte PI header
                                Bytes::copy_from_slice(&buf[4..n])
                            } else {
                                Bytes::copy_from_slice(&buf[..n])
                            };

                            #[cfg(not(target_os = "macos"))]
                            let payload = Bytes::copy_from_slice(&buf[..n]);

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
            // Write initial stats to both locations
            let stats = "sent:0,received:0";
            let _ = std::fs::write("/var/run/aivpn/traffic.stats", stats);
            let _ = std::fs::write("/tmp/aivpn-traffic.stats", stats);
            info!("Initial stats written");
            
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                let sent = stats_bytes_sent.load(std::sync::atomic::Ordering::Relaxed);
                let received = stats_bytes_received.load(std::sync::atomic::Ordering::Relaxed);
                let stats = format!("sent:{},received:{}", sent, received);
                let _ = std::fs::write("/var/run/aivpn/traffic.stats", &stats);
                let _ = std::fs::write("/tmp/aivpn-traffic.stats", &stats);
                
                if stats_shutdown.load(Ordering::SeqCst) {
                    break;
                }
            }
        });

        // Main forwarding loop
        let mut keepalive_interval = tokio::time::interval(Duration::from_secs(15));
        keepalive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut shutdown_tick = tokio::time::interval(Duration::from_secs(1));
        shutdown_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let run_res: Result<()> = loop {
            tokio::select! {
                // Allow fast shutdown.
                _ = shutdown_tick.tick() => {
                    if shutdown.load(Ordering::SeqCst) {
                        info!("Shutdown requested");
                        stats_task.abort();
                        break Ok(());
                    }
                }

                // Periodic keepalive so idle connections also detect failures.
                _ = keepalive_interval.tick() => {
                    if let Err(e) = self.send_control(&ControlPayload::Keepalive).await {
                        warn!("Keepalive send error: {}", e);
                        break Err(e);
                    }
                }

                // TUN -> UDP (outbound traffic)
                res = tun_to_udp_rx.recv() => {
                    let packet = match res {
                        Some(p) => p,
                        None => break Err(Error::Channel("TUN->UDP channel closed".into())),
                    };

                    // If we can't send, reconnect is required (e.g. network changed).
                    if let Err(e) = self.send_packet(&packet).await {
                        warn!("Send error: {}", e);
                        break Err(e);
                    }
                }

                // UDP -> TUN (inbound traffic)
                res = udp_to_tun_rx.recv() => {
                    let packet = match res {
                        Some(p) => p,
                        None => break Err(Error::Channel("UDP->TUN channel closed".into())),
                    };

                    if let Err(e) = self.receive_and_write_packet(&packet).await {
                        // Invalid packets are usually transient; do not reconnect on every decoding error.
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

    /// Send packet to server
    async fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        let keys = self.session_keys.as_ref()
            .ok_or(Error::Session("No session keys".into()))?;
        
        let mimicry = self.mimicry_engine.as_mut()
            .ok_or(Error::Session("No mimicry engine".into()))?;
        
        // Build inner header
        let inner_header = InnerHeader {
            inner_type: InnerType::Data,
            seq_num: self.send_seq as u16,
        };
        self.send_seq = self.send_seq.wrapping_add(1);
        
        // Encode inner payload
        let mut inner_payload = inner_header.encode().to_vec();
        inner_payload.extend_from_slice(packet);

        // Skip timing for MVP — timing causes blocking that prevents recv
        // mimicry.apply_timing().await;

        // Build and send packet
        let eph_pub = if self.send_seq == 1 {
            // Obfuscate eph_pub with server's static public key (HIGH-9)
            let mut obf = self.keypair.public_key_bytes();
            crypto::obfuscate_eph_pub(&mut obf, &self.config.server_public_key);
            Some(obf)
        } else {
            None
        };
        
        let aivpn_packet = mimicry.build_packet(
            &inner_payload,
            keys,
            &mut self.counter,
            eph_pub.as_ref(),
        )?;
        
        let socket = self.udp_socket.as_ref().unwrap();
        socket.send(&aivpn_packet).await?;

        // Update FSM
        mimicry.update_fsm();

        // Update traffic counter
        self.bytes_sent.fetch_add(packet.len() as u64, std::sync::atomic::Ordering::Relaxed);

        debug!("Sent {} bytes ({} payload)", aivpn_packet.len(), packet.len());
        Ok(())
    }
    
    /// Receive packet from server and write to TUN
    async fn receive_and_write_packet(&mut self, packet: &[u8]) -> Result<()> {
        let keys = self.session_keys.as_ref()
            .ok_or(Error::Session("No session keys".into()))?;
        
        let mimicry = self.mimicry_engine.as_ref()
            .ok_or(Error::Session("No mimicry engine".into()))?;

        // 1. Minimum size check
        if packet.len() < TAG_SIZE + 2 {
            return Err(Error::InvalidPacket("Packet too short"));
        }

        // 2. Extract resonance tag (first 8 bytes)
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(&packet[0..TAG_SIZE]);

        // 3. Validate tag against expected window (server uses our tag_secret)
        let time_window = crypto::compute_time_window(
            crypto::current_timestamp_ms(),
            aivpn_common::crypto::DEFAULT_WINDOW_MS,
        );
        // Check current and adjacent time windows for clock skew tolerance
        let mut valid_counter = None;
        for window_offset in [0i64, -1, 1] {
            let tw = (time_window as i64 + window_offset) as u64;
            // Try a range of counters the server might be using
            for c in self.recv_counter..self.recv_counter + 256 {
                let expected = crypto::generate_resonance_tag(&keys.tag_secret, c, tw);
                if bool::from(expected.ct_eq(&tag)) {
                    valid_counter = Some(c);
                    break;
                }
            }
            if valid_counter.is_some() { break; }
        }
        let counter = valid_counter.ok_or(Error::InvalidPacket("Invalid resonance tag"))?;

        // 4. Parse MDH (skip it — we know MDH length from mask)
        let mdh_len = mimicry.mask().header_template.len();
        if packet.len() <= TAG_SIZE + mdh_len {
            return Err(Error::InvalidPacket("Packet too short for MDH"));
        }

        // 5. Decrypt full ciphertext (pad_len is inside encrypted area)
        let encrypted_payload = &packet[TAG_SIZE + mdh_len..];
        let mut nonce = [0u8; aivpn_common::crypto::NONCE_SIZE];
        nonce[0..8].copy_from_slice(&counter.to_le_bytes());
        let padded_plaintext = crypto::decrypt_payload(&keys.session_key, &nonce, encrypted_payload)?;

        // 6. Extract pad_len from inside decrypted data and strip padding
        if padded_plaintext.len() < 6 {
            return Err(Error::InvalidPacket("Decrypted payload too short"));
        }
        let pad_len = u16::from_le_bytes([padded_plaintext[0], padded_plaintext[1]]) as usize;
        if 2 + pad_len > padded_plaintext.len() {
            return Err(Error::InvalidPacket("Invalid padding length"));
        }
        let plaintext = &padded_plaintext[2..padded_plaintext.len() - pad_len];

        // 7. Parse inner header
        if plaintext.len() < 4 {
            return Err(Error::InvalidPacket("Inner payload too short"));
        }
        let inner_header = InnerHeader::decode(plaintext)?;
        let ip_payload = &plaintext[4..];

        // 8. Update recv counter
        self.recv_counter = counter + 1;

        // 9. Route based on inner type
        match inner_header.inner_type {
            InnerType::Data => {
                // Validate IP packet before writing to TUN (HIGH-10)
                if ip_payload.is_empty() || (ip_payload[0] >> 4 != 4 && ip_payload[0] >> 4 != 6) {
                    return Err(Error::InvalidPacket("Invalid IP version in payload"));
                }
                self.tunnel.write_packet_async(ip_payload).await?;
                // Update traffic counter
                self.bytes_received.fetch_add(ip_payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
                debug!("Received {} bytes from server, wrote to TUN", ip_payload.len());
            }
            InnerType::Control => {
                let control = ControlPayload::decode(ip_payload)?;
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
                
                // Switch to ratcheted keys — old keys dropped, PFS established
                self.session_keys = Some(ratcheted);
                self.counter = 0;
                self.recv_counter = 0;
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
        let inner_header = InnerHeader {
            inner_type: InnerType::Control,
            seq_num: self.send_seq as u16,
        };
        self.send_seq = self.send_seq.wrapping_add(1);
        
        let mut inner_payload = inner_header.encode().to_vec();
        inner_payload.extend_from_slice(&encoded);
        
        // Include eph_pub (obfuscated) in the init packet
        let mut obf = self.keypair.public_key_bytes();
        crypto::obfuscate_eph_pub(&mut obf, &self.config.server_public_key);
        
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
        
        // Build inner header
        let inner_header = InnerHeader {
            inner_type: InnerType::Control,
            seq_num: self.send_seq as u16,
        };
        self.send_seq = self.send_seq.wrapping_add(1);
        
        let mut inner_payload = inner_header.encode().to_vec();
        inner_payload.extend_from_slice(&encoded);
        
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
