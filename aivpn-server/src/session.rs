//! Session Manager
//! 
//! Manages active VPN sessions with O(1) tag validation

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;
use chacha20poly1305::aead::OsRng;
use rand::RngCore;
use subtle::ConstantTimeEq;
use tracing::{info, debug, trace};
use hex;

use aivpn_common::crypto::{
    self, SessionKeys, KeyPair, TAG_SIZE, X25519_PUBLIC_KEY_SIZE, 
    NONCE_SIZE, DEFAULT_WINDOW_MS,
};
use aivpn_common::protocol::{InnerType, InnerHeader, ControlPayload};
use aivpn_common::mask::MaskProfile;
use aivpn_common::error::{Error, Result};

/// Maximum sessions on 1GB VPS
pub const MAX_SESSIONS: usize = 500;

/// Session idle timeout (default)
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Session hard timeout — 0 means unlimited (Issue #33).
/// Configurable via `session_timeout_secs` in server.json.
/// PFS ratchet already handles key rotation, so forced session
/// expiration is unnecessary and causes reconnect failures.
pub const HARD_TIMEOUT: Duration = Duration::ZERO;

/// Tag window size (allow out-of-order packets)
pub const TAG_WINDOW_SIZE: usize = 256;

/// Session state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Pending,
    Active,
    Idle,
    Rotating,
    MaskChange,
    Expired,
    Closed,
}

/// Session information
pub struct Session {
    pub session_id: [u8; 16],
    pub client_addr: SocketAddr,
    pub state: SessionState,
    pub keys: SessionKeys,
    pub eph_pub: [u8; X25519_PUBLIC_KEY_SIZE],
    
    /// Packet counter for tag generation
    pub counter: u64,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Created timestamp
    pub created_at: Instant,
    /// Last server-to-client packet timestamp (for downlink recording IAT)
    pub last_server_send: Instant,
    
    /// Current mask profile
    pub mask: Option<MaskProfile>,
    /// Pending mask awaiting grace period before activation.
    /// Stored as (new_mask, timestamp_when_MaskUpdate_was_sent).
    pub pending_mask: Option<(MaskProfile, Instant)>,
    /// Current FSM state
    pub fsm_state: u16,
    /// Packets in current FSM state
    pub fsm_packets: u32,
    /// Duration in current FSM state
    pub fsm_state_start: Instant,
    
    /// Sequence number for outgoing packets
    pub send_seq: u32,
    /// Last received sequence (for ACK)
    pub recv_seq: u32,
    /// Send counter for nonce generation (u64, same space as tags)
    pub send_counter: u64,
    
    /// Expected tags (counter -> tag)
    pub expected_tags: HashMap<u64, [u8; TAG_SIZE]>,
    /// Counter value used as the base for the currently precomputed tag window.
    pub tag_window_base: u64,
    /// Received tag bitmap (for anti-replay)
    pub received_bitmap: u256,
    /// Accumulated inbound bytes to flush into client_db in batches.
    pub pending_bytes_in: u64,
    /// Accumulated outbound (downlink) bytes to flush into client_db in batches.
    pub pending_bytes_out: u64,

    // --- PFS Ratchet fields (CRIT-3) ---
    /// Server's ephemeral public key for this session
    pub server_eph_pub: Option<[u8; 32]>,
    /// Ed25519 signature for ServerHello
    pub server_hello_signature: Option<[u8; 64]>,
    /// Ratcheted session keys (PFS)
    pub ratcheted_keys: Option<SessionKeys>,
    /// Ratcheted tags for validation (counter -> tag)
    pub ratcheted_expected_tags: HashMap<u64, [u8; TAG_SIZE]>,
    /// Whether session has completed PFS ratchet
    pub is_ratcheted: bool,
    /// Assigned VPN IP (e.g. 10.0.0.2)
    pub vpn_ip: Option<Ipv4Addr>,
    /// Registered client ID (from client_db) for traffic accounting
    pub client_id: Option<String>,
}

/// 256-bit bitmap for tracking received packets
#[derive(Debug, Clone, Copy, Default)]
#[allow(non_camel_case_types)]
pub struct u256 {
    lo: u128,
    hi: u128,
}

impl u256 {
    pub fn set_bit(&mut self, bit: usize) {
        if bit < 128 {
            self.lo |= 1u128 << bit;
        } else {
            self.hi |= 1u128 << (bit - 128);
        }
    }

    pub fn shift_left(&mut self, shift: usize) {
        if shift == 0 {
            return;
        }
        if shift >= 256 {
            self.clear();
            return;
        }
        if shift >= 128 {
            self.hi = self.lo << (shift - 128);
            self.lo = 0;
            return;
        }

        self.hi = (self.hi << shift) | (self.lo >> (128 - shift));
        self.lo <<= shift;
    }
    
    pub fn get_bit(&self, bit: usize) -> bool {
        if bit < 128 {
            (self.lo & (1u128 << bit)) != 0
        } else {
            (self.hi & (1u128 << (bit - 128))) != 0
        }
    }
    
    pub fn clear(&mut self) {
        self.lo = 0;
        self.hi = 0;
    }
}

impl Session {
    pub fn new(
        session_id: [u8; 16],
        client_addr: SocketAddr,
        keys: SessionKeys,
        eph_pub: [u8; X25519_PUBLIC_KEY_SIZE],
    ) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            client_addr,
            state: SessionState::Pending,
            keys,
            eph_pub,
            counter: 0,
            last_seen: now,
            created_at: now,
            last_server_send: now,
            mask: None,
            pending_mask: None,
            fsm_state: 0,
            fsm_packets: 0,
            fsm_state_start: now,
            send_seq: 0,
            recv_seq: 0,
            send_counter: 0,
            expected_tags: HashMap::with_capacity(TAG_WINDOW_SIZE),
            tag_window_base: 0,
            received_bitmap: u256::default(),
            pending_bytes_in: 0,
            pending_bytes_out: 0,
            server_eph_pub: None,
            server_hello_signature: None,
            ratcheted_keys: None,
            ratcheted_expected_tags: HashMap::new(),
            is_ratcheted: false,
            vpn_ip: None,
            client_id: None,
        }
    }
    
    /// Compute next nonce for encryption from send_counter (u64)
    /// Uses the same counter space as tag generation for consistency
    pub fn next_send_nonce(&mut self) -> ([u8; NONCE_SIZE], u64) {
        let counter = self.send_counter;
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..8].copy_from_slice(&counter.to_le_bytes());
        self.send_counter += 1;
        (nonce, counter)
    }
    
    /// Update expected tags for validation window
    pub fn update_tag_window(&mut self) {
        let time_window = crypto::compute_time_window(
            crypto::current_timestamp_ms(),
            DEFAULT_WINDOW_MS,
        );

        // Pre-compute tags for a bidirectional window around the highest
        // validated counter so minor UDP reordering does not fall out of the
        // fast path lookup map.
        self.expected_tags.clear();
        self.tag_window_base = self.counter;
        let window_back = TAG_WINDOW_SIZE as u64 - 1;
        let window_start = self.counter.saturating_sub(window_back);
        let window_end = self.counter.saturating_add(TAG_WINDOW_SIZE as u64 - 1);

        for counter_val in window_start..=window_end {
            let tag = crypto::generate_resonance_tag(
                &self.keys.tag_secret,
                counter_val,
                time_window,
            );
            self.expected_tags.insert(counter_val, tag);
        }
    }
    
    /// Validate received tag (constant-time)
    /// Returns (counter, is_ratcheted_tag) if valid.
    /// Checks the current time window first, then adjacent windows (±1)
    /// for clock skew tolerance.
    pub fn validate_tag(&self, tag: &[u8; TAG_SIZE]) -> Option<(u64, bool)> {
        let is_replay = |counter_val: u64| {
            if counter_val > self.counter {
                return false;
            }

            let bit_index = (self.counter - counter_val) as usize;
            bit_index < TAG_WINDOW_SIZE && self.received_bitmap.get_bit(bit_index)
        };

        let history_window = TAG_WINDOW_SIZE as u64 - 1;
        let window_start = self.counter.saturating_sub(history_window);
        let window_end = self.counter.saturating_add(TAG_WINDOW_SIZE as u64 - 1);

        // Check initial keys — current time window (pre-computed)
        for (counter, expected) in &self.expected_tags {
            if bool::from(expected.ct_eq(tag)) {
                if is_replay(*counter) {
                    return None; // Already received
                }
                return Some((*counter, false));
            }
        }
        // Check adjacent time windows (±1) on-the-fly for clock skew
        let current_tw = crypto::compute_time_window(
            crypto::current_timestamp_ms(),
            DEFAULT_WINDOW_MS,
        );
        for tw_offset in [current_tw.wrapping_sub(1), current_tw.wrapping_add(1)] {
            for counter_val in window_start..=window_end {
                let expected = crypto::generate_resonance_tag(
                    &self.keys.tag_secret,
                    counter_val,
                    tw_offset,
                );
                if bool::from(expected.ct_eq(tag)) {
                    if is_replay(counter_val) {
                        return None;
                    }
                    return Some((counter_val, false));
                }
            }
        }
        // Check ratcheted keys (only during transition, before ratchet is complete)
        if !self.is_ratcheted {
            for (counter, expected) in &self.ratcheted_expected_tags {
                if bool::from(expected.ct_eq(tag)) {
                    return Some((*counter, true));
                }
            }
            // Also check adjacent windows for ratcheted keys
            if let Some(ratcheted_keys) = &self.ratcheted_keys {
                for tw_offset in [current_tw.wrapping_sub(1), current_tw.wrapping_add(1)] {
                    for i in 0..TAG_WINDOW_SIZE {
                        let expected = crypto::generate_resonance_tag(
                            &ratcheted_keys.tag_secret,
                            i as u64,
                            tw_offset,
                        );
                        if bool::from(expected.ct_eq(tag)) {
                            return Some((i as u64, true));
                        }
                    }
                }
            }
        }
        None
    }
    
    /// Mark tag as received
    pub fn mark_tag_received(&mut self, counter: u64) {
        if counter > self.counter {
            let shift = (counter - self.counter) as usize;
            self.received_bitmap.shift_left(shift);
            self.counter = counter;
            self.received_bitmap.set_bit(0);
            return;
        }

        let bit_index = (self.counter - counter) as usize;
        if bit_index < 256 {
            self.received_bitmap.set_bit(bit_index);
        }
    }
    
    /// Get next sequence number for inner header
    pub fn next_seq(&mut self) -> u32 {
        let seq = self.send_seq;
        self.send_seq = self.send_seq.wrapping_add(1);
        seq
    }
    
    /// Update FSM state
    pub fn update_fsm(&mut self) {
        if let Some(mask) = &self.mask {
            let duration_ms = self.fsm_state_start.elapsed().as_millis() as u64;
            let (new_state, _size_override, _iat_override, _padding_override) = 
                mask.process_transition(self.fsm_state, self.fsm_packets, duration_ms);
            
            if new_state != self.fsm_state {
                self.fsm_state = new_state;
                self.fsm_packets = 0;
                self.fsm_state_start = Instant::now();
            }
        }
        self.fsm_packets += 1;
    }
    
    /// Check if session is idle
    pub fn is_idle(&self) -> bool {
        self.last_seen.elapsed() > IDLE_TIMEOUT
    }
    
    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > HARD_TIMEOUT
    }

    /// Pre-compute tags for ratcheted keys
    pub fn update_ratcheted_tag_window(&mut self) {
        if let Some(ratcheted_keys) = &self.ratcheted_keys {
            let time_window = crypto::compute_time_window(
                crypto::current_timestamp_ms(),
                DEFAULT_WINDOW_MS,
            );
            self.ratcheted_expected_tags.clear();
            // Ratcheted counter starts at 0
            for i in 0..TAG_WINDOW_SIZE {
                let tag = crypto::generate_resonance_tag(
                    &ratcheted_keys.tag_secret,
                    i as u64,
                    time_window,
                );
                self.ratcheted_expected_tags.insert(i as u64, tag);
            }
        }
    }

    /// Complete PFS ratchet: switch to ratcheted keys, zeroize old ones
    pub fn complete_ratchet(&mut self) {
        if let Some(ratcheted_keys) = self.ratcheted_keys.take() {
            self.keys = ratcheted_keys;
            self.counter = 0;
            self.send_counter = 0;
            self.tag_window_base = self.counter;
            self.expected_tags = std::mem::take(&mut self.ratcheted_expected_tags);
            self.received_bitmap.clear();
            self.pending_bytes_in = 0;
            self.pending_bytes_out = 0;
            self.is_ratcheted = true;
            self.server_eph_pub = None;
            self.server_hello_signature = None;
        }
    }

    /// Check and commit a pending mask if the grace period has elapsed.
    /// Returns true if a mask was committed.
    /// Grace period = 500ms — enough for the MaskUpdate packet to reach the client.
    pub fn commit_pending_mask(&mut self) -> bool {
        const MASK_GRACE_PERIOD: Duration = Duration::from_millis(500);
        if let Some((_, sent_at)) = &self.pending_mask {
            if sent_at.elapsed() >= MASK_GRACE_PERIOD {
                let (new_mask, _) = self.pending_mask.take().unwrap();
                info!("Committing deferred mask switch to '{}'", new_mask.mask_id);
                self.mask = Some(new_mask);
                // Reset FSM state for the new mask
                self.fsm_state = 0;
                self.fsm_packets = 0;
                self.fsm_state_start = Instant::now();
                return true;
            }
        }
        false
    }
}

/// Session Manager with O(1) tag lookup
pub struct SessionManager {
    /// Sessions by ID
    sessions: DashMap<[u8; 16], Arc<Mutex<Session>>>,
    /// Tag -> Session ID mapping for O(1) lookup
    tag_map: DashMap<[u8; TAG_SIZE], [u8; 16]>,
    /// VPN IP -> Session ID mapping for TUN return routing
    vpn_ip_map: DashMap<Ipv4Addr, [u8; 16]>,
    /// Next VPN IP to assign (last octet)
    next_ip_octet: AtomicU32,
    /// Server's long-term keypair
    server_keys: KeyPair,
    /// Server's signing key (Ed25519)
    signing_key: ed25519_dalek::SigningKey,
    /// Default mask profile
    default_mask: MaskProfile,
    /// Configurable session hard timeout
    hard_timeout: Duration,
    /// Configurable session idle timeout
    idle_timeout: Duration,
}

impl SessionManager {
    pub fn new(
        server_keys: KeyPair,
        signing_key: ed25519_dalek::SigningKey,
        default_mask: MaskProfile,
    ) -> Self {
        Self::with_timeouts(server_keys, signing_key, default_mask, None, None)
    }

    pub fn with_timeouts(
        server_keys: KeyPair,
        signing_key: ed25519_dalek::SigningKey,
        default_mask: MaskProfile,
        session_timeout_secs: Option<u64>,
        idle_timeout_secs: Option<u64>,
    ) -> Self {
        let hard_timeout = session_timeout_secs
            .map(|s| Duration::from_secs(s))
            .unwrap_or(HARD_TIMEOUT);
        let idle_timeout = idle_timeout_secs
            .map(|s| Duration::from_secs(s))
            .unwrap_or(IDLE_TIMEOUT);
        Self {
            sessions: DashMap::new(),
            tag_map: DashMap::new(),
            vpn_ip_map: DashMap::new(),
            next_ip_octet: AtomicU32::new(2),
            server_keys,
            signing_key,
            default_mask,
            hard_timeout,
            idle_timeout,
        }
    }
    
    /// Create new session from initial packet.
    /// NOTE: Does NOT remove old sessions for the same client IP.
    /// The caller must call `cleanup_old_sessions_for_ip()` after
    /// validating that the new session is legitimate (tag matches).
    pub fn create_session(
        &self,
        client_addr: SocketAddr,
        eph_pub: [u8; X25519_PUBLIC_KEY_SIZE],
        preshared_key: Option<[u8; 32]>,
        static_vpn_ip: Option<Ipv4Addr>,
    ) -> Result<Arc<Mutex<Session>>> {
        // Look for a reusable VPN IP from an existing session for the same
        // client IP, but do NOT remove the old session yet — the caller
        // will do that only after the handshake tag validates.
        let reused_vpn_ip: Option<Ipv4Addr> = self.sessions.iter()
            .filter_map(|entry| {
                let session = entry.value().lock();
                if session.client_addr.ip() == client_addr.ip() {
                    session.vpn_ip
                } else {
                    None
                }
            })
            .next();

        if self.sessions.len() >= MAX_SESSIONS {
            return Err(Error::Session("Max sessions reached".into()));
        }
        
        // MED-6: Per-IP session limit (max 5 sessions per IP)
        let ip_count = self.sessions.iter()
            .filter(|e| e.value().lock().client_addr.ip() == client_addr.ip())
            .count();
        if ip_count >= 5 {
            return Err(Error::Session("Per-IP session limit reached".into()));
        }
        
        // DH1: server_static * client_eph → initial keys (0-RTT)
        let dh1 = self.server_keys.compute_shared(&eph_pub)?;
        trace!("Server DH result: {}", hex::encode(&dh1));
        trace!("Server eph_pub (after deobfuscation): {}", hex::encode(&eph_pub));
        trace!("Server PSK: {:?}", preshared_key.as_ref().map(hex::encode));
        let initial_keys = crypto::derive_session_keys(
            &dh1,
            preshared_key.as_ref(),
            &eph_pub,
        );
        trace!("Server tag_secret: {}", hex::encode(&initial_keys.tag_secret));
        
        // --- CRIT-3 + HIGH-6: PFS ratchet preparation ---
        // Generate server ephemeral keypair
        let server_eph_kp = crypto::KeyPair::generate();
        let server_eph_pub = server_eph_kp.public_key_bytes();
        
        // DH2: server_eph * client_eph → PFS keys
        let dh2 = server_eph_kp.compute_shared(&eph_pub)?;
        // Use initial session_key as PSK for domain separation
        let ratcheted_keys = crypto::derive_session_keys(
            &dh2,
            Some(&initial_keys.session_key),
            &eph_pub,
        );
        
        // Sign (server_eph_pub || client_eph_pub) for server authentication (HIGH-6)
        use ed25519_dalek::Signer;
        let mut sign_message = Vec::with_capacity(64);
        sign_message.extend_from_slice(&server_eph_pub);
        sign_message.extend_from_slice(&eph_pub);
        let signature = self.signing_key.sign(&sign_message).to_bytes();
        
        // Generate session ID
        let mut session_id = [0u8; 16];
        OsRng.fill_bytes(&mut session_id);
        
        // Create session with initial (DH1) keys
        let session = Arc::new(Mutex::new(Session::new(
            session_id,
            client_addr,
            initial_keys,
            eph_pub,
        )));
        
        // Setup ratchet state + populate tag maps
        {
            let mut sess = session.lock();
            sess.state = SessionState::Active;
            
            // Store ratchet data
            sess.server_eph_pub = Some(server_eph_pub);
            sess.server_hello_signature = Some(signature);
            sess.ratcheted_keys = Some(ratcheted_keys);
            
            // Compute initial tags
            sess.update_tag_window();
            for tag in sess.expected_tags.values() {
                self.tag_map.insert(*tag, session_id);
            }
            
            // Pre-compute ratcheted tags (for when client switches to PFS keys)
            sess.update_ratcheted_tag_window();
            for tag in sess.ratcheted_expected_tags.values() {
                self.tag_map.insert(*tag, session_id);
            }
        }
        
        // Insert into session map
        self.sessions.insert(session_id, session.clone());
        
        // Assign VPN IP and register mapping.
        // Priority: 1) static IP from client config, 2) reused IP, 3) auto-assign
        let vpn_ip = static_vpn_ip.or(reused_vpn_ip).or_else(|| {
            let octet = self.next_ip_octet.fetch_add(1, Ordering::Relaxed);
            if octet <= 254 {
                Some(Ipv4Addr::new(10, 0, 0, octet as u8))
            } else {
                None
            }
        });

        if let Some(vpn_ip) = vpn_ip {
            session.lock().vpn_ip = Some(vpn_ip);
            self.vpn_ip_map.insert(vpn_ip, session_id);
            debug!("Assigned VPN IP {} to session", vpn_ip);
        }
        
        Ok(session)
    }

    /// Remove all sessions for a given IP except the specified one.
    /// Called after a new handshake is validated to clean up stale sessions.
    /// Returns list of removed session IDs (for stopping recordings).
    pub fn cleanup_old_sessions_for_ip(
        &self,
        ip: &std::net::IpAddr,
        keep_session_id: &[u8; 16],
    ) -> Vec<[u8; 16]> {
        let to_remove: Vec<[u8; 16]> = self.sessions.iter()
            .filter_map(|entry| {
                let session = entry.value().lock();
                if session.client_addr.ip() == *ip && entry.key() != keep_session_id {
                    Some(*entry.key())
                } else {
                    None
                }
            })
            .collect();

        let mut removed = Vec::new();
        for session_id in to_remove {
            info!("Removing stale session for IP {} after successful re-handshake", ip);
            if self.remove_session(&session_id).is_some() {
                removed.push(session_id);
            }
        }
        removed
    }

    /// Remove old sessions for the same VPN IP (same client) except the
    /// specified one. Unlike `cleanup_old_sessions_for_ip`, this does NOT
    /// affect sessions belonging to other clients behind the same NAT.
    /// Returns list of removed session IDs (for stopping recordings).
    pub fn cleanup_old_sessions_for_vpn_ip(
        &self,
        vpn_ip: &Ipv4Addr,
        keep_session_id: &[u8; 16],
    ) -> Vec<[u8; 16]> {
        let to_remove: Vec<[u8; 16]> = self.sessions.iter()
            .filter_map(|entry| {
                let session = entry.value().lock();
                if session.vpn_ip == Some(*vpn_ip) && entry.key() != keep_session_id {
                    Some(*entry.key())
                } else {
                    None
                }
            })
            .collect();

        let mut removed = Vec::new();
        for session_id in to_remove {
            info!("Removing stale session for VPN IP {} after successful re-handshake", vpn_ip);
            if self.remove_session(&session_id).is_some() {
                removed.push(session_id);
            }
        }
        removed
    }

    /// Rollback a session that was created but failed tag validation.
    /// Restores vpn_ip_map to the old session that still owns that IP.
    pub fn rollback_failed_session(&self, session_id: &[u8; 16]) {
        // Grab the VPN IP before removal so we can restore the old mapping.
        let vpn_ip = self.sessions.get(session_id)
            .map(|e| e.value().lock().vpn_ip)
            .flatten();

        self.remove_session(session_id);

        // If there is still another session that owns this VPN IP, restore it.
        if let Some(vpn_ip) = vpn_ip {
            for entry in self.sessions.iter() {
                let sess = entry.value().lock();
                if sess.vpn_ip == Some(vpn_ip) {
                    self.vpn_ip_map.insert(vpn_ip, *entry.key());
                    break;
                }
            }
        }
    }

    /// Return true when the same public IP already has a fresh ratcheted session
    /// on a different socket endpoint. This helps ignore stale duplicate-port
    /// probes instead of spawning a new handshake loop.
    pub fn has_recent_ratcheted_session_on_other_endpoint(
        &self,
        client_addr: &SocketAddr,
        max_age: Duration,
    ) -> bool {
        self.sessions.iter().any(|entry| {
            let sess = entry.value().lock();
            sess.client_addr.ip() == client_addr.ip()
                && sess.client_addr != *client_addr
                && sess.is_ratcheted
                && sess.last_seen.elapsed() <= max_age
        })
    }
    
    /// Get session by tag (O(1) lookup)
    pub fn get_session_by_tag(&self, tag: &[u8; TAG_SIZE]) -> Option<Arc<Mutex<Session>>> {
        if let Some(entry) = self.tag_map.get(tag) {
            let session_id = *entry;
            drop(entry);
            self.sessions.get(&session_id).map(|e| e.clone())
        } else {
            None
        }
    }

    /// Refresh tag windows for all sessions (time window may have advanced)
    /// and try to find a session matching the given tag.
    pub fn refresh_and_find_by_tag(&self, tag: &[u8; TAG_SIZE]) -> Option<(Arc<Mutex<Session>>, u64, bool)> {
        for entry in self.sessions.iter() {
            let session = entry.value().clone();
            let session_id = *entry.key();
            let mut sess = session.lock();

            // Refresh initial key tags
            let old_tags: Vec<[u8; TAG_SIZE]> = sess.expected_tags.values().cloned().collect();
            for old_tag in &old_tags {
                self.tag_map.remove(old_tag);
            }
            sess.update_tag_window();
            for t in sess.expected_tags.values() {
                self.tag_map.insert(*t, session_id);
            }

            // Refresh ratcheted key tags
            let old_ratcheted: Vec<[u8; TAG_SIZE]> = sess.ratcheted_expected_tags.values().cloned().collect();
            for old_tag in &old_ratcheted {
                self.tag_map.remove(old_tag);
            }
            sess.update_ratcheted_tag_window();
            for t in sess.ratcheted_expected_tags.values() {
                self.tag_map.insert(*t, session_id);
            }

            // Try to validate the tag now
            if let Some((counter, is_ratcheted)) = sess.validate_tag(tag) {
                drop(sess);
                return Some((session, counter, is_ratcheted));
            }
        }
        None
    }

    /// Wide-range counter recovery: brute-force search over a large counter
    /// range to recover from counter drift (e.g., client race condition).
    /// Only called when normal tag lookup + refresh both fail but a session
    /// exists for this client IP.
    pub fn recover_session_by_tag(
        &self,
        tag: &[u8; TAG_SIZE],
        client_ip: &std::net::IpAddr,
    ) -> Option<(Arc<Mutex<Session>>, u64, bool)> {
        let current_tw = crypto::compute_time_window(
            crypto::current_timestamp_ms(),
            DEFAULT_WINDOW_MS,
        );
        // Search up to 65536 counters ahead from the session's last known counter
        const RECOVERY_RANGE: u64 = 65536;

        for entry in self.sessions.iter() {
            let session = entry.value().clone();
            let session_id = *entry.key();
            let sess = session.lock();
            if sess.client_addr.ip() != *client_ip {
                continue;
            }

            let base = sess.counter;
            let tag_secret = &sess.keys.tag_secret;

            for tw_offset in [0i64, -1, 1] {
                let tw = (current_tw as i64 + tw_offset) as u64;
                for i in 0..RECOVERY_RANGE {
                    let c = base + i;
                    let expected = crypto::generate_resonance_tag(tag_secret, c, tw);
                    if bool::from(expected.ct_eq(tag)) {
                        info!(
                            "Counter recovery: found counter {} (drift={}) for session",
                            c, i
                        );
                        // Update tag window to the recovered counter
                        drop(sess);
                        {
                            let mut s = session.lock();
                            s.counter = c;
                            s.update_tag_window();
                        }
                        // Refresh tag_map
                        self.tag_map.retain(|_, id| id != &session_id);
                        let s = session.lock();
                        for t in s.expected_tags.values() {
                            self.tag_map.insert(*t, session_id);
                        }
                        drop(s);
                        return Some((session, c, false));
                    }
                }
            }
        }
        None
    }
    
    /// Get session by ID
    pub fn get_session(&self, session_id: &[u8; 16]) -> Option<Arc<Mutex<Session>>> {
        self.sessions.get(session_id).map(|e| e.clone())
    }
    
    /// Get session by VPN IP (for routing TUN responses back to clients)
    pub fn get_session_by_vpn_ip(&self, vpn_ip: &Ipv4Addr) -> Option<Arc<Mutex<Session>>> {
        if let Some(entry) = self.vpn_ip_map.get(vpn_ip) {
            let session_id = *entry;
            drop(entry);
            self.sessions.get(&session_id).map(|e| e.clone())
        } else {
            None
        }
    }
    
    /// Remove session and return its ID if it existed.
    /// The returned session_id can be used to stop active recording.
    pub fn remove_session(&self, session_id: &[u8; 16]) -> Option<[u8; 16]> {
        if let Some((_, session)) = self.sessions.remove(session_id) {
            let sess = session.lock();
            // Remove all tags from tag map (initial + ratcheted)
            for tag in sess.expected_tags.values() {
                self.tag_map.remove(tag);
            }
            for tag in sess.ratcheted_expected_tags.values() {
                self.tag_map.remove(tag);
            }
            // Remove VPN IP mapping only if it still points to THIS session.
            // A newer session may have already claimed the same VPN IP.
            if let Some(vpn_ip) = sess.vpn_ip {
                self.vpn_ip_map.remove_if(&vpn_ip, |_, sid| sid == session_id);
            }
            Some(*session_id)
        } else {
            None
        }
    }
    
    /// Refresh tag_map after session's tag window has been updated
    pub fn refresh_session_tags(&self, session_id: &[u8; 16]) {
        if let Some(session) = self.sessions.get(session_id) {
            let sess = session.lock();
            // Remove stale tags for this session
            self.tag_map.retain(|_, id| id != session_id);
            // Re-add current tags
            for tag in sess.expected_tags.values() {
                self.tag_map.insert(*tag, *session_id);
            }
            for tag in sess.ratcheted_expected_tags.values() {
                self.tag_map.insert(*tag, *session_id);
            }
        }
    }
    
    /// Complete PFS ratchet for a session: switch to ratcheted keys, remove old tags
    pub fn complete_session_ratchet(&self, session_id: &[u8; 16]) {
        if let Some(session) = self.sessions.get(session_id) {
            let mut sess = session.lock();
            // Remove old initial key tags from tag_map
            for tag in sess.expected_tags.values() {
                self.tag_map.remove(tag);
            }
            // Complete the ratchet (swaps keys, moves ratcheted_expected_tags → expected_tags)
            sess.complete_ratchet();
            // Re-add the now-active tags (which were the ratcheted tags)
            for tag in sess.expected_tags.values() {
                self.tag_map.insert(*tag, *session_id);
            }
        }
    }
    
    /// Cleanup expired sessions and return list of removed session IDs.
    /// The returned IDs can be used to stop active recordings.
    pub fn cleanup_expired(&self) -> Vec<[u8; 16]> {
        let expired: Vec<[u8; 16]> = self.sessions
            .iter()
            .filter(|e| {
                let sess = e.value().lock();
                sess.last_seen.elapsed() > self.idle_timeout
                    || (self.hard_timeout > Duration::ZERO
                        && sess.created_at.elapsed() > self.hard_timeout)
            })
            .map(|e| *e.key())
            .collect();
        
        let mut removed = Vec::new();
        for session_id in expired {
            if self.remove_session(&session_id).is_some() {
                removed.push(session_id);
            }
        }
        removed
    }
    
    /// Get active session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Log diagnostic information about all sessions and tag state
    pub fn log_session_diagnostics(&self, incoming_tag: &[u8; TAG_SIZE]) {
        let tag_map_size = self.tag_map.len();
        let current_tw = crypto::compute_time_window(
            crypto::current_timestamp_ms(),
            DEFAULT_WINDOW_MS,
        );
        info!("DIAG: tag_map_size={}, current_tw={}", tag_map_size, current_tw);
        for entry in self.sessions.iter() {
            let sess = entry.value().lock();
            let sid_hex = format!("{:02x}{:02x}{:02x}{:02x}", entry.key()[0], entry.key()[1], entry.key()[2], entry.key()[3]);
            let is_ratcheted = sess.is_ratcheted;
            let counter = sess.counter;
            let expected_count = sess.expected_tags.len();
            let ratcheted_count = sess.ratcheted_expected_tags.len();
            let has_ratcheted_keys = sess.ratcheted_keys.is_some();
            // Check if any expected tag matches (manually)
            let mut found = false;
            for (c, t) in &sess.expected_tags {
                if t == incoming_tag {
                    found = true;
                    info!("DIAG: Session {} — expected tag MATCHES at counter {}", sid_hex, c);
                    break;
                }
            }
            info!(
                "DIAG: Session {} — ratcheted={}, counter={}, expected_tags={}, ratcheted_tags={}, has_ratchet_keys={}, tag_matched={}",
                sid_hex, is_ratcheted, counter, expected_count, ratcheted_count, has_ratcheted_keys, found
            );
        }
    }
    
    /// Get server public key
    pub fn server_public_key(&self) -> [u8; X25519_PUBLIC_KEY_SIZE] {
        self.server_keys.public_key_bytes()
    }
    
    /// Sign mask data
    pub fn sign_mask(&self, mask_data: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        let signature = self.signing_key.sign(mask_data);
        signature.to_bytes()
    }
    
    /// Iterate over all sessions (for neural resonance checks)
    pub fn iter_sessions(&self) -> dashmap::iter::Iter<'_, [u8; 16], Arc<Mutex<Session>>> {
        self.sessions.iter()
    }
    
    /// Schedule a deferred mask switch for a session.
    /// The MaskUpdate control message has already been sent to the client;
    /// we store the new mask in `pending_mask` and let it activate after a
    /// grace period (see `commit_pending_mask`).
    pub fn update_session_mask(
        &self,
        session_id: &[u8; 16],
        new_mask: MaskProfile,
    ) -> Option<(Arc<Mutex<Session>>, SocketAddr)> {
        if let Some(session) = self.sessions.get(session_id) {
            let client_addr;
            {
                let mut sess = session.lock();
                info!("Session mask scheduled: {} → {} (grace period 500ms)", 
                    sess.mask.as_ref().map(|m| m.mask_id.as_str()).unwrap_or("default"),
                    new_mask.mask_id
                );
                // Don't switch immediately — store as pending
                sess.pending_mask = Some((new_mask, Instant::now()));
                sess.state = SessionState::Active;
                client_addr = sess.client_addr;
            }
            Some((session.clone(), client_addr))
        } else {
            None
        }
    }

    /// Build an encrypted MaskUpdate control packet for the given session.
    /// Returns the raw UDP datagram bytes ready to send.
    pub fn build_mask_update_packet(
        &self,
        session: &Arc<Mutex<Session>>,
        new_mask: &MaskProfile,
    ) -> Result<Vec<u8>> {
        use aivpn_common::crypto::encrypt_payload;

        // Serialize mask profile → mask_data (MessagePack to match client's rmp_serde::from_slice)
        let mask_data = rmp_serde::to_vec(new_mask)
            .map_err(|e| Error::Session(format!("Failed to serialize mask: {}", e)))?;

        // Sign mask_data with server's Ed25519 key
        let signature = self.sign_mask(&mask_data);

        // Build control payload
        let control = ControlPayload::MaskUpdate { mask_data, signature };
        let encoded = control.encode()?;

        let mut sess = session.lock();
        let inner_header = InnerHeader {
            inner_type: InnerType::Control,
            seq_num: sess.next_seq() as u16,
        };
        let mut inner_payload = inner_header.encode().to_vec();
        inner_payload.extend_from_slice(&encoded);

        // Encrypt (same logic as Gateway::build_packet)
        let (nonce, counter) = sess.next_send_nonce();
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

        let ciphertext = encrypt_payload(&sess.keys.session_key, &nonce, &padded)?;

        // Generate tag
        let time_window = crypto::compute_time_window(
            crypto::current_timestamp_ms(),
            DEFAULT_WINDOW_MS,
        );
        let tag = crypto::generate_resonance_tag(
            &sess.keys.tag_secret,
            counter,
            time_window,
        );

        // Wrap MaskUpdate in the session's current mask. The switch to `new_mask`
        // happens only after the packet is successfully delivered.
        let transport_mask = sess.mask.as_ref().unwrap_or(&self.default_mask);
        let mdh = if let Some(ref spec) = transport_mask.header_spec {
            let mut rng = rand::thread_rng();
            spec.generate(&mut rng)
        } else {
            transport_mask.header_template.clone()
        };

        // Assemble: TAG | MDH | ciphertext
        let mut packet = Vec::with_capacity(TAG_SIZE + mdh.len() + ciphertext.len());
        packet.extend_from_slice(&tag);
        packet.extend_from_slice(&mdh);
        packet.extend_from_slice(&ciphertext);

        Ok(packet)
    }
}
