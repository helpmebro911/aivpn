//! Mimicry Engine
//! 
//! Shapes traffic to match Mask profile characteristics

use std::time::{Duration, Instant};
use rand::{Rng, RngCore, SeedableRng};
use rand::rngs::StdRng;
use tracing::debug;

use aivpn_common::crypto::{self, encrypt_payload, SessionKeys, TAG_SIZE, NONCE_SIZE, POLY1305_TAG_SIZE};
use aivpn_common::protocol::{AivpnPacket, InnerType, InnerHeader, ControlPayload, MAX_PACKET_SIZE};
use aivpn_common::mask::{MaskProfile, PaddingStrategy, SpoofProtocol};
use aivpn_common::error::{Error, Result};

// Real WAN uplinks are more sensitive to near-MTU UDP datagrams than local Docker paths.
// After stabilizing the counter/tag path, use a less conservative budget to recover throughput
// without going all the way back to 1500-byte outer datagrams.
const SAFE_OUTER_PACKET_BUDGET: usize = 1380;

/// Mimicry Engine state
pub struct MimicryState {
    pub current_state: u16,
    pub packets_in_state: u32,
    pub state_start: Instant,
    pub size_override: Option<aivpn_common::mask::SizeDistribution>,
    pub iat_override: Option<aivpn_common::mask::IATDistribution>,
    pub padding_override: Option<PaddingStrategy>,
}

/// Mimicry Engine for traffic shaping
pub struct MimicryEngine {
    mask: MaskProfile,
    state: MimicryState,
    rng: StdRng,
}

impl MimicryEngine {
    pub fn new(mask: MaskProfile) -> Self {
        let initial_state = mask.initial_state();
        Self {
            mask,
            state: MimicryState {
                current_state: initial_state,
                packets_in_state: 0,
                state_start: Instant::now(),
                size_override: None,
                iat_override: None,
                padding_override: None,
            },
            rng: StdRng::from_entropy(),
        }
    }
    
    /// Get current mask
    pub fn mask(&self) -> &MaskProfile {
        &self.mask
    }
    
    /// Update mask profile
    pub fn update_mask(&mut self, new_mask: MaskProfile) {
        debug!("Updating mask to {}", new_mask.mask_id);
        self.mask = new_mask;
        self.state = MimicryState {
            current_state: self.mask.initial_state(),
            packets_in_state: 0,
            state_start: Instant::now(),
            size_override: None,
            iat_override: None,
            padding_override: None,
        };
    }
    
    /// Sample target packet size from distribution
    pub fn sample_packet_size(&mut self) -> u16 {
        if let Some(override_dist) = &self.state.size_override {
            override_dist.sample(&mut self.rng)
        } else {
            self.mask.size_distribution.sample(&mut self.rng)
        }
    }
    
    /// Sample inter-arrival time
    pub fn sample_iat(&mut self) -> f64 {
        if let Some(override_iat) = &self.state.iat_override {
            override_iat.sample(&mut self.rng)
        } else {
            self.mask.iat_distribution.sample(&mut self.rng)
        }
    }
    
    /// Calculate padding length
    pub fn calc_padding(&mut self, payload_size: usize, target_size: u16) -> u16 {
        let strategy = self.state.padding_override.as_ref()
            .unwrap_or(&self.mask.padding_strategy);
        
        strategy.calc_padding(payload_size, target_size, &mut self.rng)
    }
    
    /// Apply timing delay (async)
    pub async fn apply_timing(&mut self) {
        let iat_ms = self.sample_iat();
        if iat_ms > 0.0 {
            tokio::time::sleep(Duration::from_secs_f64(iat_ms / 1000.0)).await;
        }
    }
    
    /// Update FSM state
    pub fn update_fsm(&mut self) {
        let duration_ms = self.state.state_start.elapsed().as_millis() as u64;
        let (new_state, size_override, iat_override, padding_override) = 
            self.mask.process_transition(
                self.state.current_state,
                self.state.packets_in_state,
                duration_ms,
            );
        
        if new_state != self.state.current_state {
            debug!("FSM transition: {} -> {}", self.state.current_state, new_state);
            self.state.current_state = new_state;
            self.state.packets_in_state = 0;
            self.state.state_start = Instant::now();
            self.state.size_override = size_override;
            self.state.iat_override = iat_override;
            self.state.padding_override = padding_override;
        }
        
        self.state.packets_in_state += 1;
    }
    
    /// Build Mask-Dependent Header
    pub fn build_mdh(&mut self, eph_pub: Option<&[u8; 32]>) -> Vec<u8> {
        let mut mdh = self.mask.header_template.clone();
        
        // Insert ephemeral public key if provided
        if let Some(eph) = eph_pub {
            let offset = self.mask.eph_pub_offset as usize;
            let len = self.mask.eph_pub_length as usize;
            
            // Extend MDH if eph_pub doesn't fit within header_template
            let required = offset + len;
            if mdh.len() < required {
                mdh.resize(required, 0);
            }
            mdh[offset..offset + len].copy_from_slice(eph);
        }
        
        mdh
    }
    
    /// Encrypt and shape packet
    /// Wire format: TAG | MDH | encrypt(pad_len_u16 || plaintext || random_padding)
    /// pad_len is inside encryption — invisible to DPI (fixes CRIT-5)
    pub fn build_packet(
        &mut self,
        plaintext: &[u8],
        keys: &SessionKeys,
        counter: &mut u64,
        eph_pub: Option<&[u8; 32]>,
    ) -> Result<Vec<u8>> {
        // Build MDH first (needed for overhead calculation)
        let mdh = self.build_mdh(eph_pub);

        // Determine padding: total = TAG + MDH + encrypt(2 + plaintext + padding)
        // encrypt adds POLY1305_TAG_SIZE bytes
        let target_size = self.sample_packet_size();
        let base_overhead = TAG_SIZE + mdh.len() + 2 + plaintext.len() + POLY1305_TAG_SIZE;
        let requested_pad_len = self.calc_padding(base_overhead, target_size);
        let packet_budget = SAFE_OUTER_PACKET_BUDGET.min(MAX_PACKET_SIZE);
        let max_pad_len = packet_budget.saturating_sub(base_overhead) as u16;
        let pad_len = requested_pad_len.min(max_pad_len);

        // Build padded plaintext: pad_len(u16) || plaintext || random_padding
        let mut padded = Vec::with_capacity(2 + plaintext.len() + pad_len as usize);
        padded.extend_from_slice(&pad_len.to_le_bytes());
        padded.extend_from_slice(plaintext);
        
        // OPTIMIZATION: Use batch random generation instead of per-byte
        padded.resize(2 + plaintext.len() + pad_len as usize, 0);
        self.rng.fill_bytes(&mut padded[2 + plaintext.len()..]);
        
        // Encrypt padded payload
        let packet_counter = *counter;
        let nonce = self.generate_nonce(packet_counter);
        let ciphertext = encrypt_payload(&keys.session_key, &nonce, &padded)?;
        
        // Generate resonance tag
        let time_window = crypto::compute_time_window(
            crypto::current_timestamp_ms(),
            aivpn_common::crypto::DEFAULT_WINDOW_MS,
        );
        let tag = crypto::generate_resonance_tag(&keys.tag_secret, packet_counter, time_window);
        *counter += 1;
        
        // Assemble packet: TAG | MDH | ciphertext (no cleartext pad_len or padding)
        let mut packet = Vec::with_capacity(TAG_SIZE + mdh.len() + ciphertext.len());
        packet.extend_from_slice(&tag);
        packet.extend_from_slice(&mdh);
        packet.extend_from_slice(&ciphertext);

        Ok(packet)
    }
    
    /// Generate nonce from counter
    fn generate_nonce(&self, counter: u64) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..8].copy_from_slice(&counter.to_le_bytes());
        nonce
    }
    
    /// Get spoof protocol
    pub fn spoof_protocol(&self) -> SpoofProtocol {
        self.mask.spoof_protocol
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aivpn_common::mask::preset_masks::webrtc_zoom_v3;
    use aivpn_common::crypto::SessionKeys;
    
    #[test]
    fn test_mimicry_engine() {
        let mask = webrtc_zoom_v3();
        let mut engine = MimicryEngine::new(mask);
        
        let keys = SessionKeys {
            session_key: [0u8; 32],
            tag_secret: [0u8; 32],
            prng_seed: [0u8; 32],
        };
        
        let mut counter = 0u64;
        let plaintext = b"Hello, World!";
        
        let packet = engine.build_packet(plaintext, &keys, &mut counter, None);
        assert!(packet.is_ok());
    }
}
