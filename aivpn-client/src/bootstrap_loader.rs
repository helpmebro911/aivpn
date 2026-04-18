//! Multi-channel Bootstrap Descriptor Loader
//!
//! Implements resilient bootstrap descriptor distribution across multiple channels
//! to prevent single-point-of-failure blocking by censors.

use std::time::Duration;
use rand::{Rng, prelude::SliceRandom};
use serde::{Deserialize, Serialize};

use aivpn_common::error::{Error, Result};
pub use aivpn_common::mask::{BootstrapChannel, BootstrapConfig, BootstrapDescriptor};

use crate::bootstrap_cache::{store_verified_descriptor, load_descriptors};

/// Result from a single channel load attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelLoadResult {
    pub channel_name: String,
    pub channel_type: String,
    pub success: bool,
    pub descriptors_loaded: usize,
    pub error: Option<String>,
    pub latency_ms: u64,
}

/// Statistics from multi-channel loading
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiChannelLoadStats {
    pub total_channels: usize,
    pub successful_channels: usize,
    pub total_descriptors: usize,
    pub results: Vec<ChannelLoadResult>,
    pub elapsed_ms: u64,
}

/// Load descriptors from a CDN channel
async fn load_from_cdn(url: &str) -> Result<Vec<BootstrapDescriptor>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| Error::Session(format!("Failed to create HTTP client: {}", e)))?;
    
    let response = client.get(url)
        .send()
        .await
        .map_err(|e| Error::Session(format!("CDN request failed: {}", e)))?;
    
    if !response.status().is_success() {
        return Err(Error::Session(format!("CDN returned status: {}", response.status())));
    }
    
    let body = response.text().await
        .map_err(|e| Error::Session(format!("Failed to read CDN response: {}", e)))?;
    
    parse_descriptors_from_json(&body)
}

/// Load descriptors from a Telegram bot channel
async fn load_from_telegram(
    bot_username: &str, 
    token: Option<&str>,

) -> Result<Vec<BootstrapDescriptor>> {
    // Telegram bot API endpoint
    let api_url = match token {
        Some(t) => format!("https://api.telegram.org/bot{}/getUpdates", t),
        None => format!("https://t.me/{}?format=json", bot_username),
    };
    
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| Error::Session(format!("Failed to create HTTP client: {}", e)))?;
    
    let response = client.get(&api_url)
        .send()
        .await
        .map_err(|e| Error::Session(format!("Telegram request failed: {}", e)))?;
    
    if !response.status().is_success() {
        return Err(Error::Session(format!("Telegram returned status: {}", response.status())));
    }
    
    let body = response.text().await
        .map_err(|e| Error::Session(format!("Failed to read Telegram response: {}", e)))?;
    
    // Telegram may wrap descriptors in a message structure
    // Try to extract JSON from the response
    parse_descriptors_from_json(&body)
}

/// Load descriptors from a GitHub releases channel
async fn load_from_github(
    repo: &str,
    asset_name: &str,

) -> Result<Vec<BootstrapDescriptor>> {
    let url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        repo
    );
    
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::USER_AGENT,
                reqwest::header::HeaderValue::from_static("aivpn-client"),
            );
            headers
        })
        .build()
        .map_err(|e| Error::Session(format!("Failed to create HTTP client: {}", e)))?;
    
    let response = client.get(&url)
        .send()
        .await
        .map_err(|e| Error::Session(format!("GitHub request failed: {}", e)))?;
    
    if !response.status().is_success() {
        return Err(Error::Session(format!("GitHub returned status: {}", response.status())));
    }
    
    let body = response.text().await
        .map_err(|e| Error::Session(format!("Failed to read GitHub response: {}", e)))?;
    
    // Parse release JSON to find asset URL
    let release: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| Error::Session(format!("Failed to parse GitHub release: {}", e)))?;
    
    if let Some(assets) = release.get("assets").and_then(|a| a.as_array()) {
        for asset in assets {
            if let Some(name) = asset.get("name").and_then(|n| n.as_str()) {
                if name.contains(asset_name) || asset_name.contains(name) {
                    if let Some(download_url) = asset.get("browser_download_url").and_then(|u| u.as_str()) {
                        // Download the asset
                        let asset_response = client.get(download_url)
                            .send()
                            .await
                            .map_err(|e| Error::Session(format!("Failed to download asset: {}", e)))?;
                        
                        let asset_body = asset_response.text().await
                            .map_err(|e| Error::Session(format!("Failed to read asset: {}", e)))?;
                        
                        return parse_descriptors_from_json(&asset_body);
                    }
                }
            }
        }
    }
    
    Err(Error::Session(format!("Asset '{}' not found in GitHub release", asset_name)))
}

/// Load descriptors from an IPFS channel
async fn load_from_ipfs(
    hash: &str,
    gateway: Option<&str>,

) -> Result<Vec<BootstrapDescriptor>> {
    let url = match gateway {
        Some(g) => format!("{}/ipfs/{}", g, hash),
        None => format!("https://ipfs.io/ipfs/{}", hash),
    };
    
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| Error::Session(format!("Failed to create HTTP client: {}", e)))?;
    
    let response = client.get(&url)
        .send()
        .await
        .map_err(|e| Error::Session(format!("IPFS request failed: {}", e)))?;
    
    if !response.status().is_success() {
        return Err(Error::Session(format!("IPFS returned status: {}", response.status())));
    }
    
    let body = response.text().await
        .map_err(|e| Error::Session(format!("Failed to read IPFS response: {}", e)))?;
    
    parse_descriptors_from_json(&body)
}

/// Load descriptors from an Email channel (simulated - actual implementation would use SMTP/IMAP)
async fn load_from_email(
    _address: &str,
    _subject_pattern: &str,

) -> Result<Vec<BootstrapDescriptor>> {
    // Email-based loading would require integration with mail servers
    // For now, this is a placeholder that returns an error
    Err(Error::Session("Email channel not yet implemented".into()))
}

/// Parse descriptors from JSON body
fn parse_descriptors_from_json(
    body: &str,

) -> Result<Vec<BootstrapDescriptor>> {
    // Try parsing as array first
    let descriptors: Vec<BootstrapDescriptor> = serde_json::from_str(body)
        .or_else(|_| {
            // Try parsing as single object
            let single: BootstrapDescriptor = serde_json::from_str(body)?;
            Ok(vec![single])
        })
        .map_err(|e: serde_json::Error| Error::Session(format!("Failed to parse descriptors: {}", e)))?;
    
    // Verify each descriptor
    let mut valid_descriptors = Vec::new();
    for descriptor in descriptors {
        if store_verified_descriptor(descriptor.clone()).is_ok() {
            valid_descriptors.push(descriptor);
        }
    }
    
    Ok(valid_descriptors)
}

/// Load descriptors from a single channel
async fn load_from_channel(
    channel: &BootstrapChannel,

) -> ChannelLoadResult {
    let start = std::time::Instant::now();
    
    let result = match channel {
        BootstrapChannel::CDN { url, provider: _ } => {
            load_from_cdn(url).await
        }
        BootstrapChannel::Telegram { bot_username, token } => {
            load_from_telegram(bot_username, token.as_deref()).await
        }
        BootstrapChannel::GitHub { repo, asset_name } => {
            load_from_github(repo, asset_name).await
        }
        BootstrapChannel::IPFS { hash, gateway } => {
            load_from_ipfs(hash, gateway.as_deref()).await
        }
        BootstrapChannel::Email { address, subject_pattern } => {
            load_from_email(address, subject_pattern).await
        }
    };
    
    let latency_ms = start.elapsed().as_millis() as u64;
    
    match result {
        Ok(descriptors) => ChannelLoadResult {
            channel_name: channel.name().to_string(),
            channel_type: channel.channel_type().to_string(),
            success: true,
            descriptors_loaded: descriptors.len(),
            error: None,
            latency_ms,
        },
        Err(e) => ChannelLoadResult {
            channel_name: channel.name().to_string(),
            channel_type: channel.channel_type().to_string(),
            success: false,
            descriptors_loaded: 0,
            error: Some(e.to_string()),
            latency_ms,
        },
    }
}

/// Load descriptors from all channels with random order
pub async fn load_multi_channel(
    config: &BootstrapConfig,

) -> MultiChannelLoadStats {
    let start = std::time::Instant::now();
    
    // Randomize channel order to prevent pattern detection
    let mut channels: Vec<_> = config.channels.iter().collect();
    let mut rng = rand::thread_rng();
    channels.shuffle(&mut rng);
    
    let mut results = Vec::new();
    let mut total_descriptors = 0;
    
    for channel in channels {
        let result = load_from_channel(channel).await;
        total_descriptors += result.descriptors_loaded;
        results.push(result);
    }
    
    let successful_channels = results.iter().filter(|r| r.success).count();
    let elapsed_ms = start.elapsed().as_millis() as u64;
    
    MultiChannelLoadStats {
        total_channels: results.len(),
        successful_channels,
        total_descriptors,
        results,
        elapsed_ms,
    }
}

/// Check if we have valid descriptors in cache
pub fn has_valid_descriptors() -> bool {
    !load_descriptors().is_empty()
}

/// Get random delay for first refresh (1-60 seconds)
pub fn random_first_refresh_delay() -> Duration {
    let mut rng = rand::thread_rng();
    Duration::from_secs(rng.gen_range(1..=60))
}

/// Background descriptor refresher
pub struct BackgroundRefresher {
    config: BootstrapConfig,

}

impl BackgroundRefresher {
    pub fn new(config: BootstrapConfig) -> Self {
        Self {
            config,

        }
    }
    
    /// Run the background refresher loop
    pub async fn run(&self) {
        // Random delay before first refresh
        if self.config.randomize_first_refresh {
            let delay = random_first_refresh_delay();
            tokio::time::sleep(delay).await;
        }
        
        let mut interval = tokio::time::interval(Duration::from_secs(self.config.refresh_interval));
        
        loop {
            interval.tick().await;
            
            // Skip if we already have valid descriptors and min channels succeeded
            if has_valid_descriptors() {
                continue;
            }
            
            // Load from multiple channels
            let stats = load_multi_channel(&self.config).await;
            
            tracing::info!(
                "Bootstrap refresh: {}/{} channels succeeded, {} descriptors loaded in {}ms",
                stats.successful_channels,
                stats.total_channels,
                stats.total_descriptors,
                stats.elapsed_ms
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bootstrap_channel_names() {
        let cdn = BootstrapChannel::CDN {
            url: "https://cdn.example.com/descriptors".to_string(),
            provider: "Cloudflare".to_string(),
        };
        assert_eq!(cdn.name(), "Cloudflare");
        assert_eq!(cdn.channel_type(), "CDN");
        
        let telegram = BootstrapChannel::Telegram {
            bot_username: "@aivpn_bot".to_string(),
            token: None,
        };
        assert_eq!(telegram.name(), "@aivpn_bot");
        assert_eq!(telegram.channel_type(), "Telegram");
    }
    
    #[test]
    fn test_bootstrap_config_builder() {
        let config = BootstrapConfig::default()
            .with_cdn("https://cdn.example.com", "Cloudflare")
            .with_telegram("@aivpn_bot")
            .with_github("infosave2007/aivpn", "bootstrap-")
            .with_ipfs("QmTest123");
        
        assert_eq!(config.channels.len(), 4);
        assert_eq!(config.channels[0].channel_type(), "CDN");
        assert_eq!(config.channels[1].channel_type(), "Telegram");
        assert_eq!(config.channels[2].channel_type(), "GitHub");
        assert_eq!(config.channels[3].channel_type(), "IPFS");
    }
}
