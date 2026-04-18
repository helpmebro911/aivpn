use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use aivpn_common::error::{Error, Result};
use aivpn_common::mask::{
    current_unix_secs, derive_bootstrap_candidates, BootstrapDescriptor, MaskProfile,
};

const CACHE_FILE_NAME: &str = "bootstrap_descriptors.json";
const MAX_CACHED_DESCRIPTORS: usize = 8;

#[derive(Debug, Default, Serialize, Deserialize)]
struct BootstrapCacheFile {
    descriptors: Vec<BootstrapDescriptor>,
}

fn cache_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".aivpn");
    }
    std::env::temp_dir().join("aivpn")
}

fn cache_path() -> PathBuf {
    cache_dir().join(CACHE_FILE_NAME)
}

fn load_cache_file() -> BootstrapCacheFile {
    let path = cache_path();
    fs::read_to_string(path)
        .ok()
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default()
}

pub fn load_descriptors() -> Vec<BootstrapDescriptor> {
    let now = current_unix_secs();
    let mut descriptors = load_cache_file().descriptors;
    descriptors.retain(|descriptor| descriptor.expires_at.saturating_add(24 * 3600) >= now);
    descriptors.sort_by(|left, right| right.created_at.cmp(&left.created_at));
    descriptors
}

pub fn select_initial_mask(preshared_key: Option<&[u8; 32]>) -> Option<MaskProfile> {
    let now = current_unix_secs();
    for descriptor in load_descriptors() {
        if !descriptor.is_valid_at(now) {
            continue;
        }
        if let Some(mask) = derive_bootstrap_candidates(&descriptor, preshared_key).into_iter().next() {
            return Some(mask);
        }
    }
    None
}

pub fn store_descriptor(descriptor: BootstrapDescriptor) -> Result<()> {
    let mut cache = load_cache_file();
    cache.descriptors.retain(|existing| existing.descriptor_id != descriptor.descriptor_id);
    cache.descriptors.push(descriptor);
    cache.descriptors.sort_by(|left, right| right.created_at.cmp(&left.created_at));
    cache.descriptors.truncate(MAX_CACHED_DESCRIPTORS);

    let dir = cache_dir();
    fs::create_dir_all(&dir).map_err(Error::Io)?;
    let json = serde_json::to_string_pretty(&cache)
        .map_err(|e| Error::Session(format!("Failed to serialize bootstrap cache: {}", e)))?;
    fs::write(cache_path(), json).map_err(Error::Io)
}

pub fn store_verified_descriptor(
    descriptor: BootstrapDescriptor,
) -> Result<()> {
    store_descriptor(descriptor)
}

pub async fn refresh_from_urls(urls: &[String]) -> usize {
    let mut stored = 0usize;
    for url in urls {
        let Ok(response) = reqwest::get(url).await else {
            continue;
        };
        let Ok(body) = response.text().await else {
            continue;
        };

        let descriptors = serde_json::from_str::<Vec<BootstrapDescriptor>>(&body)
            .ok()
            .or_else(|| serde_json::from_str::<BootstrapDescriptor>(&body).ok().map(|descriptor| vec![descriptor]));

        let Some(descriptors) = descriptors else {
            continue;
        };

        for descriptor in descriptors {
            if store_verified_descriptor(descriptor).is_ok() {
                stored += 1;
            }
        }
    }
    stored
}