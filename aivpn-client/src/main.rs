//! AIVPN Client Binary - Full Implementation

use aivpn_client::AivpnClient;
use aivpn_client::client::ClientConfig;
use aivpn_client::tunnel::TunnelConfig;
use aivpn_common::mask::preset_masks::webrtc_zoom_v3;
use clap::Parser;
use tracing::{info, error, warn};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use base64::Engine;

/// AIVPN Client - Censorship-resistant VPN client
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct ClientArgs {
    /// Server address (e.g., 1.2.3.4:443)
    #[arg(short, long)]
    pub server: Option<String>,

    /// Server public key (base64, 32 bytes)
    #[arg(long)]
    pub server_key: Option<String>,

    /// Connection key (aivpn://...) — contains server, key, PSK, VPN IP
    #[arg(short = 'k', long)]
    pub connection_key: Option<String>,

    /// TUN device name (random if not specified)
    #[arg(long)]
    pub tun_name: Option<String>,

    /// TUN device address
    #[arg(long, default_value = "10.0.0.2")]
    pub tun_addr: String,

    /// Route all traffic through VPN tunnel
    #[arg(long, default_value_t = false)]
    pub full_tunnel: bool,

    /// Config file path (JSON)
    #[arg(long)]
    pub config: Option<String>,
}

// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() {
    // Initialize logging — default to INFO level when RUST_LOG is not set
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .init();

    // Setup Ctrl+C handler in a separate task
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to setup signal handler");
        info!("Received Ctrl+C, shutting down...");
        shutdown_clone.store(true, Ordering::SeqCst);
        SHUTDOWN.store(true, Ordering::SeqCst);
    });
    
    // Parse arguments
    let args = ClientArgs::parse();
    
    // Parse connection key or individual args
    let (server_addr, server_key_b64, psk_bytes, tun_addr) = if let Some(ref conn_key) = args.connection_key {
        let payload = conn_key.trim().strip_prefix("aivpn://").unwrap_or(conn_key.trim());
        let json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap_or_else(|e| {
                error!("Invalid connection key: {}", e);
                std::process::exit(1);
            });
        let json: serde_json::Value = serde_json::from_slice(&json_bytes)
            .unwrap_or_else(|e| {
                error!("Malformed connection key JSON: {}", e);
                std::process::exit(1);
            });
        let s = json["s"].as_str().unwrap_or_else(|| {
            error!("Connection key missing server address (\"s\")");
            std::process::exit(1);
        }).to_string();
        let k = json["k"].as_str().unwrap_or_else(|| {
            error!("Connection key missing server key (\"k\")");
            std::process::exit(1);
        }).to_string();
        let psk: Option<Vec<u8>> = json["p"].as_str().and_then(|p| {
            base64::engine::general_purpose::STANDARD.decode(p).ok()
        });
        let ip = json["i"].as_str().map(|i| i.to_string());
        (s, k, psk, ip.unwrap_or_else(|| args.tun_addr.clone()))
    } else {
        let server = args.server.clone().unwrap_or_else(|| {
            error!("Either --connection-key or --server + --server-key required");
            std::process::exit(1);
        });
        let key = args.server_key.clone().unwrap_or_else(|| {
            error!("Either --connection-key or --server + --server-key required");
            std::process::exit(1);
        });
        (server, key, None, args.tun_addr.clone())
    };
    
    info!("AIVPN Client v{}", env!("CARGO_PKG_VERSION"));
    info!("Connecting to server: {}", server_addr);
    
    // Parse server key
    let server_key_decoded = base64::engine::general_purpose::STANDARD
        .decode(&server_key_b64)
        .unwrap_or_else(|e| {
            error!("Invalid server key: {}", e);
            std::process::exit(1);
        });
    
    let mut server_public_key = [0u8; 32];
    if server_key_decoded.len() != 32 {
        error!("Server key must be 32 bytes, got {}", server_key_decoded.len());
        std::process::exit(1);
    }
    server_public_key.copy_from_slice(&server_key_decoded);

    // Parse PSK
    let preshared_key: Option<[u8; 32]> = psk_bytes.and_then(|v| {
        if v.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&v);
            Some(arr)
        } else {
            None
        }
    });
    
    let tun_name_fixed = args.tun_name.clone();
    let full_tunnel = args.full_tunnel;
    let tun_addr = tun_addr;

    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(60);

    loop {
        if shutdown.load(Ordering::SeqCst) {
            info!("Shutdown requested, stopping client loop");
            break;
        }

        // Use stable TUN name when user asked for it; otherwise generate fresh.
        // Fresh name avoids rare conflicts when previous TUN wasn't fully torn down yet.
        let tun_name = tun_name_fixed.clone().unwrap_or_else(|| {
            use rand::Rng;
            format!("tun{:04x}", rand::thread_rng().gen::<u16>())
        });

        let config = ClientConfig {
            server_addr: server_addr.clone(),
            server_public_key,
            preshared_key,
            initial_mask: webrtc_zoom_v3(),
            server_signing_pub: None,
            tun_config: TunnelConfig {
                tun_name: tun_name.clone(),
                tun_addr: tun_addr.clone(),
                tun_netmask: "255.255.255.0".to_string(),
                mtu: 1346,
                full_tunnel,
            },
        };

        match AivpnClient::new(config) {
            Ok(mut client) => {
                info!("Client initialized successfully (TUN: {})", tun_name);
                
                // Write initial stats file
                let _ = std::fs::write("/var/run/aivpn/traffic.stats", "sent:0,received:0");
                let _ = std::fs::write("/tmp/aivpn-traffic.stats", "sent:0,received:0");

                match client.run(shutdown.clone()).await {
                    Ok(()) => break,
                    Err(e) => {
                        warn!("Client run failed: {}. Reconnecting in {}s", e, backoff.as_secs());
                    }
                }
            }
            Err(e) => {
                error!("Failed to create client: {}. Reconnecting in {}s", e, backoff.as_secs());
            }
        }

        if shutdown.load(Ordering::SeqCst) {
            info!("Shutdown requested after failure");
            break;
        }

        tokio::time::sleep(backoff).await;
        backoff = std::cmp::min(backoff * 2, max_backoff);
    }
}
