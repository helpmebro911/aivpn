//! AIVPN Server Binary

use aivpn_server::{AivpnServer, ServerArgs, ClientDatabase};
use aivpn_server::gateway::GatewayConfig;
use aivpn_server::neural::NeuralConfig;
use aivpn_common::crypto;
use aivpn_common::mask::MaskProfile;
use aivpn_common::network_config::{
    netmask_to_prefix_len, ClientNetworkConfig, DEFAULT_VPN_MTU, VpnNetworkConfig,
};
use tracing::{info, error};
use clap::Parser;
use serde::Deserialize;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const DEFAULT_SERVER_CONFIG_PATH: &str = "/etc/aivpn/server.json";
const LOCAL_SERVER_CONFIG_PATH: &str = "config/server.json";

#[derive(Debug, Clone, Default, Deserialize)]
struct ServerFileConfig {
    listen_addr: Option<String>,
    tun_name: Option<String>,
    tun_addr: Option<Ipv4Addr>,
    tun_netmask: Option<Ipv4Addr>,
    network_config: Option<VpnNetworkConfig>,
    mask_dir: Option<String>,
    bootstrap_mask_files: Option<Vec<String>>,
    session_timeout_secs: Option<u64>,
    idle_timeout_secs: Option<u64>,
}

#[tokio::main]
async fn main() {
    // Parse arguments first (before logging for CLI commands)
    let args = ServerArgs::parse_from(std::env::args());

    let config_path = resolve_config_path(&args);
    let file_config = load_server_file_config(config_path.as_deref());
    let network_config = resolve_network_config(file_config.as_ref()).unwrap_or_else(|e| {
        eprintln!("Failed to resolve VPN network config: {}", e);
        std::process::exit(1);
    });
    let bootstrap_masks = load_bootstrap_masks(file_config.as_ref()).unwrap_or_else(|e| {
        eprintln!("Failed to load bootstrap masks: {}", e);
        std::process::exit(1);
    });

    // Load client database
    let clients_db_path = Path::new(&args.clients_db);
    let client_db = match ClientDatabase::load(clients_db_path, network_config) {
        Ok(db) => Arc::new(db),
        Err(e) => {
            eprintln!("Failed to load client database: {}", e);
            std::process::exit(1);
        }
    };

    // Handle CLI management commands (no logging needed)
    if let Some(ref name) = args.add_client {
        handle_add_client(&client_db, name, &args);
        return;
    }
    if let Some(ref id) = args.remove_client {
        handle_remove_client(&client_db, id);
        return;
    }
    if args.list_clients {
        handle_list_clients(&client_db);
        return;
    }
    if let Some(ref id) = args.show_client {
        handle_show_client(&client_db, id, &args);
        return;
    }

    // Initialize logging (only for server mode)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("aivpn_server=debug".parse().unwrap())
                .add_directive("aivpn_common=debug".parse().unwrap())
        )
        .init();

    info!("AIVPN Server v{}", env!("CARGO_PKG_VERSION"));
    info!("Starting server...");
    info!("Listening on: {}", args.listen);
    info!("Registered clients: {}", client_db.list_clients().len());
    info!(
        "Authoritative VPN subnet: {} (server {}, mtu {})",
        network_config.cidr_string(),
        network_config.server_vpn_ip,
        network_config.mtu,
    );

    // Load server private key from file if provided (HIGH-11)
    let server_private_key = if let Some(ref key_file) = args.key_file {
        let key_data = std::fs::read(key_file)
            .unwrap_or_else(|e| {
                error!("Failed to read key file '{}': {}", key_file, e);
                std::process::exit(1);
            });
        if key_data.len() != 32 {
            error!("Key file must be exactly 32 bytes, got {}", key_data.len());
            std::process::exit(1);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_data);
        info!("Loaded server key from file");
        let kp = crypto::KeyPair::from_private_key(key);
        let pub_bytes = kp.public_key_bytes();
        info!("Server public key (hex): {}", pub_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>());
        key
    } else {
        info!("No --key-file provided, server key will be ephemeral");
        [0u8; 32]
    };

    // Generate random TUN name if not specified (MED-1: avoids fingerprinting)
    let tun_name = args.tun_name.clone().or_else(|| file_config.as_ref().and_then(|config| config.tun_name.clone())).unwrap_or_else(|| {
        use rand::Rng;
        format!("tun{:04x}", rand::thread_rng().gen::<u16>())
    });

    let listen_addr = resolve_listen_addr(&args, file_config.as_ref());

    // Create config
    let config = GatewayConfig {
        listen_addr,
        per_ip_pps_limit: args.per_ip_pps_limit,
        tun_name,
        tun_addr: network_config.server_ip_string(),
        tun_netmask: network_config.netmask_string(),
        network_config,
        server_private_key,
        signing_key: [0u8; 64],
        enable_nat: true,
        enable_neural: true,
        neural_config: NeuralConfig::default(),
        client_db: Some(client_db),
        mask_dir: resolve_mask_dir(&args, file_config.as_ref()),
        session_timeout_secs: file_config.as_ref().and_then(|c| c.session_timeout_secs),
        idle_timeout_secs: file_config.as_ref().and_then(|c| c.idle_timeout_secs),
        bootstrap_masks,
    };

    // Create and run server
    match AivpnServer::new(config) {
        Ok(server) => {
            info!("Server initialized successfully");
            if let Err(e) = server.run().await {
                error!("Server error: {}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!("Failed to create server: {}", e);
            std::process::exit(1);
        }
    }
}

fn load_server_public_key(args: &ServerArgs) -> Option<[u8; 32]> {
    args.key_file.as_ref().and_then(|key_file| {
        let key_data = std::fs::read(key_file).ok()?;
        if key_data.len() != 32 { return None; }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_data);
        let kp = crypto::KeyPair::from_private_key(key);
        Some(kp.public_key_bytes())
    })
}

/// Build a connection key: aivpn://BASE64({"s":"host:port","k":"...","p":"...","i":"...","n":{...}})
fn build_connection_key(
    args: &ServerArgs,
    server_ip: &str,
    server_pub_b64: &str,
    psk_b64: &str,
    client_network_config: ClientNetworkConfig,
) -> String {
    use base64::Engine;
    let server_addr = build_connection_server_addr(args, server_ip);
    let json = serde_json::json!({
        "s": server_addr,
        "k": server_pub_b64,
        "p": psk_b64,
        "i": client_network_config.client_ip,
        "n": client_network_config,
    });
    let json_bytes = serde_json::to_string(&json).unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json_bytes.as_bytes());
    format!("aivpn://{}", encoded)
}

fn build_connection_server_addr(args: &ServerArgs, server_ip: &str) -> String {
    if server_ip.parse::<SocketAddr>().is_ok() {
        return server_ip.to_string();
    }

    let config_path = resolve_config_path(args);
    let file_config = load_server_file_config(config_path.as_deref());
    let listen_addr = resolve_listen_addr(args, file_config.as_ref());

    let port = listen_addr
        .parse::<SocketAddr>()
        .map(|addr| addr.port())
        .unwrap_or(443);

    format!("{}:{}", server_ip, port)
}

fn handle_add_client(db: &ClientDatabase, name: &str, args: &ServerArgs) {
    match db.add_client(name) {
        Ok(client) => {
            use base64::Engine;
            let psk_b64 = base64::engine::general_purpose::STANDARD.encode(&client.psk);
            let server_pub = load_server_public_key(args);
            let client_network_config = db.network_config().client_config(client.vpn_ip).unwrap();

            println!("✅ Client '{}' created!", name);
            println!("   ID:     {}", client.id);
            println!("   VPN IP: {}", client.vpn_ip);
            println!();

            if let (Some(pub_key), Some(ref server_ip)) = (server_pub, &args.server_ip) {
                let pub_b64 = base64::engine::general_purpose::STANDARD.encode(&pub_key);
                let conn_key = build_connection_key(args, server_ip, &pub_b64, &psk_b64, client_network_config);
                println!("══ Connection Key (paste into app) ══");
                println!();
                println!("{}", conn_key);
                println!();
            } else {
                if server_pub.is_none() {
                    eprintln!("⚠  --key-file not provided, cannot generate connection key");
                }
                if args.server_ip.is_none() {
                    eprintln!("⚠  --server-ip not provided, cannot generate connection key");
                    eprintln!("   Use: --server-ip YOUR_PUBLIC_IP or set AIVPN_SERVER_IP env var");
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to add client: {}", e);
            std::process::exit(1);
        }
    }
}

fn handle_remove_client(db: &ClientDatabase, id: &str) {
    // Allow removal by name too
    let actual_id = db.list_clients()
        .iter()
        .find(|c| c.id == id || c.name == id)
        .map(|c| c.id.clone());

    match actual_id {
        Some(cid) => {
            match db.remove_client(&cid) {
                Ok(()) => println!("✅ Client '{}' removed.", id),
                Err(e) => {
                    eprintln!("❌ Failed to remove: {}", e);
                    std::process::exit(1);
                }
            }
        }
        None => {
            eprintln!("❌ Client '{}' not found.", id);
            std::process::exit(1);
        }
    }
}

fn handle_list_clients(db: &ClientDatabase) {
    let clients = db.list_clients();
    if clients.is_empty() {
        println!("No registered clients.");
        println!();
        println!("Add a client: aivpn-server --add-client \"Phone\" --key-file /etc/aivpn/server.key");
        return;
    }

    println!("{:<18} {:<20} {:<12} {:<8} {:<12} {:<12} {}",
        "ID", "NAME", "VPN IP", "STATUS", "UPLOAD", "DOWNLOAD", "LAST SEEN");
    println!("{}", "-".repeat(100));

    for client in &clients {
        let status = if client.enabled { "active" } else { "disabled" };
        let upload = format_bytes(client.stats.bytes_out);
        let download = format_bytes(client.stats.bytes_in);
        let last_seen = client.stats.last_connected
            .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "never".to_string());

        println!("{:<18} {:<20} {:<12} {:<8} {:<12} {:<12} {}",
            client.id, client.name, client.vpn_ip, status, upload, download, last_seen);
    }
    println!();
    println!("Total: {} client(s)", clients.len());
}

fn handle_show_client(db: &ClientDatabase, id: &str, args: &ServerArgs) {
    let client = db.list_clients()
        .into_iter()
        .find(|c| c.id == id || c.name == id);

    match client {
        Some(client) => {
            use base64::Engine;
            let psk_b64 = base64::engine::general_purpose::STANDARD.encode(&client.psk);
            let server_pub = load_server_public_key(args);
            let client_network_config = db.network_config().client_config(client.vpn_ip);

            println!("Client: {} ({})", client.name, client.id);
            println!("  VPN IP:      {}", client.vpn_ip);
            println!("  Status:      {}", if client.enabled { "active" } else { "disabled" });
            println!("  Created:     {}", client.created_at.format("%Y-%m-%d %H:%M"));
            println!("  Connections: {}", client.stats.total_connections);
            println!("  Upload:      {}", format_bytes(client.stats.bytes_out));
            println!("  Download:    {}", format_bytes(client.stats.bytes_in));
            println!("  Last seen:   {}",
                client.stats.last_connected
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "never".to_string()));

            if let (Some(pub_key), Some(ref server_ip)) = (server_pub, &args.server_ip) {
                match client_network_config {
                    Ok(client_network_config) => {
                        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(&pub_key);
                        let conn_key = build_connection_key(args, server_ip, &pub_b64, &psk_b64, client_network_config);
                        println!();
                        println!("══ Connection Key ══");
                        println!();
                        println!("{}", conn_key);
                        println!();
                    }
                    Err(err) => {
                        eprintln!("⚠  Cannot generate connection key for this client under the current VPN subnet: {}", err);
                        eprintln!("   Client VPN IP: {}", client.vpn_ip);
                        eprintln!("   Current server subnet: {}", db.network_config().cidr_string());
                        eprintln!("   Reissue this client in the active subnet to get a new key.");
                    }
                }
            } else if args.server_ip.is_none() {
                eprintln!("⚠  --server-ip not provided, cannot generate connection key");
            }
        }
        None => {
            eprintln!("Client '{}' not found.", id);
            std::process::exit(1);
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn load_server_file_config(path: Option<&str>) -> Option<ServerFileConfig> {
    let path = path?;
    let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("Failed to read config file '{}': {}", path, e);
        std::process::exit(1);
    });
    Some(serde_json::from_str(&content).unwrap_or_else(|e| {
        eprintln!("Failed to parse config file '{}': {}", path, e);
        std::process::exit(1);
    }))
}

fn resolve_config_path(args: &ServerArgs) -> Option<String> {
    if let Some(path) = &args.config {
        return Some(path.clone());
    }

    [DEFAULT_SERVER_CONFIG_PATH, LOCAL_SERVER_CONFIG_PATH]
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
        .map(|path| path.to_string_lossy().into_owned())
}

fn resolve_network_config(file_config: Option<&ServerFileConfig>) -> aivpn_common::error::Result<VpnNetworkConfig> {
    let config = if let Some(file_config) = file_config {
        if let Some(network_config) = file_config.network_config {
            network_config
        } else {
            VpnNetworkConfig {
                server_vpn_ip: file_config.tun_addr.unwrap_or(Ipv4Addr::new(10, 0, 0, 1)),
                prefix_len: netmask_to_prefix_len(
                    file_config.tun_netmask.unwrap_or(Ipv4Addr::new(255, 255, 255, 0)),
                )?,
                mtu: DEFAULT_VPN_MTU,
            }
        }
    } else {
        VpnNetworkConfig::default()
    };

    config.validate()?;
    Ok(config)
}

fn resolve_listen_addr(args: &ServerArgs, file_config: Option<&ServerFileConfig>) -> String {
    if args.listen == "0.0.0.0:443" {
        file_config
            .and_then(|config| config.listen_addr.clone())
            .unwrap_or_else(|| args.listen.clone())
    } else {
        args.listen.clone()
    }
}

fn load_bootstrap_masks(file_config: Option<&ServerFileConfig>) -> Result<Vec<MaskProfile>, String> {
    let Some(files) = file_config.and_then(|config| config.bootstrap_mask_files.clone()) else {
        return Ok(Vec::new());
    };

    let mut masks = Vec::with_capacity(files.len());
    for file in files {
        let content = std::fs::read_to_string(&file)
            .map_err(|e| format!("{}: {}", file, e))?;
        let mask = serde_json::from_str::<MaskProfile>(&content)
            .map_err(|e| format!("{}: {}", file, e))?;
        masks.push(mask);
    }
    Ok(masks)
}

/// Resolve mask directory: CLI --mask-dir / env AIVPN_MASK_DIR → server.json "mask_dir" → default
const DEFAULT_MASK_DIR: &str = "/var/lib/aivpn/masks";

fn resolve_mask_dir(args: &ServerArgs, file_config: Option<&ServerFileConfig>) -> PathBuf {
    // CLI/env already handled by clap (env = "AIVPN_MASK_DIR")
    if let Some(ref dir) = args.mask_dir {
        return PathBuf::from(dir);
    }
    // server.json
    if let Some(ref dir) = file_config.and_then(|c| c.mask_dir.clone()) {
        return PathBuf::from(dir);
    }
    PathBuf::from(DEFAULT_MASK_DIR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn test_args(listen: &str) -> ServerArgs {
        ServerArgs {
            listen: listen.to_string(),
            tun_name: None,
            key_file: None,
            config: None,
            clients_db: "/tmp/clients.json".to_string(),
            add_client: None,
            remove_client: None,
            list_clients: false,
            show_client: None,
            server_ip: None,
            per_ip_pps_limit: 1000,
            mask_dir: None,
        }
    }

    #[test]
    fn build_connection_server_addr_keeps_explicit_port() {
        let args = test_args("0.0.0.0:443");
        assert_eq!(build_connection_server_addr(&args, "203.0.113.10:8443"), "203.0.113.10:8443");
    }

    #[test]
    fn build_connection_server_addr_adds_listen_port_once() {
        let args = test_args("0.0.0.0:443");
        assert_eq!(build_connection_server_addr(&args, "203.0.113.10"), "203.0.113.10:443");
    }

    #[test]
    fn build_connection_key_embeds_normalized_server_addr() {
        let args = test_args("0.0.0.0:443");
        let key = build_connection_key(
            &args,
            "203.0.113.10:8443",
            "server-key",
            "psk",
            ClientNetworkConfig {
                client_ip: Ipv4Addr::new(10, 0, 0, 2),
                server_vpn_ip: Ipv4Addr::new(10, 0, 0, 1),
                prefix_len: 24,
                mtu: 1346,
                mdh_len: 20,
            },
        );
        let payload = key.strip_prefix("aivpn://").unwrap();
        let json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();

        assert_eq!(json["s"], "203.0.113.10:8443");
        assert_eq!(json["n"]["prefix_len"], 24);
    }

    #[test]
    fn resolve_network_config_prefers_network_config_block() {
        let file_config = ServerFileConfig {
            listen_addr: None,
            tun_name: None,
            tun_addr: Some(Ipv4Addr::new(10, 0, 0, 1)),
            tun_netmask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            network_config: Some(VpnNetworkConfig {
                server_vpn_ip: Ipv4Addr::new(10, 150, 0, 1),
                prefix_len: 24,
                mtu: 1400,
            }),
            mask_dir: None,
            bootstrap_mask_files: None,
            session_timeout_secs: None,
            idle_timeout_secs: None,
        };

        let resolved = resolve_network_config(Some(&file_config)).unwrap();
        assert_eq!(resolved.server_vpn_ip, Ipv4Addr::new(10, 150, 0, 1));
        assert_eq!(resolved.mtu, 1400);
    }
}
