//! Tunnel Module - Cross-platform TUN Device Integration
//! 
//! Supports Linux, macOS and Windows.
//! Handles TUN device creation, packet capture, and routing.

use std::io;
use tokio::io::AsyncWriteExt;
use tracing::{info, debug, error};

use aivpn_common::error::{Error, Result};
use aivpn_common::network_config::{ClientNetworkConfig, LEGACY_SERVER_VPN_IP, VpnNetworkConfig};

// Keep the full encrypted outer datagram within SAFE_OUTER_PACKET_BUDGET=1380.
// Outer overhead is 34 bytes: TAG(16) + MDH(4) + pad_len(2) + Poly1305(16) -
// the inner header is part of the plaintext payload, so the TUN MTU must leave
// room for it as well.
const WAN_SAFE_TUN_MTU: u16 = 1346;

/// Tunnel configuration
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    pub tun_name: String,
    pub tun_addr: String,
    pub server_vpn_ip: String,
    pub tun_netmask: String,
    pub prefix_len: u8,
    pub mtu: u16,
    /// Route all traffic through VPN (full tunnel mode)
    pub full_tunnel: bool,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        use rand::Rng;
        Self {
            tun_name: format!("tun{:04x}", rand::thread_rng().gen::<u16>()),
            tun_addr: "10.0.0.2".to_string(),
            server_vpn_ip: LEGACY_SERVER_VPN_IP.to_string(),
            tun_netmask: "255.255.255.0".to_string(),
            prefix_len: 24,
            mtu: WAN_SAFE_TUN_MTU,
            full_tunnel: false,
        }
    }
}

impl TunnelConfig {
    pub fn from_network_config(
        tun_name: String,
        network_config: ClientNetworkConfig,
        full_tunnel: bool,
    ) -> Self {
        Self {
            tun_name,
            tun_addr: network_config.client_ip.to_string(),
            server_vpn_ip: network_config.server_vpn_ip.to_string(),
            tun_netmask: network_config.netmask_string(),
            prefix_len: network_config.prefix_len,
            mtu: network_config.mtu,
            full_tunnel,
        }
    }

    pub fn client_network_config(&self) -> Result<ClientNetworkConfig> {
        let client_ip = self.configured_client_ip()?;
        let server_vpn_ip = self.configured_server_vpn_ip()?;
        let network_config = ClientNetworkConfig {
            client_ip,
            server_vpn_ip,
            prefix_len: self.prefix_len,
            mtu: self.mtu,
            mdh_len: 20,
        };
        network_config.validate()?;
        Ok(network_config)
    }

    fn configured_client_ip(&self) -> Result<std::net::Ipv4Addr> {
        self.tun_addr.parse().map_err(|e| Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid configured client IP {}: {}", self.tun_addr, e),
        )))
    }

    fn configured_server_vpn_ip(&self) -> Result<std::net::Ipv4Addr> {
        self.server_vpn_ip.parse().map_err(|e| Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Invalid configured server VPN IP {}: {}", self.server_vpn_ip, e),
        )))
    }

    fn vpn_network_config(&self) -> Result<VpnNetworkConfig> {
        let network_config = VpnNetworkConfig {
            server_vpn_ip: self.configured_server_vpn_ip()?,
            prefix_len: self.prefix_len,
            mtu: self.mtu,
        };
        network_config.validate()?;
        Ok(network_config)
    }
}

/// TUN Tunnel for packet capture
pub struct Tunnel {
    config: TunnelConfig,
    reader: Option<tun::DeviceReader>,
    writer: Option<tun::DeviceWriter>,
    /// Saved default gateway for full-tunnel restore
    saved_default_gw: Option<String>,
    /// Server IP for bypass route cleanup
    server_ip: Option<String>,
    /// Active IPv6 interface name saved before we add the blackhole route.
    /// Used to restore the route on disconnect instead of guessing (e.g. hard-coding en0).
    saved_ipv6_iface: Option<String>,
    /// Windows: wintun adapter interface index for explicit route binding.
    /// Without this, `route add` may bind VPN routes to the physical NIC.
    wintun_if_index: Option<String>,
}

impl Tunnel {
    pub fn new(config: TunnelConfig) -> Self {
        Self {
            config,
            reader: None,
            writer: None,
            saved_default_gw: None,
            server_ip: None,
            saved_ipv6_iface: None,
            wintun_if_index: None,
        }
    }

    #[cfg(target_os = "windows")]
    fn windows_command_output(output: &std::process::Output) -> String {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

        match (stdout.is_empty(), stderr.is_empty()) {
            (false, false) => format!("{} | {}", stdout, stderr),
            (false, true) => stdout,
            (true, false) => stderr,
            (true, true) => format!("route exited with status {}", output.status),
        }
    }

    #[cfg(target_os = "windows")]
    fn run_windows_route(args: &[&str], context: &str) -> Result<std::process::Output> {
        std::process::Command::new("route")
            .args(args)
            .output()
            .map_err(|e| Error::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to run route for {}: {}", context, e),
            )))
    }

    #[cfg(target_os = "windows")]
    fn add_windows_route_with_retry(
        &self,
        add_args: &[&str],
        delete_args: &[&str],
        success_message: &str,
        context: &str,
    ) -> Result<()> {
        let first_attempt = Self::run_windows_route(add_args, context)?;
        if first_attempt.status.success() {
            info!("{}", success_message);
            return Ok(());
        }

        let first_error = Self::windows_command_output(&first_attempt);
        debug!("Initial route add failed for {}: {}", context, first_error);

        let delete_attempt = Self::run_windows_route(delete_args, context)?;
        if !delete_attempt.status.success() {
            debug!(
                "Route delete before retry failed for {}: {}",
                context,
                Self::windows_command_output(&delete_attempt)
            );
        }

        let retry_attempt = Self::run_windows_route(add_args, context)?;
        if retry_attempt.status.success() {
            info!("{}", success_message);
            return Ok(());
        }

        Err(Error::Io(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Failed to configure {} after retry: {}",
                context,
                Self::windows_command_output(&retry_attempt)
            ),
        )))
    }
    
    /// Create TUN device (works on Linux, macOS, Windows)
    pub fn create(&mut self) -> Result<()> {
        let mut config_builder = tun::Configuration::default();
        
        config_builder
            .address(&self.config.tun_addr)
            .netmask(&self.config.tun_netmask)
            .mtu(self.config.mtu)
            .up();
        
        #[cfg(target_os = "macos")]
        {
            // Disable tun crate's automatic routing — it generates invalid CIDR
            // notation (e.g. "route -n add -net 10.0.0.4/24") which macOS route(8)
            // does not support.  We handle routing ourselves in configure_macos()
            // using the correct "-netmask" syntax.
            config_builder.platform_config(|config| {
                config.enable_routing(false);
            });
        }

        #[cfg(target_os = "linux")]
        {
            config_builder.name(&self.config.tun_name);
            config_builder.platform_config(|config| {
                config.ensure_root_privileges(true);
            });
        }
        
        #[cfg(target_os = "windows")]
        {
            // Windows uses wintun driver; name is set via platform_config
            config_builder.platform_config(|config| {
                config.device_guid(9099482345783245345u128);
            });
        }
        
        let dev = tun::create_as_async(&config_builder)
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other, e.to_string())))?;
        
        // Get actual device name before split (on macOS, name is assigned by kernel as utunN)
        if let Ok(actual_name) = tun::AbstractDevice::tun_name(&*dev) {
            self.config.tun_name = actual_name;
        }
        
        // Split into independent reader/writer — no Mutex needed for concurrent I/O
        let (writer, reader) = dev.split()
            .map_err(Error::Io)?;
        self.reader = Some(reader);
        self.writer = Some(writer);
        
        info!(
            "Created TUN device: {} ({}/{})",
            self.config.tun_name,
            self.config.tun_addr,
            self.config.tun_netmask
        );
        
        // Platform-specific post-creation configuration
        #[cfg(target_os = "macos")]
        self.configure_macos()?;
        
        #[cfg(target_os = "linux")]
        self.configure_linux()?;
        
        #[cfg(target_os = "windows")]
        {
            self.wintun_if_index = self.find_wintun_interface_index();
            if let Some(ref idx) = self.wintun_if_index {
                info!("Wintun interface index: {}", idx);
            } else {
                error!("Could not determine wintun interface index — routes may bind to wrong adapter");
            }
            self.configure_windows()?;
        }
        
        Ok(())
    }

    pub fn apply_network_config(&mut self, network_config: ClientNetworkConfig) -> Result<()> {
        network_config.validate()?;
        self.config.tun_addr = network_config.client_ip.to_string();
        self.config.server_vpn_ip = network_config.server_vpn_ip.to_string();
        self.config.tun_netmask = network_config.netmask_string();
        self.config.prefix_len = network_config.prefix_len;
        self.config.mtu = network_config.mtu;

        if self.reader.is_none() && self.writer.is_none() {
            return Ok(());
        }

        #[cfg(target_os = "macos")]
        self.configure_macos()?;

        #[cfg(target_os = "linux")]
        self.configure_linux()?;

        #[cfg(target_os = "windows")]
        self.configure_windows()?;

        Ok(())
    }
    
    // ──────────────────── macOS ────────────────────
    
    /// Configure TUN device on macOS (ifconfig + route)
    #[cfg(target_os = "macos")]
    fn configure_macos(&mut self) -> Result<()> {
        use std::process::Command;
        
        let tun_name = &self.config.tun_name;
        let tun_addr = &self.config.tun_addr;
        let peer_addr = &self.config.server_vpn_ip;
        let vpn_network = self.config.vpn_network_config()?;
        let vpn_network_addr = vpn_network.network_addr().to_string();
        let tun_netmask = self.config.tun_netmask.clone();
        
        // Set point-to-point addresses with explicit netmask
        let status = Command::new("/sbin/ifconfig")
            .args([tun_name, "inet", tun_addr, peer_addr, "netmask", &tun_netmask, "mtu", &self.config.mtu.to_string(), "up"])
            .status()
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other, 
                format!("Failed to run ifconfig: {}", e))))?;
        
        if !status.success() {
            error!("ifconfig failed with status: {}", status);
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("ifconfig failed: {}", status),
            )));
        } else {
            info!("Configured {} with {} -> {} (netmask {})", tun_name, tun_addr, peer_addr, tun_netmask);
        }
        
        // Delete any stale routes to prevent conflicts
        info!("Cleaning up stale routes...");
        let _ = Command::new("/sbin/route").args(["-n", "delete", "-host", peer_addr]).status();
        let _ = Command::new("/sbin/route").args(["-n", "delete", "-net", &vpn_network_addr, "-netmask", &tun_netmask]).status();
        
        // Small delay to ensure routes are cleaned up
        std::thread::sleep(std::time::Duration::from_millis(100));
        
        // Add host route for the peer (10.0.0.1) - REQUIRED for point-to-point
        info!("Adding host route for peer {} via {}", peer_addr, tun_name);
        let status = Command::new("/sbin/route")
            .args(["-n", "add", "-host", peer_addr, "-interface", tun_name])
            .status()
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other, 
                format!("Failed to add host route: {}", e))))?;
        
        if !status.success() {
            error!("route add -host {} failed with status: {}", peer_addr, status);
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to add host route: {}", status),
            )));
        } else {
            info!("✓ Added host route {} via {}", peer_addr, tun_name);
        }
        
        // Add subnet route for 10.0.0.0/24
        info!("Adding subnet route {}/{} via {} (gateway {})", vpn_network_addr, self.config.prefix_len, tun_name, tun_addr);
        let status = Command::new("/sbin/route")
            .args(["-n", "add", "-net", &vpn_network_addr, "-netmask", &tun_netmask, tun_addr])
            .status()
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other,
                format!("Failed to add subnet route: {}", e))))?;

        if !status.success() {
            error!("route add -net {}/{} failed with status: {}", vpn_network_addr, self.config.prefix_len, status);
            // Don't fail completely - host route is more important
            debug!("Subnet route may already exist or not be needed");
        } else {
            info!("✓ Added subnet route {}/{} via {} (gateway {})", vpn_network_addr, self.config.prefix_len, tun_name, tun_addr);
        }

        // Block IPv6 to prevent traffic leaks (IPv6 bypasses the IPv4-only VPN tunnel).
        // First, discover and save the current IPv6 default interface so we can restore
        // it precisely on disconnect — avoids the "hardcode en0" problem.
        info!("Blocking IPv6 to prevent traffic leak...");
        let ipv6_iface = Command::new("/sbin/route")
            .args(["-n", "get", "-inet6", "default"])
            .output()
            .ok()
            .and_then(|out| {
                String::from_utf8(out.stdout).ok()
            })
            .and_then(|text| {
                text.lines()
                    .find(|l| l.trim().starts_with("interface:"))
                    .and_then(|l| l.split(':').nth(1))
                    .map(|s| s.trim().to_string())
            });
        if let Some(ref iface) = ipv6_iface {
            info!("Saving IPv6 default interface: {} (will restore on disconnect)", iface);
        } else {
            info!("No IPv6 default route found — nothing to restore on disconnect");
        }
        self.saved_ipv6_iface = ipv6_iface;

        // Add a blackhole for ::/0 — any IPv6 packet hits a dead end inside the OS.
        let _ = Command::new("/sbin/route").args(["-n", "delete", "-inet6", "default"]).status();
        let _ = Command::new("/sbin/route")
            .args(["-n", "add", "-inet6", "-net", "::/0", "-blackhole"])
            .status();
        info!("IPv6 blocked — all v6 traffic goes to blackhole (no leak possible)");

        // Verify routes
        info!("Verifying routes...");
        let output = Command::new("netstat")
            .args(["-rn", "-f", "inet"])
            .output()
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other,
                format!("Failed to run netstat: {}", e))))?;

        let routes = String::from_utf8_lossy(&output.stdout);
        if routes.contains(&vpn_network_addr) {
            info!("Routes verified:");
            for line in routes.lines().filter(|l| l.contains(&vpn_network_addr)) {
                debug!("  {}", line.trim());
            }
        }

        Ok(())
    }
    
    // ──────────────────── Linux ────────────────────
    
    /// Configure TUN device on Linux (ip route)
    #[cfg(target_os = "linux")]
    fn configure_linux(&self) -> Result<()> {
        use std::process::Command;
        
        let tun_name = &self.config.tun_name;
        let cidr = self.config.client_network_config()?.cidr_string();

        let status = Command::new("ip")
            .args(["addr", "replace", &cidr, "dev", tun_name])
            .status()
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other,
                format!("Failed to configure tunnel address: {}", e))))?;

        if !status.success() {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to configure tunnel address {} on {}", cidr, tun_name),
            )));
        }
        
        // Add route for the VPN subnet through our TUN device
        let status = Command::new("ip")
            .args(["route", "replace", &self.config.vpn_network_config()?.cidr_string(), "dev", tun_name])
            .status()
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other,
                format!("Failed to add route: {}", e))))?;
        
        if status.success() {
            info!("Added route {} via {}", self.config.vpn_network_config()?.cidr_string(), tun_name);
        } else {
            debug!("ip route add {} failed (may already exist)", self.config.vpn_network_config()?.cidr_string());
        }
        
        Ok(())
    }
    
    // ──────────────────── Windows ────────────────────

    /// Discover the wintun adapter's interface index via `netsh`.
    /// Used to pass `IF <index>` to `route add` so Windows binds the route
    /// to wintun rather than the physical NIC with the best next-hop metric.
    #[cfg(target_os = "windows")]
    fn find_wintun_interface_index(&self) -> Option<String> {
        let output = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "show", "interfaces"])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let tun_lower = self.config.tun_name.to_lowercase();
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.to_lowercase().ends_with(&tun_lower) {
                if let Some(idx) = trimmed.split_whitespace().next() {
                    if idx.parse::<u32>().is_ok() {
                        return Some(idx.to_string());
                    }
                }
            }
        }
        None
    }
    
    /// Configure TUN device on Windows (netsh / route add)
    #[cfg(target_os = "windows")]
    fn configure_windows(&self) -> Result<()> {
        let peer_addr = &self.config.server_vpn_ip;
        let vpn_network = self.config.vpn_network_config()?;
        let network_addr = vpn_network.network_addr().to_string();
        let tun_netmask = self.config.tun_netmask.clone();

        // Explicitly bind the VPN subnet route to the wintun interface.
        // Without IF, Windows may attach it to the physical NIC.
        let (add_args, delete_args): (Vec<&str>, Vec<&str>) = if let Some(ref idx) = self.wintun_if_index {
            (
                vec!["add", network_addr.as_str(), "mask", tun_netmask.as_str(), peer_addr, "IF", idx.as_str()],
                vec!["delete", network_addr.as_str(), "mask", tun_netmask.as_str(), "IF", idx.as_str()],
            )
        } else {
            (
                vec!["add", network_addr.as_str(), "mask", tun_netmask.as_str(), peer_addr],
                vec!["delete", network_addr.as_str(), "mask", tun_netmask.as_str()],
            )
        };

        self.add_windows_route_with_retry(
            &add_args,
            &delete_args,
            &format!("Added route {}/{} via {} IF {} (Windows)", network_addr, self.config.prefix_len, peer_addr, self.wintun_if_index.as_deref().unwrap_or("auto")),
            &format!("VPN subnet route {}/{}", network_addr, self.config.prefix_len),
        )?;
        
        Ok(())
    }
    
    /// Set VPN server IP (call before enable_full_tunnel)
    pub fn set_server_ip(&mut self, server_ip: String) {
        self.server_ip = Some(server_ip);
    }
    
    /// Enable full-tunnel mode: route all traffic through VPN
    #[cfg(target_os = "macos")]
    pub fn enable_full_tunnel(&mut self) -> Result<()> {
        use std::process::Command;
        
        let tun_name = &self.config.tun_name;
        
        // 1. Get current default gateway
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other,
                format!("Failed to get default route: {}", e))))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let default_gw = stdout.lines()
            .find(|l| l.trim().starts_with("gateway:"))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string());
        
        let gw = match default_gw {
            Some(g) => g,
            None => {
                error!("Could not determine default gateway");
                return Err(Error::Io(io::Error::new(io::ErrorKind::Other,
                    "Could not determine default gateway")));
            }
        };
        
        info!("Current default gateway: {}", gw);
        self.saved_default_gw = Some(gw.clone());
        
        // 2. Add bypass route for VPN server IP via original gateway
        if let Some(ref server_ip) = self.server_ip {
            let _ = Command::new("route").args(["-n", "delete", "-host", server_ip]).status();
            let status = Command::new("route")
                .args(["-n", "add", "-host", server_ip, &gw])
                .status()
                .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other,
                    format!("Failed to add server bypass route: {}", e))))?;
            if status.success() {
                info!("Added bypass route: {} via {}", server_ip, gw);
            } else {
                error!("Failed to add bypass route for {}", server_ip);
            }
        }
        
        // 3. Route all traffic through TUN using 0/1 + 128/1 trick
        for net in ["0.0.0.0/1", "128.0.0.0/1"] {
            let _ = Command::new("route").args(["-n", "delete", "-net", net]).status();
            let status = Command::new("route")
                .args(["-n", "add", "-net", net, "-interface", tun_name])
                .status()
                .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other,
                    format!("Failed to add full-tunnel route {}: {}", net, e))))?;
            if status.success() {
                info!("Added full-tunnel route: {} via {}", net, tun_name);
            } else {
                error!("Failed to add full-tunnel route {}", net);
            }
        }
        
        info!("Full tunnel mode enabled — all traffic routed through VPN");
        Ok(())
    }
    
    /// Enable full-tunnel mode on Linux
    #[cfg(target_os = "linux")]
    pub fn enable_full_tunnel(&mut self) -> Result<()> {
        use std::process::Command;
        
        let tun_name = &self.config.tun_name;
        
        // 1. Get current default gateway
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other,
                format!("Failed to get default route: {}", e))))?;
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let route_fields: Vec<&str> = stdout.split_whitespace().collect();
        let default_gw = route_fields.windows(2)
            .find(|window| window[0] == "via")
            .map(|window| window[1].to_string());
        let default_dev = route_fields.windows(2)
            .find(|window| window[0] == "dev")
            .map(|window| window[1].to_string());
        let default_onlink = route_fields.iter().any(|field| *field == "onlink");

        let (gw, default_dev) = match (default_gw, default_dev) {
            (Some(gw), Some(default_dev)) => (gw, default_dev),
            _ => {
                error!("Could not determine default gateway/interface");
                return Err(Error::Io(io::Error::new(io::ErrorKind::Other,
                    "Could not determine default gateway/interface")));
            }
        };
        
        info!("Current default gateway: {} via {}{}", gw, default_dev, if default_onlink { " onlink" } else { "" });
        self.saved_default_gw = Some(gw.clone());
        
        // 2. Add bypass route for VPN server IP via original gateway
        if let Some(ref server_ip) = self.server_ip {
            let mut bypass_added = false;

            let mut route_attempts = Vec::new();
            if default_onlink {
                route_attempts.push(vec!["route", "replace", server_ip.as_str(), "via", gw.as_str(), "dev", default_dev.as_str(), "onlink"]);
            }
            route_attempts.push(vec!["route", "replace", server_ip.as_str(), "via", gw.as_str(), "dev", default_dev.as_str()]);
            if !default_onlink {
                route_attempts.push(vec!["route", "replace", server_ip.as_str(), "via", gw.as_str(), "dev", default_dev.as_str(), "onlink"]);
            }

            for args in route_attempts {
                let status = Command::new("ip")
                    .args(&args)
                    .status()
                    .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other,
                        format!("Failed to add server bypass route: {}", e))))?;
                if status.success() {
                    bypass_added = true;
                    let used_onlink = args.last().is_some_and(|arg| *arg == "onlink");
                    info!(
                        "Added bypass route: {} via {} dev {}{}",
                        server_ip,
                        gw,
                        default_dev,
                        if used_onlink { " onlink" } else { "" }
                    );
                    break;
                }
            }

            if !bypass_added {
                let gateway_link_status = Command::new("ip")
                    .args(["route", "replace", gw.as_str(), "dev", default_dev.as_str(), "scope", "link"])
                    .status()
                    .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other,
                        format!("Failed to add gateway link route: {}", e))))?;

                if gateway_link_status.success() {
                    let status = Command::new("ip")
                        .args(["route", "replace", server_ip.as_str(), "via", gw.as_str(), "dev", default_dev.as_str()])
                        .status()
                        .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other,
                            format!("Failed to add server bypass route after gateway link route: {}", e))))?;

                    if status.success() {
                        bypass_added = true;
                        info!(
                            "Added bypass route: {} via {} dev {} after gateway link route",
                            server_ip,
                            gw,
                            default_dev
                        );
                    }
                }
            }

            if !bypass_added {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to add bypass route for {} via {} dev {}", server_ip, gw, default_dev),
                )));
            }
        }
        
        // 3. Route all traffic through TUN using 0/1 + 128/1 trick
        for net in ["0.0.0.0/1", "128.0.0.0/1"] {
            let status = Command::new("ip")
                .args(["route", "replace", net, "dev", tun_name])
                .status()
                .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other,
                    format!("Failed to add full-tunnel route {}: {}", net, e))))?;
            if status.success() {
                info!("Added full-tunnel route: {} via {}", net, tun_name);
            } else {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to add full-tunnel route {} via {}", net, tun_name),
                )));
            }
        }
        
        info!("Full tunnel mode enabled — all traffic routed through VPN");
        Ok(())
    }
    
    /// Enable full-tunnel mode on Windows
    #[cfg(target_os = "windows")]
    pub fn enable_full_tunnel(&mut self) -> Result<()> {
        use std::process::Command;
        
        let peer_addr = self.config.server_vpn_ip.clone();
        
        // 1. Get current default gateway via powershell
        let output = Command::new("powershell")
            .args(["-Command", "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop"])
            .output()
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other,
                format!("Failed to get default route: {}", e))))?;
        
        let gw = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if gw.is_empty() {
            error!("Could not determine default gateway");
            return Err(Error::Io(io::Error::new(io::ErrorKind::Other,
                "Could not determine default gateway")));
        }
        
        info!("Current default gateway: {}", gw);
        self.saved_default_gw = Some(gw.clone());
        
        // 2. Add bypass route for VPN server IP via original gateway
        if let Some(ref server_ip) = self.server_ip {
            let success_message = format!("Added bypass route: {} via {}", server_ip, gw);
            let add_args = ["add", server_ip.as_str(), "mask", "255.255.255.255", gw.as_str()];
            let delete_args = ["delete", server_ip.as_str(), "mask", "255.255.255.255"];
            self.add_windows_route_with_retry(
                &add_args,
                &delete_args,
                &success_message,
                &format!("server bypass route {}", server_ip),
            )?;
        }
        
        // 3. Route all traffic through TUN via 0/1 + 128/1 trick
        //    Explicitly bind to wintun IF to prevent Windows from attaching
        //    these routes to the physical NIC.
        for net in [("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")] {
            let if_suffix = self.wintun_if_index.as_deref().unwrap_or("auto");
            let success_message = format!("Added full-tunnel route: {}/1 via {} IF {}", net.0, peer_addr, if_suffix);
            let (add_args, delete_args): (Vec<&str>, Vec<&str>) = if let Some(ref idx) = self.wintun_if_index {
                (
                    vec!["add", net.0, "mask", net.1, peer_addr.as_str(), "metric", "5", "IF", idx.as_str()],
                    vec!["delete", net.0, "mask", net.1],
                )
            } else {
                (
                    vec!["add", net.0, "mask", net.1, peer_addr.as_str(), "metric", "5"],
                    vec!["delete", net.0, "mask", net.1],
                )
            };
            self.add_windows_route_with_retry(
                &add_args,
                &delete_args,
                &success_message,
                &format!("full-tunnel route {}/{}", net.0, net.1),
            )?;
        }
        
        info!("Full tunnel mode enabled — all traffic routed through VPN");
        Ok(())
    }
    
    /// Disable full-tunnel mode: restore original routing
    #[cfg(target_os = "macos")]
    fn disable_full_tunnel(&mut self) {
        use std::process::Command;
        
        for net in ["0.0.0.0/1", "128.0.0.0/1"] {
            let _ = Command::new("route").args(["-n", "delete", "-net", net]).status();
        }
        if let Some(ref server_ip) = self.server_ip {
            let _ = Command::new("route").args(["-n", "delete", "-host", server_ip]).status();
        }
        info!("Full tunnel routes removed");
    }
    
    /// Disable full-tunnel mode on Linux
    #[cfg(target_os = "linux")]
    fn disable_full_tunnel(&mut self) {
        use std::process::Command;
        
        for net in ["0.0.0.0/1", "128.0.0.0/1"] {
            let _ = Command::new("ip").args(["route", "del", net]).status();
        }
        if let Some(ref server_ip) = self.server_ip {
            let _ = Command::new("ip").args(["route", "del", server_ip]).status();
        }
        // Restore default gateway
        if let Some(ref gw) = self.saved_default_gw {
            let _ = Command::new("ip").args(["route", "add", "default", "via", gw]).status();
        }
        info!("Full tunnel routes removed");
    }

    /// Disable full-tunnel mode on Windows
    #[cfg(target_os = "windows")]
    fn disable_full_tunnel(&mut self) {
        use std::process::Command;

        for net in [("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")] {
            let _ = Command::new("route").args(["delete", net.0, "mask", net.1]).status();
        }
        if let Some(ref server_ip) = self.server_ip {
            let _ = Command::new("route").args(["delete", server_ip]).status();
        }
        info!("Full tunnel routes removed");
    }

    /// Restore IPv6 on macOS when disconnecting
    #[cfg(target_os = "macos")]
    fn restore_ipv6(&self) {
        use std::process::Command;

        info!("Restoring IPv6...");
        // Remove the blackhole.  If we saved the interface before blocking,
        // restore the default route through it.  If not — the macOS network
        // stack will re-discover the gateway via ND/SLAAC automatically.
        let _ = Command::new("/sbin/route")
            .args(["-n", "delete", "-inet6", "-net", "::/0", "-blackhole"])
            .status();

        if let Some(ref iface) = self.saved_ipv6_iface {
            let status = Command::new("/sbin/route")
                .args(["-n", "add", "-inet6", "default", "-interface", iface])
                .status();
            match status {
                Ok(s) if s.success() => info!("IPv6 default route restored via {}", iface),
                _ => info!("IPv6 blackhole removed — macOS will auto-restore via ND (iface {})", iface),
            }
        } else {
            info!("IPv6 blackhole removed — macOS will auto-restore via ND");
        }
    }

    /// Restore IPv6 on Linux
    #[cfg(target_os = "linux")]
    fn restore_ipv6(&self) {
        use std::process::Command;

        info!("Restoring IPv6...");
        // Remove the blackhole (if any).  Let the kernel re-discover the gateway.
        let _ = Command::new("ip").args(["-6", "route", "del", "blackhole", "default"]).status();
        let _ = Command::new("ip").args(["-6", "route", "del", "::/0"]).status();
        info!("IPv6 blackhole removed — kernel will auto-restore via ND/RA");
    }
    
    /// Take the TUN reader (moves ownership to caller, e.g. spawned task)
    pub fn take_reader(&mut self) -> Option<tun::DeviceReader> {
        self.reader.take()
    }

    /// Write packet to TUN asynchronously
    pub async fn write_packet_async(&mut self, packet: &[u8]) -> Result<usize> {
        let writer = self.writer.as_mut()
            .ok_or_else(|| Error::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                "TUN writer not available",
            )))?;
        
        writer.write_all(packet).await?;
        writer.flush().await?;
        
        debug!("Wrote {} bytes to TUN", packet.len());
        Ok(packet.len())
    }
    
    /// Get TUN device name
    pub fn name(&self) -> &str {
        &self.config.tun_name
    }
    
    /// Get TUN config
    pub fn config(&self) -> &TunnelConfig {
        &self.config
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        if self.config.full_tunnel && self.saved_default_gw.is_some() {
            self.disable_full_tunnel();
        }
        
        // Restore IPv6 on macOS
        #[cfg(target_os = "macos")]
        self.restore_ipv6();
        
        if self.writer.is_some() || self.reader.is_some() {
            info!("Closing TUN device: {}", self.config.tun_name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tunnel_config() {
        let config = TunnelConfig::default();
        assert!(config.tun_name.starts_with("tun"), "TUN name should start with 'tun'");
        assert_eq!(config.tun_addr, "10.0.0.2");
        assert_eq!(config.server_vpn_ip, "10.0.0.1");
        assert_eq!(config.mtu, WAN_SAFE_TUN_MTU);
    }
}
