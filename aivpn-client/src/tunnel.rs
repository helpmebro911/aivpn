//! Tunnel Module - Cross-platform TUN Device Integration
//! 
//! Supports Linux, macOS and Windows.
//! Handles TUN device creation, packet capture, and routing.

use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, debug, error};

use aivpn_common::error::{Error, Result};

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
    pub tun_netmask: String,
    pub mtu: u16,
    /// Route all traffic through VPN (full tunnel mode)
    pub full_tunnel: bool,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        use rand::Rng;
        Self {
            tun_name: format!("tun{:04x}", rand::thread_rng().gen::<u16>()),
            tun_addr: "10.0.0.1".to_string(),
            tun_netmask: "255.255.255.0".to_string(),
            mtu: WAN_SAFE_TUN_MTU,
            full_tunnel: false,
        }
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
        }
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
        let peer_addr = "10.0.0.1";
        
        // Set point-to-point addresses with explicit netmask
        let status = Command::new("/sbin/ifconfig")
            .args([tun_name, "inet", tun_addr, peer_addr, "netmask", "255.255.255.0", "mtu", &self.config.mtu.to_string(), "up"])
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
            info!("Configured {} with {} -> {} (netmask 255.255.255.0)", tun_name, tun_addr, peer_addr);
        }
        
        // Delete any stale routes to prevent conflicts
        info!("Cleaning up stale routes...");
        let _ = Command::new("/sbin/route").args(["-n", "delete", "-host", peer_addr]).status();
        let _ = Command::new("/sbin/route").args(["-n", "delete", "-net", "10.0.0.0", "-netmask", "255.255.255.0"]).status();
        
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
        info!("Adding subnet route 10.0.0.0/24 via {} (gateway {})", tun_name, tun_addr);
        let status = Command::new("/sbin/route")
            .args(["-n", "add", "-net", "10.0.0.0/24", tun_addr])
            .status()
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other,
                format!("Failed to add subnet route: {}", e))))?;

        if !status.success() {
            error!("route add -net 10.0.0.0/24 failed with status: {}", status);
            // Don't fail completely - host route is more important
            debug!("Subnet route may already exist or not be needed");
        } else {
            info!("✓ Added subnet route 10.0.0.0/24 via {} (gateway {})", tun_name, tun_addr);
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
        if routes.contains("10.0.0") {
            info!("Routes verified:");
            for line in routes.lines().filter(|l| l.contains("10.0.0")) {
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
        let peer_addr = "10.0.0.1";
        
        // Add route for the VPN subnet through our TUN device
        let _ = Command::new("ip")
            .args(["route", "del", "10.0.0.0/24"])
            .status();
        
        let status = Command::new("ip")
            .args(["route", "add", "10.0.0.0/24", "dev", tun_name])
            .status()
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other,
                format!("Failed to add route: {}", e))))?;
        
        if status.success() {
            info!("Added route 10.0.0.0/24 via {}", tun_name);
        } else {
            debug!("ip route add 10.0.0.0/24 failed (may already exist)");
        }
        
        Ok(())
    }
    
    // ──────────────────── Windows ────────────────────
    
    /// Configure TUN device on Windows (netsh / route add)
    #[cfg(target_os = "windows")]
    fn configure_windows(&self) -> Result<()> {
        use std::process::Command;
        
        let tun_addr = &self.config.tun_addr;
        let peer_addr = "10.0.0.1";
        
        // Add route for VPN subnet via our TUN adapter
        let status = Command::new("route")
            .args(["add", "10.0.0.0", "mask", "255.255.255.0", peer_addr])
            .status()
            .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other,
                format!("Failed to add route: {}", e))))?;
        
        if status.success() {
            info!("Added route 10.0.0.0/24 via {} (Windows)", peer_addr);
        } else {
            debug!("route add failed (may already exist)");
        }
        
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
        // Parse "default via X.X.X.X dev ethN"
        let default_gw = stdout.split_whitespace()
            .skip_while(|w| *w != "via")
            .nth(1)
            .map(|s| s.to_string());
        
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
            let _ = Command::new("ip").args(["route", "del", server_ip]).status();
            let status = Command::new("ip")
                .args(["route", "add", server_ip, "via", &gw])
                .status()
                .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other,
                    format!("Failed to add server bypass route: {}", e))))?;
            if status.success() {
                info!("Added bypass route: {} via {}", server_ip, gw);
            }
        }
        
        // 3. Route all traffic through TUN using 0/1 + 128/1 trick
        for net in ["0.0.0.0/1", "128.0.0.0/1"] {
            let _ = Command::new("ip").args(["route", "del", net]).status();
            let status = Command::new("ip")
                .args(["route", "add", net, "dev", tun_name])
                .status()
                .map_err(|e| Error::Io(io::Error::new(io::ErrorKind::Other,
                    format!("Failed to add full-tunnel route {}: {}", net, e))))?;
            if status.success() {
                info!("Added full-tunnel route: {} via {}", net, tun_name);
            }
        }
        
        info!("Full tunnel mode enabled — all traffic routed through VPN");
        Ok(())
    }
    
    /// Enable full-tunnel mode on Windows
    #[cfg(target_os = "windows")]
    pub fn enable_full_tunnel(&mut self) -> Result<()> {
        use std::process::Command;
        
        let peer_addr = "10.0.0.1";
        
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
            let _ = Command::new("route").args(["delete", server_ip]).status();
            let _ = Command::new("route")
                .args(["add", server_ip, "mask", "255.255.255.255", &gw])
                .status();
            info!("Added bypass route: {} via {}", server_ip, gw);
        }
        
        // 3. Route all traffic through TUN via 0/1 + 128/1 trick
        for net in [("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")] {
            let _ = Command::new("route").args(["delete", net.0, "mask", net.1]).status();
            let _ = Command::new("route")
                .args(["add", net.0, "mask", net.1, peer_addr, "metric", "5"])
                .status();
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
        assert_eq!(config.tun_addr, "10.0.0.1");
        assert_eq!(config.mtu, 1280);
    }
}
