# AIVPN

**Next-generation VPN that makes your traffic invisible to deep packet inspection.**

<p align="center">
  <img src="https://img.shields.io/badge/lang-Rust-orange?style=flat-square&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/version-0.3.0-blue?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/tests-113%20passed-brightgreen?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/binary-~2.5MB-lightgrey?style=flat-square" alt="Size">
</p>

---

AIVPN doesn't just encrypt your traffic — it makes it **indistinguishable from ordinary internet activity**. To any observer, including state-level deep packet inspection systems, your connection looks like a regular video call, web browsing, or any other everyday application. No headers to fingerprint. No handshake to detect. No pattern to match.

## Why Existing VPNs Get Blocked

Every mainstream VPN protocol — OpenVPN, WireGuard, Shadowsocks — has a fingerprint. Encrypt all you want, the traffic *shape* still betrays you: packet sizes are too uniform, timing is too regular, handshakes follow a detectable sequence. Modern DPI systems with ML classifiers catch these patterns in seconds.

AIVPN solves this at the protocol level:

| | Traditional VPN | AIVPN |
|---|---|---|
| **Connection** | Detectable handshake phase | Zero-RTT — first packet carries data |
| **Headers** | Known structure / magic bytes | Dynamic per-session — nothing to match |
| **Traffic shape** | Uniform, machine-like | Mimics real apps (video calls, HTTPS) |
| **Active probes** | Server responds with errors | Complete silence — invisible to scanners |
| **If source code leaks** | Protocol is compromised | No effect — security is in keys, not code |
| **If server is seized** | Past traffic decryptable | Protected — Perfect Forward Secrecy |

## Key Features

- **Adaptive Traffic Mimicry** — every session shapeshifts to match a real application's traffic profile
- **Zero-RTT Start** — no handshake for censors to fingerprint; data flows from the first packet
- **Perfect Forward Secrecy** — ephemeral key ratchet; compromising a server reveals nothing about past sessions
- **Silent Server** — looks like a closed port to anyone without valid credentials
- **Cryptographic Server Auth** — prevents man-in-the-middle even on a fully hostile network
- **O(1) Packet Routing** — constant-time session identification via rotating cryptographic tags
- **Memory-Safe** — pure Rust with zero `unsafe` code; all key material auto-zeroed on drop
- **Tiny Footprint** — client ~2.4 MB, server ~2.6 MB, runs comfortably on a $5 VPS

### What's New in 0.3.0

- **Neural Resonance (Baked Mask Encoder)** — each mask gets a dedicated micro-neural-network (MLP 64→128→64, ~66 KB per mask) that detects DPI compromise via traffic reconstruction error. No external models — pure Rust, runs on any VPS.
- **Automatic Mask Rotation** — when DPI compromises a mask, the session instantly switches to a fallback mask from the catalog without dropping the connection.
- **Mask Catalog with Fallback Pool** — register multiple masks, monitor their status, automatically select the best available mask.
- **Anomaly Detector** — monitors packet loss and RTT per mask; a spike in metrics signals DPI interference.
- **Encryption Key Rotation** — automatic session key rotation by timer (120s) and data volume (1 MB).
- **Prometheus Metrics** — optional monitoring module (feature flag `metrics`).

## Quick Start

### Requirements

- **Rust 1.75+** — [rustup.rs](https://rustup.rs/)
- **Linux** with TUN/TAP support (server and client)
- **macOS** supported for client and development
- **Root access** required for TUN device and NAT

### Build

```bash
git clone <repo-url> && cd aivpn

# Build optimized release binaries
cargo build --release

# Or use the build script
./build.sh
```

### Run Tests

```bash
cargo test    # 113 tests: crypto, protocol, mimicry, neural resonance, mask rotation, anomaly, keys, stress
```

---

## Server Setup

### 1. Generate Server Key

```bash
sudo mkdir -p /etc/aivpn
openssl rand 32 | sudo tee /etc/aivpn/server.key > /dev/null
sudo chmod 600 /etc/aivpn/server.key
```

### 2. Start Server

```bash
sudo ./target/release/aivpn-server \
    --listen 0.0.0.0:443 \
    --key-file /etc/aivpn/server.key
```

The server logs its **public key** on startup — share it with clients.

| Flag | Default | Description |
|---|---|---|
| `--listen` | `0.0.0.0:443` | UDP listen address and port |
| `--key-file` | — | Path to 32-byte server private key |
| `--tun-name` | auto | TUN interface name (randomized by default) |
| `--config` | — | Path to JSON config file |

### 3. Enable NAT

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
```

### Server Config (optional)

`/etc/aivpn/server.json`:
```json
{
  "listen_addr": "0.0.0.0:443",
  "tun_addr": "10.0.0.1",
  "tun_netmask": "255.255.255.0",
  "max_sessions": 500,
  "session_timeout_secs": 86400
}
```

---

## Client Setup

```bash
sudo ./target/release/aivpn-client \
    --server YOUR_SERVER_IP:443 \
    --server-key BASE64_SERVER_PUBLIC_KEY
```

| Flag | Default | Description |
|---|---|---|
| `--server` | — | Server address (`ip:port`) |
| `--server-key` | — | Server public key (base64, 32 bytes) |
| `--tun-name` | auto | TUN interface name |
| `--tun-addr` | `10.0.0.2` | Client tunnel IP |
| `--config` | — | Path to JSON config file |

### Client Config (optional)

```json
{
  "server_addr": "YOUR_SERVER_IP:443",
  "server_public_key": "BASE64_KEY",
  "tun_addr": "10.0.0.2",
  "tun_netmask": "255.255.255.0"
}
```

---

## Docker Deployment

```bash
docker-compose up -d
docker-compose logs -f aivpn-server
```

Runs with `NET_ADMIN`, optimized sysctls, and 800 MB memory limit.

---

## How It Works

```
  Your traffic                                         Internet
      |                                                   ^
      v                                                   |
+-----------+      indistinguishable     +-----------+    |
|  AIVPN    | ==== from normal UDP ====> |  AIVPN    |----+
|  Client   |       (Zoom, HTTPS...)     |  Server   |
+-----------+                            +-----------+
```

1. Client captures IP packets from a TUN device, encrypts them, and reshapes the traffic to look like a specific real-world application
2. Each packet carries a **rotating cryptographic tag** that changes every packet and looks like random bytes to any observer
3. The server identifies sessions via O(1) hash lookup and is completely silent to everything else
4. On connection, an automatic **key ratchet** establishes forward secrecy — old keys are destroyed, past traffic stays safe

## Security

| Property | Detail |
|---|---|
| Encryption | ChaCha20-Poly1305 AEAD, every packet |
| Key Exchange | X25519 with clamping and constant-time operations |
| Forward Secrecy | Ephemeral key ratchet, keys zeroized after use |
| Server Auth | Ed25519 signature verification |
| Anti-Replay | 256-bit sliding window bitmap + monotonic counters |
| Key Hygiene | `ZeroizeOnDrop` on all secrets, `OsRng` for keygen |
| Rate Limiting | Per-IP session limits, connection throttling |
| Neural Resonance | Baked Mask Encoder — ~66 KB per mask instead of ~400 MB LLM |
| Auto-Rotation | Mask compromise → instant fallback switch |
| Key Rotation | By timer and data volume, BLAKE3 key derivation |

The codebase has been hardened through a comprehensive internal security audit. All critical and high-severity findings have been addressed.

## Project Structure

```
aivpn/
├── aivpn-common/       # Shared crypto, protocol, and mask engine
├── aivpn-client/       # VPN client binary
├── aivpn-server/       # VPN server binary
│   ├── gateway.rs      #   UDP gateway, MaskCatalog, resonance loop
│   ├── neural.rs       #   Baked Mask Encoder, AnomalyDetector
│   ├── key_rotation.rs #   Session key rotation
│   ├── metrics.rs      #   Prometheus monitoring (optional)
│   └── passive_distribution.rs  # Passive mask distribution
├── config/             # Example configurations
├── Dockerfile          # Multi-stage production build
├── docker-compose.yml  # Container deployment
├── build.sh            # Release build script
└── setup.sh            # Dev environment setup
```

## Contributing

```bash
cargo test && cargo clippy --all-targets
```

PRs welcome. Run the full suite before submitting.

## License

MIT
