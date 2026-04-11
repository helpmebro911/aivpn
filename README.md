# AIVPN

Traditional VPNs are dead. ISPs and state-level firewalls (like GFW) detect WireGuard and OpenVPN in milliseconds just by looking at packet sizes, timing intervals, and handshake patterns. You can encrypt your payload with whatever cipher you want — DPI systems don't care about the content, they block the *shape* of the connection itself.

**AIVPN** is my answer to modern deep packet inspection. We don't just encrypt packets — we disguise them as real application traffic. Your ISP sees a Zoom call or TikTok scrolling, when in reality it's a fully encrypted tunnel.

To validate this in practice, I built my own DPI emulator, reproduced real filtering scenarios, and intentionally blocked traffic across different modes. I then stress-tested the system under heavy load to measure resilience, mask-switching speed, and routing stability. For fast routing, I implemented my patented approach: USPTO (USA) application No. 19/452,440 dated Jan 19, 2026 — *SYSTEM AND METHOD FOR UNSUPERVISED MULTI-TASK ROUTING VIA SIGNAL RECONSTRUCTION RESONANCE*.

## Supported Platforms

| Platform | Server | Client | Full Tunnel | Notes |
|----------|--------|--------|-------------|-------|
| **Linux** | ✅ | ✅ | ✅ | Primary platform, TUN via `/dev/net/tun` |
| **macOS** | — | ✅ | ✅ | Via `utun` kernel interface, auto route config |
| **Windows** | — | ✅ | ✅ | Via [Wintun](https://www.wintun.net/) driver |
| **Android** | — | ✅ | ✅ | Native Kotlin app via `VpnService` API |

### Current Client Status

- ✅ macOS app: working
- ✅ CLI client: working
- ✅ Android app: working
- 🧪 Windows client: currently in testing

## 📥 Downloads (Pre-built Binaries)

No need to compile — download and run:

| Platform | File | Size | Notes |
|----------|------|------|-------|
| **macOS** | [aivpn-macos.dmg](releases/aivpn-macos.dmg) | ~1.8 MB | Menu bar app with RU/EN interface |
| **Linux** | [aivpn-client-linux-x86_64](releases/aivpn-client-linux-x86_64) | ~4.0 MB | Native x86_64 GNU/Linux CLI binary |
| **Linux ARMv7** | [aivpn-client-linux-armv7-musleabihf](releases/aivpn-client-linux-armv7-musleabihf) | ~4-5 MB | Static musl client binary for ARMv7 servers and SBCs |
| **Entware / MIPSel** | [aivpn-client-linux-mipsel-musl](releases/aivpn-client-linux-mipsel-musl) | ~4-5 MB | Static musl client binary for Entware-capable routers |
| **Windows** | [aivpn-windows-package.zip](releases/aivpn-windows-package.zip) | ~7 MB | Includes `aivpn-client.exe` + `wintun.dll` |
| **Android** | [aivpn-client.apk](releases/aivpn-client.apk) | ~6.5 MB | Install and paste your connection key |
| **Linux Server** | [aivpn-server-linux-x86_64](releases/aivpn-server-linux-x86_64) | ~4.0 MB | Prebuilt x86_64 GNU/Linux server binary for VPS or fast Docker deploy |
| **Linux Server ARMv7** | [aivpn-server-linux-armv7-musleabihf](releases/aivpn-server-linux-armv7-musleabihf) | ~4-5 MB | Static musl server binary for ARMv7 Linux hosts |
| **Linux Server MIPSel** | [aivpn-server-linux-mipsel-musl](releases/aivpn-server-linux-mipsel-musl) | ~4-5 MB | Static musl server binary for lightweight MIPSel/Entware systems |


### Quick Start (macOS)
1. Download and open `aivpn-macos.dmg`
2. Drag **Aivpn.app** to Applications
3. Launch — the app appears in the menu bar (no dock icon)
4. Paste your connection key (`aivpn://...`) and click **Connect**
5. Toggle 🇷🇺/🇬🇧 to switch language
> ⚠️ The VPN client requires root privileges for TUN device. The app will prompt for password via `sudo`.

### Quick Start (Windows)
1. Download and extract [aivpn-windows-package.zip](releases/aivpn-windows-package.zip)
2. Ensure `aivpn-client.exe` and `wintun.dll` remain in the same folder
3. Run **as Administrator** in PowerShell:
   ```powershell
   .\aivpn-client.exe -k "your_connection_key_here"
   ```

### Quick Start (Linux)
1. Download [aivpn-client-linux-x86_64](releases/aivpn-client-linux-x86_64)
2. Make it executable and run as root:
    ```bash
    chmod +x ./aivpn-client-linux-x86_64
    sudo ./aivpn-client-linux-x86_64 -k "your_connection_key_here"
    ```

### Quick Start (Entware Routers)
1. Download [aivpn-client-linux-mipsel-musl](releases/aivpn-client-linux-mipsel-musl) for MIPSel routers or [aivpn-client-linux-armv7-musleabihf](releases/aivpn-client-linux-armv7-musleabihf) for ARMv7 routers.
2. Copy the binary to the router, for example into `/opt/bin/aivpn-client`.
3. Make it executable and run it from Entware shell as root:
    ```sh
    chmod +x /opt/bin/aivpn-client
    /opt/bin/aivpn-client -k "your_connection_key_here"
    ```
4. Because these musl builds are statically linked, no Rust toolchain or extra shared libraries are required on the router.

### Quick Start (Android)
1. Download and install `aivpn-client.apk`
2. Paste your connection key (`aivpn://...`) into the app
3. Tap **Connect**

### Android Release Signing

For a production-signed Android APK, create `aivpn-android/keystore.properties`:

```properties
storeFile=/absolute/path/to/aivpn-release.jks
storePassword=your-store-password
keyAlias=aivpn
keyPassword=your-key-password
```

Then build with Java 21:

```bash
cd aivpn-android
export JAVA_HOME="$(/usr/libexec/java_home -v 21)"
export PATH="$JAVA_HOME/bin:$PATH"
./build-rust-android.sh release
```

If `keystore.properties` is absent, the script falls back to an unsigned release APK and then signs it with the debug keystore only as a local installable fallback.

## ❤️ Support the Project

If you find this project helpful, you can support its development with a donation via Tribute:

👉 https://t.me/tribute/app?startapp=dzX1

Every donation helps keep AIVPN evolving. Thank you! 🙌

## The Main Feature: Neural Resonance (AI)

The most interesting thing under the hood is our AI module called **Neural Resonance**.
We didn't drag a 400 MB LLM into the project that would eat all the RAM on a cheap VPS. Instead:

- **Baked Mask Encoder:** For each mask profile (WebRTC codec, QUIC protocol) we trained and "baked" a micro neural network (MLP 64→128→64) directly into the binary. It weighs only ~66 KB!
- **Real-time analysis:** This neural net analyzes entropy and IAT (inter-arrival times) of incoming UDP packets on the fly.
- **Hunting censors:** If the ISP's DPI system tries to probe our server (Active Probing) or starts throttling packets, the neural module detects a spike in reconstruction error (MSE).
- **Auto mask rotation:** As soon as the AI determines the current mask is compromised (e.g. `webrtc_zoom` got flagged), the server and client *seamlessly* reshape traffic to a backup mask (e.g. `dns_over_udp`). Zero disconnects!

## Other Cool Stuff

- **Zero-RTT & PFS:** No classic handshake for sniffers to catch. Data flows from the very first packet. And Perfect Forward Secrecy is built in — keys rotate on the fly, so even if the server gets seized, old traffic dumps can't be decrypted.
- **O(1) cryptographic session tags:** We never transmit a session ID in the clear. Instead, every packet carries a dynamic cryptographic tag derived from a timestamp and a secret key. The server finds the right client instantly, but to any observer it's just noise.
- **Written in Rust:** Fast, memory-safe, no leaks. The entire client binary is ~2.5 MB. Runs comfortably on a $5 VPS.

## Getting Started

### 1. Clone the repo

```bash
git clone https://github.com/infosave2007/aivpn.git
cd aivpn
```

### 2. Build (requires Rust 1.75+)

The project is split into workspaces: `aivpn-common` (crypto & masks), `aivpn-server`, and `aivpn-client`.

```bash
# Same command on all platforms:
cargo build --release
```

To refresh the Linux server release artifact without installing Rust on the host:

```bash
./build-server-release.sh
```

For static musl builds for ARMv7 servers and Entware-class MIPSel routers:

```bash
./build-musl-release.sh server armv7-unknown-linux-musleabihf
./build-musl-release.sh server mipsel-unknown-linux-musl
./build-musl-release.sh client armv7-unknown-linux-musleabihf
./build-musl-release.sh client mipsel-unknown-linux-musl
```

To deploy the latest published Linux server release to a VPS in one command:

```bash
./deploy-server-release.sh
```

> For GitHub Releases, publish `aivpn-server-linux-x86_64` as the default Linux server asset, keep `aivpn-windows-package.zip` as the primary Windows asset, and attach the musl artifacts `aivpn-server-linux-armv7-musleabihf`, `aivpn-server-linux-mipsel-musl`, `aivpn-client-linux-armv7-musleabihf`, and `aivpn-client-linux-mipsel-musl` for ARM/Entware targets. Raw `aivpn-client.exe` is only safe when `wintun.dll` is shipped next to it.

GitHub Releases automation: the workflow in `.github/workflows/server-release-asset.yml` builds `aivpn-server-linux-x86_64` plus the ARMv7 and MIPSel musl server/client assets on each published Release and uploads them automatically.

### 3. Server (Linux only)

#### Option A: Docker (recommended)

The easiest way — everything is preconfigured in `docker-compose.yml`.

```bash
# Pick the Compose command available on your system
if docker compose version >/dev/null 2>&1; then
    AIVPN_COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    AIVPN_COMPOSE="docker-compose"
else
    echo "Install Docker Compose v2 (`docker-compose-v2` or `docker-compose-plugin`) or legacy `docker-compose`."
    exit 1
fi

# Generate server key
mkdir -p config
openssl rand 32 > config/server.key
chmod 600 config/server.key

# Enable NAT (required for internet access from VPN)
DEFAULT_IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -C POSTROUTING -s 10.0.0.0/24 -o "$DEFAULT_IFACE" -j MASQUERADE 2>/dev/null || \
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o "$DEFAULT_IFACE" -j MASQUERADE

# Fast start from the prebuilt Linux release binary
AIVPN_SERVER_DOCKERFILE=Dockerfile.prebuilt $AIVPN_COMPOSE up -d aivpn-server

# Or keep the original source build path
$AIVPN_COMPOSE up -d aivpn-server
```

The fast path expects `releases/aivpn-server-linux-x86_64` to be present locally. Build it with `./build-server-release.sh` or download it from Releases before starting Docker.

For a VPS one-command fast deploy, run `./deploy-server-release.sh`. It downloads the release asset, creates `config/server.key` if needed, enables IPv4 forwarding, adds the NAT rule for the default interface, and starts Docker with `Dockerfile.prebuilt`.

If your firewall is enabled, also allow `443/udp` using the tool your system uses:

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 443/udp

# firewalld (RHEL/CentOS/Fedora)
sudo firewall-cmd --add-port=443/udp --permanent
sudo firewall-cmd --reload
```

> The container runs with `network_mode: "host"` and mounts `./config` → `/etc/aivpn` inside the container.

#### Option B: Bare metal

SSH into your VPS, generate a key:

```bash
sudo mkdir -p /etc/aivpn
openssl rand 32 | sudo tee /etc/aivpn/server.key > /dev/null
sudo chmod 600 /etc/aivpn/server.key
```

Start it up:

```bash
sudo ./target/release/aivpn-server --listen 0.0.0.0:443 --key-file /etc/aivpn/server.key
```

Enable NAT:

```bash
DEFAULT_IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -C POSTROUTING -s 10.0.0.0/24 -o "$DEFAULT_IFACE" -j MASQUERADE 2>/dev/null || \
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o "$DEFAULT_IFACE" -j MASQUERADE
```

### 3.1 Client Management

AIVPN uses a client registration model similar to WireGuard/XRay: each client gets a unique PSK, a static VPN IP, and traffic statistics.

All config is packed into a single **connection key** — one string that the user pastes into the app or CLI client.

#### Docker

```bash
# Reuse the same Compose command detected above
# Add a new client (prints a connection key)
$AIVPN_COMPOSE exec aivpn-server aivpn-server \
    --add-client "Alice Phone" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip YOUR_PUBLIC_IP:443

# Output:
# ✅ Client 'Alice Phone' created!
#    ID:     a1b2c3d4e5f67890
#    VPN IP: 10.0.0.2
#
# ══ Connection Key (paste into app) ══
#
# aivpn://eyJpIjoiMTAuMC4wLjIiLCJrIjoiLi4uIiwicCI6Ii4uLiIsInMiOiIxLjIuMy40OjQ0MyJ9

# List all clients with traffic stats
docker compose exec aivpn-server aivpn-server \
    --list-clients --clients-db /etc/aivpn/clients.json

# Show a specific client (and its connection key)
$AIVPN_COMPOSE exec aivpn-server aivpn-server \
    --show-client "Alice Phone" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip YOUR_PUBLIC_IP:443

# Remove a client
docker compose exec aivpn-server aivpn-server \
    --remove-client "Alice Phone" \
    --clients-db /etc/aivpn/clients.json
```

> Uses the Compose service name, so it works regardless of the generated container name.

#### Bare metal

```bash
# Add a new client
aivpn-server \
    --add-client "Alice Phone" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip YOUR_PUBLIC_IP:443

# List all clients with traffic stats
aivpn-server --list-clients --clients-db /etc/aivpn/clients.json

# Show a specific client (and its connection key)
aivpn-server \
    --show-client "Alice Phone" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip YOUR_PUBLIC_IP:443

# Remove a client
aivpn-server \
    --remove-client "Alice Phone" \
    --clients-db /etc/aivpn/clients.json
```

### 4. Client

#### Connection Key (recommended)

The easiest way — paste the connection key from `--add-client`:

```bash
sudo ./target/release/aivpn-client -k "aivpn://eyJp..."
```

Full tunnel:

```bash
sudo ./target/release/aivpn-client -k "aivpn://eyJp..." --full-tunnel
```

#### Manual mode

You can also specify the server address and key manually (without PSK — for legacy/no-auth mode):

#### Linux

```bash
sudo ./target/release/aivpn-client \
    --server YOUR_VPS_IP:443 \
    --server-key SERVER_PUBLIC_KEY_BASE64
```

Full tunnel mode (route all traffic through VPN):

```bash
sudo ./target/release/aivpn-client \
    --server YOUR_VPS_IP:443 \
    --server-key SERVER_PUBLIC_KEY_BASE64 \
    --full-tunnel
```

#### macOS

Same deal, `cargo build --release` produces a native binary:

```bash
sudo ./target/release/aivpn-client \
    --server YOUR_VPS_IP:443 \
    --server-key SERVER_PUBLIC_KEY_BASE64
```

> macOS will auto-configure the `utun` interface and routes via `ifconfig` / `route`.

#### Windows

Preferred for users: download and extract `releases/aivpn-windows-package.zip`.

If you distribute raw files instead, keep `wintun.dll` next to the `.exe`:

```
aivpn-client.exe
wintun.dll
```

Run from PowerShell **as Administrator**:

```powershell
.\aivpn-client.exe --server YOUR_VPS_IP:443 --server-key SERVER_PUBLIC_KEY_BASE64
```

Full tunnel:

```powershell
.\aivpn-client.exe --server YOUR_VPS_IP:443 --server-key SERVER_PUBLIC_KEY_BASE64 --full-tunnel
```

> The client auto-configures routes via `route add` and cleans them up on exit.

### 5. Android

1. Install the APK (`aivpn-android/app/build/outputs/apk/debug/app-debug.apk`)
2. Paste your **connection key** (`aivpn://...`) into the single input field
3. Tap **Connect**

The connection key contains everything: server address, public key, your PSK, and VPN IP. No manual configuration needed.

## Cross-compilation

Build the client for any platform from your current machine:

```bash
# Linux target from macOS/Windows
rustup target add x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu

# Windows target from Linux/macOS
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

For static musl cross-builds without installing a local cross toolchain, use Docker-backed release builds:

```bash
./build-musl-release.sh client armv7-unknown-linux-musleabihf
./build-musl-release.sh client mipsel-unknown-linux-musl
./build-musl-release.sh server armv7-unknown-linux-musleabihf
./build-musl-release.sh server mipsel-unknown-linux-musl
```

These artifacts are intended for ARM Linux servers/SBCs and Entware-capable MIPSel routers.

For Entware routers, the usual flow is: build or download the musl artifact, copy it into `/opt/bin`, `chmod +x`, and run it directly from the router shell.

## Project Structure

```
aivpn/
├── aivpn-common/src/
│   ├── crypto.rs        # X25519, ChaCha20-Poly1305, BLAKE3
│   ├── mask.rs          # Mimicry profiles (WebRTC, QUIC, DNS)
│   └── protocol.rs      # Packet format, inner types
├── aivpn-client/src/
│   ├── client.rs        # Core client logic
│   ├── tunnel.rs        # TUN interface (Linux / macOS / Windows)
│   └── mimicry.rs       # Traffic shaping engine
├── aivpn-server/src/
│   ├── gateway.rs       # UDP gateway, MaskCatalog, resonance loop
│   ├── neural.rs        # Baked Mask Encoder, AnomalyDetector
│   ├── nat.rs           # NAT forwarder (iptables)
│   ├── client_db.rs     # Client database (PSK, static IP, stats)
│   ├── key_rotation.rs  # Session key rotation
│   └── metrics.rs       # Prometheus monitoring
├── aivpn-android/       # Android client (Kotlin)
├── Dockerfile
├── docker-compose.yml
└── build.sh
```

## Contributing

Want to dig into the code or train your own mask for the neural module? Jump in:

- Mask engine: [`aivpn-common/src/mask.rs`](aivpn-common/src/mask.rs)
- Neural weights & anomaly detector: [`aivpn-server/src/neural.rs`](aivpn-server/src/neural.rs)
- Cross-platform TUN module: [`aivpn-client/src/tunnel.rs`](aivpn-client/src/tunnel.rs)
- Tests (100+): `cargo test`

PRs are welcome! We're especially looking for people with traffic analysis experience to capture dumps from popular apps and train new profiles for Neural Resonance.

---

License — MIT. Use it, fork it, bypass censorship responsibly.
