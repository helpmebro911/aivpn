//! Android VPN tunnel — runs on top of a TUN fd created by VpnService.Builder and a UDP
//! socket created here and exempted via VpnService.protect(int).
//!
//! Wire protocol is byte-for-byte identical to AivpnCrypto.kt so that both can talk to the
//! same Rust server without any server-side changes.

use std::net::{SocketAddr, SocketAddrV4};
use std::os::fd::OwnedFd;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jni::objects::GlobalRef;
use jni::JavaVM;
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::time;

use aivpn_common::crypto::{
    current_timestamp_ms, compute_time_window, decrypt_payload, derive_session_keys,
    encrypt_payload, generate_resonance_tag, obfuscate_eph_pub, KeyPair, SessionKeys,
    DEFAULT_WINDOW_MS, NONCE_SIZE, TAG_SIZE,
};
use aivpn_common::error::{Error, Result};

// ──────────── Constants ────────────

const MDH_SIZE: usize = 4; // Mask-Dependent Header — always 4 zero bytes in our protocol
const INNER_TYPE_DATA: u16 = 0x0001;
const INNER_TYPE_CONTROL: u16 = 0x0002;
const CTRL_KEEPALIVE: u8 = 0x03;
const CTRL_SERVER_HELLO: u8 = 0x09;
const BUF_SIZE: usize = 1500;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);
const RX_SILENCE_MS: u64 = 120_000; // 2 min: detect dead NAT before keepalive masks it
const REKEY_INTERVAL: Duration = Duration::from_secs(1800); // 30 min

// ──────────── Public globals (read by JNI exports in lib.rs) ────────────

pub static TUNNEL_UDP_FD: AtomicI32 = AtomicI32::new(-1);
pub static UPLOAD_BYTES: AtomicU64 = AtomicU64::new(0);
pub static DOWNLOAD_BYTES: AtomicU64 = AtomicU64::new(0);

// ──────────── Entry point ────────────

/// Blocking async function that runs the whole tunnel session.
/// Returns Ok(()) only on REKEY_INTERVAL expiry (clean reconnect trigger).
/// All errors cause the Kotlin reconnect loop to kick in.
pub async fn run_tunnel_android(
    vm: JavaVM,
    vpn_service: GlobalRef,
    tun_fd_int: RawFd,
    server_host: String,
    server_port: u16,
    server_key: [u8; 32],
    psk: Option<[u8; 32]>,
) -> Result<()> {
    // Reset per-session counters.
    UPLOAD_BYTES.store(0, Ordering::Relaxed);
    DOWNLOAD_BYTES.store(0, Ordering::Relaxed);

    // ── 1. Ephemeral keypair + initial session keys (Zero-RTT like existing Kotlin) ──
    let keypair = KeyPair::generate();
    let dh = keypair.compute_shared(&server_key)?;
    let mut keys = derive_session_keys(&dh, psk.as_ref(), &keypair.public_key_bytes());

    // ── 2. Create and protect UDP socket ──
    // Resolve host (async DNS so we don't block the tokio thread).
    let dest_str = format!("{}:{}", server_host, server_port);
    let dest: SocketAddr = tokio::net::lookup_host(&dest_str)
        .await
        .map_err(|e| Error::Io(e))?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| Error::Session("Cannot resolve server host to IPv4".into()))?;

    let raw_udp_fd = create_protected_udp_socket(&vm, &vpn_service, dest)?;
    TUNNEL_UDP_FD.store(raw_udp_fd, Ordering::SeqCst);

    // ── 3. Set TUN fd to non-blocking for AsyncFd ──
    unsafe { libc::fcntl(tun_fd_int, libc::F_SETFL, libc::O_NONBLOCK) };
    // SAFETY: we own this fd (Kotlin called detachFd()).
    let owned_tun = unsafe { OwnedFd::from_raw_fd(tun_fd_int) };
    let tun = AsyncFd::new(owned_tun)?;

    // Convert the raw UDP fd to a tokio UdpSocket (already connected to server).
    let std_udp = unsafe { std::net::UdpSocket::from_raw_fd(raw_udp_fd) };
    std_udp.set_nonblocking(true)?;
    let udp = UdpSocket::from_std(std_udp)?;

    // ── 4. Send init handshake (Control/Keepalive + obfuscated eph_pub) ──
    let mut send_counter: u64 = 0;
    let mut send_seq: u16 = 0;
    {
        let inner = build_inner(INNER_TYPE_CONTROL, send_seq, &[CTRL_KEEPALIVE]);
        send_seq = send_seq.wrapping_add(1);
        let mut obf_pub = keypair.public_key_bytes();
        obfuscate_eph_pub(&mut obf_pub, &server_key);
        let pkt = build_packet(&keys, &mut send_counter, &inner, Some(&obf_pub))?;
        udp.send(&pkt).await?;
    }

    // ── 5. Wait for ServerHello with timeout ──
    let mut recv_buf = vec![0u8; BUF_SIZE];
    let n = time::timeout(HANDSHAKE_TIMEOUT, udp.recv(&mut recv_buf))
        .await
        .map_err(|_| Error::Session("Handshake timeout (10 s)".into()))??;

    let mut recv_win = RecvWindow::new();
    process_server_hello(&recv_buf[..n], &mut keys, &keypair, &mut recv_win, &mut send_counter)?;
    log::info!("aivpn: handshake + PFS ratchet complete");

    // ── 6. Main forwarding loop ──
    let mut tun_buf = vec![0u8; BUF_SIZE];
    let mut udp_buf = vec![0u8; BUF_SIZE];
    let mut last_rx_ms = monotonic_ms();
    let rekey_sleep = time::sleep(REKEY_INTERVAL);
    tokio::pin!(rekey_sleep);
    let mut ka_interval = time::interval(KEEPALIVE_INTERVAL);
    ka_interval.tick().await; // discard immediate first tick

    loop {
        tokio::select! {
            biased;

            // ── Rekey (triggers fresh reconnect in Kotlin) ──
            _ = &mut rekey_sleep => {
                log::info!("aivpn: rekey interval — signalling reconnect");
                return Ok(());
            }

            // ── TUN → UDP (outbound IP packets) ──
            r = tun_async_read(&tun, &mut tun_buf) => {
                let n = r?;
                if n == 0 { continue; }
                // Drop non-IPv4 packets (IPv6 version nibble = 6, first byte 0x60-0x6F).
                // Android routes ::/0 into TUN to prevent IPv6 leaks; we must discard
                // those packets here because the server only speaks IPv4.
                if tun_buf[0] >> 4 != 4 { continue; }
                let inner = build_inner(INNER_TYPE_DATA, send_seq, &tun_buf[..n]);
                send_seq = send_seq.wrapping_add(1);
                let pkt = build_packet(&keys, &mut send_counter, &inner, None)?;
                udp.send(&pkt).await?;
                UPLOAD_BYTES.fetch_add(n as u64, Ordering::Relaxed);
            }

            // ── UDP → TUN (inbound from server) ──
            r = udp.recv(&mut udp_buf) => {
                let n = r?;
                last_rx_ms = monotonic_ms();
                if let Some(ip) = decrypt_packet(&udp_buf[..n], &keys, &mut recv_win) {
                    tun_write(&tun, &ip)?;
                    DOWNLOAD_BYTES.fetch_add(ip.len() as u64, Ordering::Relaxed);
                }
            }

            // ── Keepalive + RX-silence check ──
            _ = ka_interval.tick() => {
                let silence = monotonic_ms().saturating_sub(last_rx_ms);
                if silence > RX_SILENCE_MS {
                    return Err(Error::Session(
                        format!("No RX for {}ms — reconnecting", silence)
                    ));
                }
                let inner = build_inner(INNER_TYPE_CONTROL, send_seq, &[CTRL_KEEPALIVE]);
                send_seq = send_seq.wrapping_add(1);
                let pkt = build_packet(&keys, &mut send_counter, &inner, None)?;
                udp.send(&pkt).await?;
            }
        }
    }
}

// ──────────── Protected UDP socket creation ────────────

fn create_protected_udp_socket(
    vm: &JavaVM,
    vpn_service: &GlobalRef,
    dest: SocketAddr,
) -> Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    // Call Android VpnService.protect(int) to exempt this socket from the VPN.
    let mut guard = vm
        .attach_current_thread()
        .map_err(|e| Error::Session(format!("JNI attach: {}", e)))?;

    let protected = guard
        .call_method(
            vpn_service,
            "protect",
            "(I)Z",
            &[jni::objects::JValue::Int(fd)],
        )
        .and_then(|v| v.z())
        .unwrap_or(false);

    if !protected {
        unsafe { libc::close(fd) };
        return Err(Error::Session("VpnService.protect() returned false".into()));
    }

    // Connect to server (sets default destination for send/recv, non-blocking for UDP).
    let SocketAddr::V4(v4) = dest else {
        unsafe { libc::close(fd) };
        return Err(Error::Session("Only IPv4 server addresses are supported".into()));
    };
    let sa = to_sockaddr_in(&v4);
    let rc = unsafe {
        libc::connect(
            fd,
            &sa as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        unsafe { libc::close(fd) };
        return Err(Error::Io(std::io::Error::last_os_error()));
    }

    Ok(fd)
}

fn to_sockaddr_in(addr: &SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

// ──────────── Async TUN I/O ────────────

async fn tun_async_read(tun: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        let mut guard = tun.readable().await?;
        match guard.try_io(|inner| {
            let n = unsafe {
                libc::read(
                    inner.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(r) => return r,
            Err(_would_block) => continue,
        }
    }
}

fn tun_write(tun: &AsyncFd<OwnedFd>, data: &[u8]) -> std::io::Result<()> {
    // TUN writes are rare and small; a blocking write is fine here.
    let n = unsafe {
        libc::write(
            tun.as_raw_fd(),
            data.as_ptr() as *const libc::c_void,
            data.len(),
        )
    };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// ──────────── Packet construction ────────────

/// TAG(8) | MDH(4 zeros) | [obf_eph_pub(32)] | encrypt(pad_len(2) | inner | padding)
fn build_packet(
    keys: &SessionKeys,
    counter: &mut u64,
    inner: &[u8],
    obf_eph_pub: Option<&[u8; 32]>,
) -> aivpn_common::error::Result<Vec<u8>> {
    use rand::RngCore;
    let pad_len: u16 = 8 + rand::thread_rng().next_u32() as u16 % 16;
    let mut plaintext = Vec::with_capacity(2 + inner.len() + pad_len as usize);
    plaintext.extend_from_slice(&pad_len.to_le_bytes());
    plaintext.extend_from_slice(inner);
    plaintext.resize(2 + inner.len() + pad_len as usize, 0);
    rand::thread_rng().fill_bytes(&mut plaintext[2 + inner.len()..]);

    let c = *counter;
    *counter += 1;
    let nonce = counter_to_nonce(c);
    // encrypt_payload never fails with a valid 32-byte key.
    let ciphertext = encrypt_payload(&keys.session_key, &nonce, &plaintext)?;

    let tw = compute_time_window(current_timestamp_ms(), DEFAULT_WINDOW_MS);
    let tag = generate_resonance_tag(&keys.tag_secret, c, tw);

    let eph_len = if obf_eph_pub.is_some() { 32 } else { 0 };
    let mut pkt = Vec::with_capacity(TAG_SIZE + MDH_SIZE + eph_len + ciphertext.len());
    pkt.extend_from_slice(&tag);
    pkt.extend_from_slice(&[0u8; MDH_SIZE]);
    if let Some(e) = obf_eph_pub {
        pkt.extend_from_slice(e);
    }
    pkt.extend_from_slice(&ciphertext);
    Ok(pkt)
}

/// inner_header = type(u16 LE) | seq(u16 LE) — compatible with Kotlin's [type(u8), 0, seq_lo, seq_hi]
fn build_inner(inner_type: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + payload.len());
    v.extend_from_slice(&inner_type.to_le_bytes());
    v.extend_from_slice(&seq.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

// ──────────── Packet decryption ────────────

fn decrypt_packet(
    packet: &[u8],
    keys: &SessionKeys,
    win: &mut RecvWindow,
) -> Option<Vec<u8>> {
    if packet.len() < TAG_SIZE + MDH_SIZE + 16 {
        return None;
    }
    let tag: [u8; TAG_SIZE] = packet[..TAG_SIZE].try_into().ok()?;
    let counter = win.find_counter(&tag, keys)?;

    let nonce = counter_to_nonce(counter);
    let ciphertext = &packet[TAG_SIZE + MDH_SIZE..];
    let pt = decrypt_payload(&keys.session_key, &nonce, ciphertext).ok()?;

    win.mark(counter);

    if pt.len() < 2 {
        return None;
    }
    let pad_len = u16::from_le_bytes([pt[0], pt[1]]) as usize;
    let end = pt.len().checked_sub(pad_len)?;
    let inner = &pt[2..end];

    if inner.len() < 4 {
        return None;
    }
    let inner_type = u16::from_le_bytes([inner[0], inner[1]]);
    let body = &inner[4..];

    // Return IP payload only for Data packets; Control/Keepalive ACKs return None
    // but their counter still advanced last_rx_ms in the caller.
    if inner_type == INNER_TYPE_DATA && !body.is_empty() {
        Some(body.to_vec())
    } else {
        None
    }
}

// ──────────── ServerHello / PFS ratchet ────────────

fn process_server_hello(
    packet: &[u8],
    keys: &mut SessionKeys,
    keypair: &KeyPair,
    win: &mut RecvWindow,
    send_counter: &mut u64,
) -> Result<()> {
    if packet.len() < TAG_SIZE + MDH_SIZE + 16 {
        return Err(Error::InvalidPacket("ServerHello too short"));
    }
    let tag: [u8; TAG_SIZE] = packet[..TAG_SIZE].try_into().unwrap();
    let counter = win
        .find_counter(&tag, keys)
        .ok_or(Error::InvalidPacket("ServerHello tag not found"))?;

    let nonce = counter_to_nonce(counter);
    let ciphertext = &packet[TAG_SIZE + MDH_SIZE..];
    let pt = decrypt_payload(&keys.session_key, &nonce, ciphertext)
        .map_err(|_| Error::InvalidPacket("ServerHello decryption failed"))?;
    win.mark(counter);

    if pt.len() < 2 {
        return Err(Error::InvalidPacket("ServerHello plaintext too short"));
    }
    let pad_len = u16::from_le_bytes([pt[0], pt[1]]) as usize;
    let inner = &pt[2..pt.len().saturating_sub(pad_len)];

    if inner.len() < 4 {
        return Err(Error::InvalidPacket("ServerHello inner too short"));
    }
    let body = &inner[4..]; // skip 4-byte inner header
    if body.is_empty() || body[0] != CTRL_SERVER_HELLO {
        return Err(Error::InvalidPacket("Expected ServerHello subtype 0x09"));
    }
    if body.len() < 33 {
        return Err(Error::InvalidPacket("ServerHello missing eph_pub"));
    }
    let mut server_eph: [u8; 32] = [0; 32];
    server_eph.copy_from_slice(&body[1..33]);

    // PFS ratchet: DH2 = client_eph * server_eph, then re-derive keys with current session_key as PSK
    let dh2 = keypair.compute_shared(&server_eph)?;
    let old_session_key = keys.session_key;
    *keys = derive_session_keys(&dh2, Some(&old_session_key), &keypair.public_key_bytes());

    // Both sides reset counters after ratchet (matches Kotlin processServerHello).
    *send_counter = 0;
    win.reset();

    Ok(())
}

// ──────────── Sliding-window anti-replay ────────────

struct RecvWindow {
    highest: i64, // -1 = nothing received
    bitmap: u64,
}

impl RecvWindow {
    fn new() -> Self {
        Self { highest: -1, bitmap: 0 }
    }

    fn reset(&mut self) {
        self.highest = -1;
        self.bitmap = 0;
    }

    fn is_new(&self, c: u64) -> bool {
        if self.highest < 0 {
            return true;
        }
        let h = self.highest as u64;
        if c > h {
            return true;
        }
        let diff = h - c;
        if diff >= 64 {
            return false;
        }
        (self.bitmap >> diff) & 1 == 0
    }

    fn mark(&mut self, c: u64) {
        if self.highest < 0 || c > self.highest as u64 {
            let shift = if self.highest < 0 { 64u64 } else { c - self.highest as u64 };
            self.bitmap = if shift >= 64 { 1 } else { (self.bitmap << shift) | 1 };
            self.highest = c as i64;
        } else {
            let diff = (self.highest as u64 - c) as usize;
            if diff < 64 {
                self.bitmap |= 1u64 << diff;
            }
        }
    }

    /// Search window for a counter whose resonance tag matches.
    /// Matches Kotlin's counter search range: [max(0, highest-63), max(256, highest+257))
    fn find_counter(&self, tag: &[u8; TAG_SIZE], keys: &SessionKeys) -> Option<u64> {
        let now = current_timestamp_ms();
        let base_tw = compute_time_window(now, DEFAULT_WINDOW_MS);
        let start = if self.highest < 0 { 0 } else { (self.highest as u64).saturating_sub(63) };
        let end = if self.highest < 0 {
            256
        } else {
            std::cmp::max(256, self.highest as u64 + 257)
        };

        for tw_off in [0i64, -1, 1] {
            let tw = (base_tw as i64 + tw_off) as u64;
            for c in start..end {
                if !self.is_new(c) {
                    continue;
                }
                let expected = generate_resonance_tag(&keys.tag_secret, c, tw);
                if tag == &expected {
                    return Some(c);
                }
            }
        }
        None
    }
}

// ──────────── Helpers ────────────

fn counter_to_nonce(counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

fn monotonic_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
