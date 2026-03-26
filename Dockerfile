# AIVPN Server Production Dockerfile
# Multi-stage build for minimal image size

# Stage 1: Build
FROM rust:1.86-slim AS builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace
COPY Cargo.toml ./
COPY aivpn-common aivpn-common/
COPY aivpn-server aivpn-server/
COPY aivpn-client aivpn-client/

# Build in release mode (Cargo.lock is auto-generated if missing)
RUN cargo build --release --bin aivpn-server

# Stage 2: Runtime
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 aivpn

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/aivpn-server /usr/local/bin/aivpn-server

# Create config directory and TUN device node
RUN mkdir -p /etc/aivpn /dev/net && \
    mknod /dev/net/tun c 10 200 2>/dev/null || true && \
    chmod 600 /dev/net/tun

# Copy example config
COPY config/server.json.example /etc/aivpn/server.json

# Expose port
EXPOSE 443/udp

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD test "$(basename "$(readlink /proc/1/exe 2>/dev/null)")" = "aivpn-server" || exit 1

# Run as root (required for TUN device and NAT)
ENTRYPOINT ["/usr/local/bin/aivpn-server"]
CMD ["--listen", "0.0.0.0:443", "--key-file", "/etc/aivpn/server.key"]
