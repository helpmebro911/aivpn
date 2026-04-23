#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PACKAGE_KIND="${1:-}"
TARGET="${2:-}"

usage() {
    cat <<'EOF'
Usage: ./build-musl-release.sh <server|client> <target>

Supported targets:
  - armv7-unknown-linux-musleabihf
  - mipsel-unknown-linux-musl

Examples:
  ./build-musl-release.sh server armv7-unknown-linux-musleabihf
  ./build-musl-release.sh client mipsel-unknown-linux-musl
EOF
}

if [ -z "$PACKAGE_KIND" ] || [ -z "$TARGET" ]; then
    usage
    exit 1
fi

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Error: required command '$1' is not installed" >&2
        exit 1
    fi
}

case "$PACKAGE_KIND" in
    server)
        CRATE_NAME="aivpn-server"
        BINARY_NAME="aivpn-server"
        ;;
    client)
        CRATE_NAME="aivpn-client"
        BINARY_NAME="aivpn-client"
        ;;
    *)
        echo "Error: unsupported package kind '$PACKAGE_KIND'" >&2
        usage
        exit 1
        ;;
esac

case "$TARGET" in
    armv7-unknown-linux-musleabihf)
        IMAGE_TAG="armv7-musleabihf"
        ARTIFACT_PATH="releases/${BINARY_NAME}-linux-armv7-musleabihf"
        ;;
    mipsel-unknown-linux-musl)
        IMAGE_TAG="mipsel-musl"
        ARTIFACT_PATH="releases/${BINARY_NAME}-linux-mipsel-musl"
        ;;
    *)
        echo "Error: unsupported target '$TARGET'" >&2
        usage
        exit 1
        ;;
esac

require_command docker

IMAGE_NAME="aivpn-${BINARY_NAME}-${TARGET//[^a-zA-Z0-9]/-}:musl-release"
CONTAINER_NAME="aivpn-${BINARY_NAME}-${TARGET//[^a-zA-Z0-9]/-}-$RANDOM-$RANDOM"

cleanup() {
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}

trap cleanup EXIT

echo "=== Building ${BINARY_NAME} for ${TARGET} (musl static) ==="
echo ""
echo "Using Docker image: messense/rust-musl-cross:${IMAGE_TAG}"

mkdir -p releases

docker build \
    --build-arg MUSL_IMAGE_TAG="$IMAGE_TAG" \
    --build-arg TARGET_TRIPLE="$TARGET" \
    --build-arg CRATE_NAME="$CRATE_NAME" \
    --build-arg BINARY_NAME="$BINARY_NAME" \
    -t "$IMAGE_NAME" \
    -f - \
    . <<'EOF'
ARG MUSL_IMAGE_TAG
FROM messense/rust-musl-cross:${MUSL_IMAGE_TAG} AS builder

ARG TARGET_TRIPLE
ARG CRATE_NAME
ARG BINARY_NAME

WORKDIR /app

COPY Cargo.toml ./
COPY aivpn-common aivpn-common/
COPY aivpn-server aivpn-server/
COPY aivpn-client aivpn-client/
COPY aivpn-android-core aivpn-android-core/
COPY aivpn-windows aivpn-windows/
COPY mask-assets mask-assets/

RUN cargo build --release --target "$TARGET_TRIPLE" -p "$CRATE_NAME" --bin "$BINARY_NAME"
EOF

docker create --name "$CONTAINER_NAME" "$IMAGE_NAME" >/dev/null
docker cp "$CONTAINER_NAME:/app/target/${TARGET}/release/${BINARY_NAME}" "$ARTIFACT_PATH"
chmod +x "$ARTIFACT_PATH"

echo ""
echo "=== Artifact Ready ==="
ls -lh "$ARTIFACT_PATH"
file "$ARTIFACT_PATH" || true