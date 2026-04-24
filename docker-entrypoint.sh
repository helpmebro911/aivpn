#!/bin/sh
set -eu

CONFIG_DIR="/etc/aivpn"
CONFIG_PATH="$CONFIG_DIR/server.json"
CONFIG_TEMPLATE="/usr/share/aivpn/server.json.example"
KEY_PATH="$CONFIG_DIR/server.key"

mkdir -p "$CONFIG_DIR" /var/lib/aivpn/masks

# Seed preset masks on first run (won't overwrite existing files)
PRESET_DIR="/usr/share/aivpn/preset-masks"
if [ -d "$PRESET_DIR" ]; then
    for f in "$PRESET_DIR"/*.json; do
        [ -f "$f" ] || continue
        base="$(basename "$f")"
        if [ ! -f "/var/lib/aivpn/masks/$base" ]; then
            cp "$f" "/var/lib/aivpn/masks/$base"
            echo "Seeded preset mask: $base"
        fi
    done
fi

if [ ! -f "$CONFIG_PATH" ]; then
    cp "$CONFIG_TEMPLATE" "$CONFIG_PATH"
    echo "Initialized $CONFIG_PATH from bundled template"
fi

if [ ! -f "$KEY_PATH" ]; then
    umask 077
    head -c 32 /dev/urandom > "$KEY_PATH"
    echo "Generated $KEY_PATH"
fi

# Default log level to info if not set (prevents debug-level log floods)
export RUST_LOG="${RUST_LOG:-info}"

exec /usr/local/bin/aivpn-server "$@"