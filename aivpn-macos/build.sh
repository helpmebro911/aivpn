#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$SCRIPT_DIR/build"
APP_BUNDLE="$BUILD_DIR/Aivpn.app"
SIGNED_APP_BUNDLE=""
CONTENTS="$APP_BUNDLE/Contents"
MACOS="$CONTENTS/MacOS"
RESOURCES="$CONTENTS/Resources"
HELPER_BUILD="$BUILD_DIR/helper"
PKG_BUILD="$BUILD_DIR/pkg"
PKG_ROOT="$PKG_BUILD/root"
PKG_SCRIPTS="$PKG_BUILD/scripts"

SWIFT_SOURCES=(
    "$SCRIPT_DIR/AivpnApp.swift"
    "$SCRIPT_DIR/ContentView.swift"
    "$SCRIPT_DIR/VPNManager.swift"
    "$SCRIPT_DIR/LocalizationManager.swift"
    "$SCRIPT_DIR/KeychainHelper.swift"
    "$SCRIPT_DIR/ConnectionKey.swift"
)

HELPER_SOURCES=(
    "$SCRIPT_DIR/aivpn-helper/main.swift"
)

echo "🔨 Building AIVPN macOS v0.3.0 (Universal Binary + PKG)..."

# ──────────────────────────────────────────────
# Clean
# ──────────────────────────────────────────────
rm -rf "$BUILD_DIR"
mkdir -p "$MACOS" "$RESOURCES" "$BUILD_DIR/arm64" "$BUILD_DIR/x86_64"
mkdir -p "$HELPER_BUILD/arm64" "$HELPER_BUILD/x86_64"
mkdir -p "$PKG_ROOT/Library/Application Support/AIVPN"
mkdir -p "$PKG_ROOT/Library/PrivilegedHelperTools"
mkdir -p "$PKG_ROOT/Library/LaunchDaemons"
mkdir -p "$PKG_ROOT/Applications"
mkdir -p "$PKG_SCRIPTS"

# ──────────────────────────────────────────────
# Compile GUI app for arm64
# ──────────────────────────────────────────────
echo "📦 Compiling GUI for arm64 (Apple Silicon)..."
swiftc \
    -o "$BUILD_DIR/arm64/Aivpn" \
    -target arm64-apple-macosx13.0 \
    -parse-as-library \
    -framework Cocoa \
    -framework SwiftUI \
    -framework Security \
    -framework Foundation \
    -module-name Aivpn \
    "${SWIFT_SOURCES[@]}"

# ──────────────────────────────────────────────
# Compile GUI app for x86_64
# ──────────────────────────────────────────────
echo "📦 Compiling GUI for x86_64 (Intel)..."
swiftc \
    -o "$BUILD_DIR/x86_64/Aivpn" \
    -target x86_64-apple-macosx13.0 \
    -parse-as-library \
    -framework Cocoa \
    -framework SwiftUI \
    -framework Security \
    -framework Foundation \
    -module-name Aivpn \
    "${SWIFT_SOURCES[@]}"

# ──────────────────────────────────────────────
# Create universal GUI binary
# ──────────────────────────────────────────────
echo "🔗 Creating universal GUI binary..."
lipo -create \
    "$BUILD_DIR/arm64/Aivpn" \
    "$BUILD_DIR/x86_64/Aivpn" \
    -output "$MACOS/Aivpn"
echo "  ✅ $(file "$MACOS/Aivpn" | sed 's/.*: //')"

# ──────────────────────────────────────────────
# Compile helper daemon for arm64
# ──────────────────────────────────────────────
echo "📦 Compiling helper daemon for arm64..."
swiftc \
    -o "$HELPER_BUILD/arm64/aivpn-helper" \
    -target arm64-apple-macosx13.0 \
    -O \
    "${HELPER_SOURCES[@]}"

# ──────────────────────────────────────────────
# Compile helper daemon for x86_64
# ──────────────────────────────────────────────
echo "📦 Compiling helper daemon for x86_64..."
swiftc \
    -o "$HELPER_BUILD/x86_64/aivpn-helper" \
    -target x86_64-apple-macosx13.0 \
    -O \
    "${HELPER_SOURCES[@]}"

# ──────────────────────────────────────────────
# Create universal helper binary
# ──────────────────────────────────────────────
echo "🔗 Creating universal helper binary..."
# lipo writes a temporary file next to the output path; use /tmp to avoid
# permission issues inside the pkg root directory.
HELPER_UNIVERSAL_TMP="$(mktemp /tmp/aivpn-helper.XXXXXX)"
lipo -create \
    "$HELPER_BUILD/arm64/aivpn-helper" \
    "$HELPER_BUILD/x86_64/aivpn-helper" \
    -output "$HELPER_UNIVERSAL_TMP"
cp "$HELPER_UNIVERSAL_TMP" "$PKG_ROOT/Library/PrivilegedHelperTools/aivpn-helper"
rm -f "$HELPER_UNIVERSAL_TMP"
chmod 755 "$PKG_ROOT/Library/PrivilegedHelperTools/aivpn-helper"
echo "  ✅ $(file "$PKG_ROOT/Library/PrivilegedHelperTools/aivpn-helper" | sed 's/.*: //')"

# ──────────────────────────────────────────────
# Copy LaunchDaemon plist
# ──────────────────────────────────────────────
echo "📋 Installing LaunchDaemon plist..."
cp "$SCRIPT_DIR/aivpn-helper/com.aivpn.helper.plist" \
   "$PKG_ROOT/Library/LaunchDaemons/com.aivpn.helper.plist"
chmod 644 "$PKG_ROOT/Library/LaunchDaemons/com.aivpn.helper.plist"

# ──────────────────────────────────────────────
# Bundle aivpn-client binary into app
# ──────────────────────────────────────────────
echo "📦 Bundling aivpn-client binary..."
CLIENT_BIN_UNIVERSAL="$PROJECT_DIR/releases/aivpn-client-universal"
CLIENT_BIN_X86="$PROJECT_DIR/target/release/aivpn-client"
CLIENT_BIN_ARM="$PROJECT_DIR/target/aarch64-apple-darwin/release/aivpn-client"

if [ -f "$CLIENT_BIN_X86" ] && [ -f "$CLIENT_BIN_ARM" ]; then
    echo "  🔄 Creating Universal Binary from x86_64 + arm64..."
    lipo -create "$CLIENT_BIN_X86" "$CLIENT_BIN_ARM" -output "$RESOURCES/aivpn-client"
    chmod +x "$RESOURCES/aivpn-client"
    echo "  ✅ aivpn-client bundled (Universal Binary: $(file "$RESOURCES/aivpn-client" | sed 's/.*: //'))"
elif [ -f "$CLIENT_BIN_X86" ]; then
    cp "$CLIENT_BIN_X86" "$RESOURCES/aivpn-client"
    chmod +x "$RESOURCES/aivpn-client"
    echo "  ⚠️  aivpn-client bundled (x86_64 only)"
elif [ -f "$CLIENT_BIN_UNIVERSAL" ]; then
    cp "$CLIENT_BIN_UNIVERSAL" "$RESOURCES/aivpn-client"
    chmod +x "$RESOURCES/aivpn-client"
    echo "  ⚠️  aivpn-client bundled from fallback universal artifact"
else
    echo "  ⚠️  aivpn-client not found"
    echo "  Run 'cargo build --release --bin aivpn-client' first"
fi

# ──────────────────────────────────────────────
# Copy Info.plist
# ──────────────────────────────────────────────
cp "$SCRIPT_DIR/Info.plist" "$CONTENTS/Info.plist"

# ──────────────────────────────────────────────
# Copy app icon
# ──────────────────────────────────────────────
if [ -f "/tmp/Aivpn.icns" ]; then
    cp /tmp/Aivpn.icns "$RESOURCES/AppIcon.icns"
    echo "  ✅ App icon bundled"
elif [ -f "$SCRIPT_DIR/AppIcon.icns" ]; then
    cp "$SCRIPT_DIR/AppIcon.icns" "$RESOURCES/AppIcon.icns"
    echo "  ✅ App icon bundled"
fi

# ──────────────────────────────────────────────
# Create PkgInfo and Assets
# ──────────────────────────────────────────────
echo -n "APPL????" > "$CONTENTS/PkgInfo"

mkdir -p "$RESOURCES/Assets.xcassets/AppIcon.appiconset"
cat > "$RESOURCES/Assets.xcassets/AppIcon.appiconset/Contents.json" << 'EOF'
{
  "images" : [
    { "idiom" : "mac", "scale" : "1x", "size" : "16x16" },
    { "idiom" : "mac", "scale" : "2x", "size" : "16x16" },
    { "idiom" : "mac", "scale" : "1x", "size" : "32x32" },
    { "idiom" : "mac", "scale" : "2x", "size" : "32x32" },
    { "idiom" : "mac", "scale" : "1x", "size" : "128x128" },
    { "idiom" : "mac", "scale" : "2x", "size" : "128x128" },
    { "idiom" : "mac", "scale" : "1x", "size" : "256x256" },
    { "idiom" : "mac", "scale" : "2x", "size" : "256x256" },
    { "idiom" : "mac", "scale" : "1x", "size" : "512x512" },
    { "idiom" : "mac", "scale" : "2x", "size" : "512x512" }
  ],
  "info" : { "author" : "xcode", "version" : 1 }
}
EOF

cat > "$RESOURCES/Assets.xcassets/Contents.json" << 'EOF'
{ "info" : { "author" : "xcode", "version" : 1 } }
EOF

# ──────────────────────────────────────────────
# Sign app (ad-hoc, required for macOS Sequoia)
# ──────────────────────────────────────────────
echo "🔐 Signing app..."
SIGNED_APP_BUNDLE="$(mktemp -d /tmp/aivpn-signed.XXXXXX)/Aivpn.app"
ditto "$APP_BUNDLE" "$SIGNED_APP_BUNDLE"
xattr -cr "$SIGNED_APP_BUNDLE" 2>/dev/null
codesign --force --deep --sign - "$SIGNED_APP_BUNDLE" 2>/dev/null
echo "  ✅ Signed ($(du -sh "$SIGNED_APP_BUNDLE" | cut -f1))"

# ──────────────────────────────────────────────
# Copy app into PKG root + aivpn-client to system path
# ──────────────────────────────────────────────
echo "📦 Staging PKG..."
cp -R "$SIGNED_APP_BUNDLE" "$PKG_ROOT/Applications/Aivpn.app"

# Copy aivpn-client to /Library/Application Support/AIVPN/ (helper default path)
if [ -f "$RESOURCES/aivpn-client" ]; then
    cp "$RESOURCES/aivpn-client" "$PKG_ROOT/Library/Application Support/AIVPN/aivpn-client"
    chmod 755 "$PKG_ROOT/Library/Application Support/AIVPN/aivpn-client"
    echo "  ✅ aivpn-client staged for system install"
fi

# ──────────────────────────────────────────────
# Copy install scripts
# ──────────────────────────────────────────────
cp "$SCRIPT_DIR/pkg-scripts/preinstall" "$PKG_SCRIPTS/preinstall"
cp "$SCRIPT_DIR/pkg-scripts/postinstall" "$PKG_SCRIPTS/postinstall"
chmod +x "$PKG_SCRIPTS/preinstall" "$PKG_SCRIPTS/postinstall"

# ──────────────────────────────────────────────
# Build PKG
# ──────────────────────────────────────────────
echo "📦 Building installer package..."
PKG_OUTPUT="$PROJECT_DIR/releases/aivpn-macos.pkg"

pkgbuild \
    --root "$PKG_ROOT" \
    --install-location "/" \
    --scripts "$PKG_SCRIPTS" \
    --identifier "com.aivpn.client" \
    --version "0.3.0" \
    --ownership "recommended" \
    "$PKG_OUTPUT"

echo "  ✅ Package created: $PKG_OUTPUT ($(du -sh "$PKG_OUTPUT" | cut -f1))"

# ──────────────────────────────────────────────
# Also create DMG for manual distribution
# ──────────────────────────────────────────────
echo "💿 Creating DMG..."
DMG_OUTPUT="$PROJECT_DIR/releases/aivpn-macos.dmg"
hdiutil create \
    -volname "AIVPN" \
    -srcfolder "$SIGNED_APP_BUNDLE" \
    -ov -format UDZO \
    "$DMG_OUTPUT"
echo "  ✅ DMG created: $DMG_OUTPUT ($(du -sh "$DMG_OUTPUT" | cut -f1))"

echo ""
echo "═══════════════════════════════════════════════════"
echo "✅ Build complete!"
echo ""
echo "  📦 Installer: $PKG_OUTPUT"
echo "  💿 DMG:       $DMG_OUTPUT"
echo "  🖥️  App:       $SIGNED_APP_BUNDLE"
echo ""
echo "To run (development):"
echo "  open $APP_BUNDLE"
echo ""
echo "To install (production):"
echo "  sudo installer -pkg $PKG_OUTPUT -target /"
echo "═══════════════════════════════════════════════════"
