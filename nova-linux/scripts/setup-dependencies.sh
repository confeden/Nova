#!/usr/bin/env bash
set -e

# Nova Linux - Dependency Setup Script
# Checks and downloads sing-box and ByeDPI (ciadpi) binaries if not present in system.

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo "Root privileges required."
        exit 1
    fi
fi

BIN_DIR="/usr/local/bin"
TEMP_DIR="/tmp/nova_setup"
mkdir -p "$TEMP_DIR"

echo "=== Nova Linux: Checking Network Core Dependencies ==="

# 1. Check nftables
if command -v nft >/dev/null 2>&1; then
    echo "[OK] nftables is installed: $(nft --version | head -n 1)"
else
    echo "[WARN] nftables is missing. Installing via package manager..."
    if command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get update && $SUDO apt-get install -y nftables iproute2
    elif command -v pacman >/dev/null 2>&1; then
        $SUDO pacman -Sy --noconfirm nftables iproute2
    elif command -v dnf >/dev/null 2>&1; then
        $SUDO dnf install -y nftables iproute
    fi
fi

# 2. Check sing-box
if command -v sing-box >/dev/null 2>&1; then
    echo "[OK] sing-box found: $(sing-box version | head -n 1)"
else
    echo "[INSTALL] Downloading official sing-box binary..."
    SINGBOX_VER="1.11.4"
    ARCH="linux-amd64"
    URL="https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VER}/sing-box-${SINGBOX_VER}-${ARCH}.tar.gz"
    
    curl -sL "$URL" -o "$TEMP_DIR/sing-box.tar.gz"
    tar -xzf "$TEMP_DIR/sing-box.tar.gz" -C "$TEMP_DIR"
    $SUDO cp "$TEMP_DIR/sing-box-${SINGBOX_VER}-${ARCH}/sing-box" "$BIN_DIR/sing-box"
    $SUDO chmod +x "$BIN_DIR/sing-box"
    echo "[OK] sing-box installed to $BIN_DIR/sing-box"
fi

# 3. Check ByeDPI (ciadpi)
if command -v ciadpi >/dev/null 2>&1; then
    echo "[OK] ByeDPI (ciadpi) found: $(ciadpi -v 2>&1 | head -n 1 || echo 'Installed')"
else
    echo "[INSTALL] Downloading official ByeDPI binary..."
    BYEDPI_VER="0.17.3"
    BYEDPI_FILE="byedpi-17.3-x86_64.tar.gz"
    URL="https://github.com/hufrea/byedpi/releases/download/v${BYEDPI_VER}/${BYEDPI_FILE}"
    
    if curl -sL "$URL" -o "$TEMP_DIR/byedpi.tar.gz"; then
        tar -xzf "$TEMP_DIR/byedpi.tar.gz" -C "$TEMP_DIR"
        $SUDO cp "$TEMP_DIR/ciadpi-x86_64" "$BIN_DIR/ciadpi" || $SUDO cp "$TEMP_DIR/ciadpi" "$BIN_DIR/ciadpi"
        $SUDO chmod +x "$BIN_DIR/ciadpi"
        echo "[OK] ciadpi installed to $BIN_DIR/ciadpi"
    else
        echo "[WARN] Could not download pre-compiled ciadpi. You can install it via package manager or compile with 'make'."
    fi
fi

rm -rf "$TEMP_DIR"
echo "=== All Core Dependencies Ready ==="
