#!/usr/bin/env bash
set -e

# Nova Linux - Master Installation Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo "Root privileges required."
        exit 1
    fi
fi

echo "=== Installing Nova Linux ==="

# 1. Run dependencies setup
bash "$SCRIPT_DIR/setup-dependencies.sh"

# 2. Build binaries if in source repository
if [ -f "$PROJECT_ROOT/Cargo.toml" ]; then
    echo "[BUILD] Building novad daemon (release)..."
    cargo build --release -p novad --manifest-path "$PROJECT_ROOT/Cargo.toml"
    $SUDO cp "$PROJECT_ROOT/target/release/novad" /usr/local/bin/novad
    $SUDO chmod +x /usr/local/bin/novad

    if command -v npm >/dev/null 2>&1; then
        echo "[BUILD] Building nova-gui (release)..."
        cargo build --release -p nova-gui --manifest-path "$PROJECT_ROOT/Cargo.toml" || true
        if [ -f "$PROJECT_ROOT/target/release/nova-gui" ]; then
            $SUDO cp "$PROJECT_ROOT/target/release/nova-gui" /usr/local/bin/nova
            $SUDO chmod +x /usr/local/bin/nova
        fi
    fi
fi

# 3. Setup systemd daemon
echo "[CONFIG] Installing systemd service..."
$SUDO mkdir -p /run/nova /etc/nova
$SUDO cp "$SCRIPT_DIR/novad.service" /etc/systemd/system/novad.service
$SUDO systemctl daemon-reload || true
$SUDO systemctl enable --now novad || true

# 4. Install Desktop Entry
echo "[CONFIG] Installing desktop application entry..."
$SUDO tee /usr/share/applications/nova.desktop > /dev/null <<EOF
[Desktop Entry]
Name=Nova
Comment=Adaptive Traffic & DPI Bypass Core
Exec=/usr/local/bin/nova
Icon=nova
Terminal=false
Type=Application
Categories=Network;Security;Utility;
Keywords=dpi;vpn;proxy;zapret;byedpi;singbox;
EOF

echo ""
echo "=========================================================="
echo "  🌌 Nova Linux successfully installed and activated!"
echo "  Daemon status: sudo systemctl status novad"
echo "  Run GUI:       nova"
echo "=========================================================="
