#!/usr/bin/env bash
set -euo pipefail

echo "=== CodexBar Linux Installer ==="
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "ERROR: Python 3 is required. Install it with:"
    echo "  sudo apt install python3 python3-pip python3-tk"
    exit 1
fi

# Check tkinter
python3 -c "import tkinter" 2>/dev/null || {
    echo "ERROR: tkinter not found. Install it with:"
    echo "  Ubuntu/Debian: sudo apt install python3-tk"
    echo "  Fedora:        sudo dnf install python3-tkinter"
    echo "  Arch:          sudo pacman -S tk"
    exit 1
}

# Install system dependencies for pystray (AppIndicator)
echo "[1/3] Checking system tray support..."
if command -v apt &>/dev/null; then
    # Debian/Ubuntu
    PKGS=""
    dpkg -l | grep -q libgirepository || PKGS="$PKGS libgirepository1.0-dev"
    dpkg -l | grep -q gir1.2-ayatanaappindicator3 || PKGS="$PKGS gir1.2-ayatanaappindicator3-0.1"
    if [ -n "$PKGS" ]; then
        echo "  Installing system packages:$PKGS"
        sudo apt install -y $PKGS
    fi
elif command -v dnf &>/dev/null; then
    # Fedora
    rpm -q libappindicator-gtk3 &>/dev/null || sudo dnf install -y libappindicator-gtk3
elif command -v pacman &>/dev/null; then
    # Arch
    pacman -Q libappindicator-gtk3 &>/dev/null || sudo pacman -S --noconfirm libappindicator-gtk3
fi

# Install Python dependencies
echo "[2/3] Installing Python packages..."
pip install --user -r requirements.txt

# Create desktop entry
echo "[3/3] Creating desktop entry..."
INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"

mkdir -p ~/.local/share/applications
cat > ~/.local/share/applications/codexbar.desktop << DESKTOP
[Desktop Entry]
Type=Application
Name=CodexBar
Comment=System tray monitor for Claude Code and OpenAI Codex usage
Exec=python3 ${INSTALL_DIR}/codexbar.py
Icon=${INSTALL_DIR}/assets/claude-logo.png
Terminal=false
Categories=Utility;Development;
StartupNotify=false
X-GNOME-Autostart-enabled=true
DESKTOP

# Also add to autostart
mkdir -p ~/.config/autostart
cp ~/.local/share/applications/codexbar.desktop ~/.config/autostart/codexbar.desktop

echo ""
echo "=== Installation complete! ==="
echo ""
echo "  Run now:      python3 ${INSTALL_DIR}/codexbar.py"
echo "  Or launch:    CodexBar (from app menu)"
echo "  Auto-start:   enabled (disable in Startup Applications)"
echo ""
