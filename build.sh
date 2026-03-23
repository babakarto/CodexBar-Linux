#!/usr/bin/env bash
set -euo pipefail

echo "=== CodexBar Linux Build ==="

# Install dependencies
echo "[1/4] Installing dependencies..."
python3 -m pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

# Generate icon (PNG for Linux — no .ico needed)
echo "[2/4] Generating icon..."
python3 -c "
from PIL import Image
img = Image.open('assets/claude-logo.png').convert('RGBA')
# Save as PNG (used by pystray on Linux)
img.resize((256, 256), Image.LANCZOS).save('assets/codexbar.png')
print('Icon generated: assets/codexbar.png')
"

# Build
echo "[3/4] Building with PyInstaller..."
pyinstaller --onefile \
    --noconsole \
    --name "CodexBar" \
    --icon "assets/codexbar.png" \
    --add-data "assets:assets" \
    --hidden-import pystray._appindicator \
    --hidden-import pystray._xorg \
    --hidden-import customtkinter \
    --hidden-import ptyprocess \
    --hidden-import secretstorage \
    --collect-data customtkinter \
    codexbar.py

# Verify
echo "[4/4] Verifying build..."
if [ -f "dist/CodexBar" ]; then
    SIZE=$(du -sh dist/CodexBar | cut -f1)
    echo "SUCCESS: dist/CodexBar ($SIZE)"
else
    echo "FAILED: dist/CodexBar not found"
    exit 1
fi

echo ""
echo "=== Build complete! ==="
echo "Run with: ./dist/CodexBar"
