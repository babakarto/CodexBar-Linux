# CodexBar for Linux

System tray app that monitors your **Claude Code** and **OpenAI Codex** usage in real-time.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Linux](https://img.shields.io/badge/Platform-Linux-orange)
![License](https://img.shields.io/badge/License-MIT-green)

> Linux port of [CodexBar-Win](https://github.com/babakarto/CodexBar-Win)

## Features

- Real-time session & weekly usage percentages
- Usage reset countdowns
- Daily and 30-day API cost tracking
- Tabbed interface: Claude + OpenAI Codex
- System tray icon with popup panel
- Auto-refresh every 5 minutes

## Data Sources (priority order)

1. **CLI** — Spawns `claude /usage` via PTY
2. **OAuth** — Reads `~/.claude/.credentials.json`
3. **Browser cookies** — Decrypts `sessionKey` from Chrome/Chromium/Brave
4. **JSONL logs** — Parses `~/.claude/projects/` for cost data

## Quick Start

### From source

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt install python3 python3-pip python3-tk gir1.2-ayatanaappindicator3-0.1

# Install Python packages
pip install -r requirements.txt

# Run
python3 codexbar.py
```

### One-liner install

```bash
git clone https://github.com/babakarto/CodexBar-Linux.git
cd CodexBar-Linux
chmod +x install.sh && ./install.sh
```

### Pre-built binary

Download `CodexBar` from [Releases](https://github.com/babakarto/CodexBar-Linux/releases), then:

```bash
chmod +x CodexBar
./CodexBar
```

## Build from source

```bash
chmod +x build.sh
./build.sh
# Output: dist/CodexBar
```

## System Requirements

- Python 3.10+
- Linux with X11 or Wayland (GNOME, KDE, XFCE, etc.)
- System tray support (AppIndicator or XOrg tray)
- `python3-tk` for the GUI

### Optional (for cookie decryption)

- `libsecret` / GNOME Keyring (auto-detected)
- `cryptography` Python package (installed via requirements.txt)

## Differences from Windows version

| Feature | Windows | Linux |
|---------|---------|-------|
| PTY | pywinpty | ptyprocess |
| Cookie crypto | DPAPI + AES-256-GCM | Keyring + AES-128-CBC |
| Window effects | DWM glass/blur | Standard tkinter |
| System tray | Win32 | AppIndicator / XOrg |
| Fonts | Segoe UI | System font (auto-detected) |
| File lock bypass | CreateFileW | shutil.copy2 |
