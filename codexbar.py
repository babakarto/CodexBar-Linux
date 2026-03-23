"""
CodexBar for Linux v1.0.0
============================
System tray app that shows your REAL Claude usage.
Native customtkinter popup — no browser hack needed.

Requirements: pip install pystray Pillow customtkinter ptyprocess cryptography secretstorage
Usage: python codexbar.py
"""

import os
import sys
import json
import time
import re
import sqlite3
import shutil
import subprocess
import threading
import base64
import tempfile
import webbrowser
from pathlib import Path
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

try:
    from PIL import Image, ImageDraw
except ImportError:
    print("ERROR: Pillow not found. Run: pip install Pillow")
    sys.exit(1)

try:
    import pystray
    from pystray import MenuItem, Menu
except ImportError:
    print("ERROR: pystray not found. Run: pip install pystray")
    sys.exit(1)

try:
    import customtkinter as ctk
except ImportError:
    print("ERROR: customtkinter not found. Run: pip install customtkinter")
    sys.exit(1)

try:
    from ptyprocess import PtyProcess
except ImportError:
    PtyProcess = None
    print("[CodexBar] ptyprocess not found (pip install ptyprocess). CLI /usage disabled.")

# ── Linux font detection ──
_LINUX_FONTS = ["Ubuntu", "Cantarell", "Noto Sans", "DejaVu Sans", "Liberation Sans", "Sans"]

def _pick_font():
    """Pick the first available font on this Linux system."""
    try:
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()
        available = set(tk.font.families())
        root.destroy()
        for f in _LINUX_FONTS:
            if f in available:
                return f
    except Exception:
        pass
    return "Sans"

# Lazy-init: resolved on first use
_FONT = None

def _font():
    global _FONT
    if _FONT is None:
        _FONT = _pick_font()
    return _FONT


def _resource_path(relative_path):
    """Get absolute path to resource — works for dev and PyInstaller binary."""
    if getattr(sys, 'frozen', False):
        base = Path(sys._MEIPASS)
    else:
        base = Path(__file__).parent
    return base / relative_path


# ─────────────────────────────────────────────
# Chromium cookie decryptor  (Linux: PBKDF2 + AES-128-CBC)
# ─────────────────────────────────────────────

class _CookieDecryptor:
    """Read and decrypt the sessionKey cookie from Chrome, Chromium, or Brave on Linux.

    On Linux, Chromium encrypts cookies with AES-128-CBC (``v10``/``v11`` prefix).
    The encryption password comes from:
      1. GNOME Keyring (via secretstorage / D-Bus) — stored as 'Chrome Safe Storage'
      2. KWallet (via dbus) — stored as 'Chrome Keys'
      3. Hardcoded fallback: 'peanuts' (when no keyring is available)

    The key is derived via PBKDF2-HMAC-SHA1 with salt='saltysalt', iterations=1.
    """

    _CONFIG = os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
    BROWSERS = [
        ("Chrome",   Path(_CONFIG) / "google-chrome"   / "Default" / "Cookies",
                     Path(_CONFIG) / "google-chrome"   / "Local State"),
        ("Chromium", Path(_CONFIG) / "chromium"         / "Default" / "Cookies",
                     Path(_CONFIG) / "chromium"         / "Local State"),
        ("Brave",    Path(_CONFIG) / "BraveSoftware"   / "Brave-Browser" / "Default" / "Cookies",
                     Path(_CONFIG) / "BraveSoftware"   / "Brave-Browser" / "Local State"),
    ]

    # ── public entry point ──────────────────────

    @classmethod
    def get_session_key(cls):
        """Return ``(cookie_value, browser_name)`` or ``(None, None)``."""
        for name, cookie_db, local_state in cls.BROWSERS:
            if not cookie_db.exists():
                # Chromium 96+ moved Cookies to Network/Cookies
                alt = cookie_db.parent / "Network" / "Cookies"
                if alt.exists():
                    cookie_db = alt
                else:
                    continue
            try:
                password = cls._get_password(name)
                if password is None:
                    print(f"    {name}: could not get encryption password")
                    continue
                key = cls._derive_key(password)
                value = cls._read_cookie(cookie_db, key)
                if value:
                    return value, name
            except Exception as e:
                print(f"    {name} cookie err: {e}")
        return None, None

    # ── get password from keyring ─────────────

    @classmethod
    def _get_password(cls, browser_name):
        """Get the encryption password from the system keyring."""
        # Try GNOME Keyring via secretstorage
        try:
            import secretstorage
            bus = secretstorage.dbus_init()
            collection = secretstorage.get_default_collection(bus)
            if collection.is_locked():
                collection.unlock()
            # Chrome stores as 'Chrome Safe Storage', Chromium as 'Chromium Safe Storage'
            label = f"{browser_name} Safe Storage"
            for item in collection.get_all_items():
                if item.get_label() == label:
                    return item.get_secret().decode("utf-8")
        except Exception as e:
            print(f"    secretstorage ({browser_name}): {e}")

        # Try KWallet via subprocess
        try:
            folder = "Chrome Keys" if browser_name == "Chrome" else f"{browser_name} Keys"
            result = subprocess.run(
                ["kwallet-query", "-f", folder, "-r", f"{browser_name} Safe Storage", "kdewallet"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass

        # Fallback: hardcoded password used when no keyring
        print(f"    {browser_name}: using fallback password 'peanuts'")
        return "peanuts"

    # ── key derivation ────────────────────────

    @staticmethod
    def _derive_key(password):
        """Derive AES-128-CBC key using PBKDF2."""
        try:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA1(),
                length=16,
                salt=b"saltysalt",
                iterations=1,
            )
            return kdf.derive(password.encode("utf-8"))
        except ImportError:
            # Fallback to hashlib
            import hashlib
            return hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"),
                                       b"saltysalt", 1, dklen=16)

    # ── AES-128-CBC decryption ────────────────

    @staticmethod
    def _aes_cbc_decrypt(key, ciphertext):
        """Decrypt AES-128-CBC with IV = 16 spaces."""
        iv = b" " * 16
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            # Remove PKCS7 padding
            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(padded) + unpadder.finalize()
        except ImportError:
            # Fallback: won't work without cryptography
            print("    WARNING: 'cryptography' package not installed, cannot decrypt cookies")
            return None

    # ── read cookie from DB ───────────────────

    @classmethod
    def _read_cookie(cls, cookie_db, key):
        """Query the Cookies SQLite DB and decrypt the sessionKey value."""
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        tmp.close()
        try:
            shutil.copy2(cookie_db, tmp.name)
            conn = sqlite3.connect(tmp.name)
            conn.text_factory = bytes
            rows = conn.execute(
                "SELECT encrypted_value, value "
                "FROM cookies "
                "WHERE host_key IN ('.claude.ai','claude.ai') "
                "  AND name = 'sessionKey' "
                "ORDER BY last_access_utc DESC LIMIT 1"
            ).fetchall()
            conn.close()
            if not rows:
                return None
            enc_val, plain_val = rows[0]
            if plain_val and plain_val != b"":
                return plain_val.decode("utf-8", errors="replace")
            if not enc_val or len(enc_val) < 4:
                return None
            return cls._decrypt_value(enc_val, key)
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    @classmethod
    def _decrypt_value(cls, enc, key):
        prefix = enc[:3]
        # v10/v11: AES-128-CBC with PBKDF2-derived key
        if prefix in (b"v10", b"v11"):
            ciphertext = enc[3:]
            if len(ciphertext) < 16:
                return None
            plain = cls._aes_cbc_decrypt(key, ciphertext)
            if plain:
                return plain.decode("utf-8", errors="replace")
            return None
        # Unrecognized prefix
        print(f"      unknown cookie prefix: {prefix}")
        return None


# ─────────────────────────────────────────────
# Data fetcher
# ─────────────────────────────────────────────

class ClaudeDataFetcher:
    def __init__(self):
        self.data = self._empty()

    def _empty(self):
        return {
            "provider": "Claude", "plan": "Unknown", "updated": "Never",
            "session_used_pct": 0, "session_reset": "unknown",
            "weekly_used_pct": 0, "weekly_reset": "unknown",
            "opus_used_pct": 0,
            "cost_today": 0.0, "cost_today_tokens": "0",
            "cost_30d": 0.0, "cost_30d_tokens": "0",
            "source": "none", "error": None,
            "installed": False,
        }

    def _is_claude_installed(self):
        """Check if Claude Code is installed (CLI in PATH or ~/.claude exists)."""
        claude_dir = Path.home() / ".claude"
        if claude_dir.exists():
            return True
        if self._find_claude():
            return True
        if shutil.which("claude"):
            return True
        return False

    def fetch_all(self):
        print("[CodexBar] Fetching real usage data...")
        got_usage = False

        # 1) Try CLI
        cli = self._fetch_cli()
        if cli and cli.get("source") == "cli":
            self.data = cli
            got_usage = True
            print(f"  OK CLI: session {cli['session_used_pct']}%, weekly {cli['weekly_used_pct']}%")
        else:
            print("  -- CLI: not available")

        # 2) Try OAuth token from ~/.claude/.credentials.json
        if not got_usage:
            api = self._fetch_oauth_api()
            if api and api.get("source") == "api":
                self.data = api
                got_usage = True
                print(f"  OK OAuth: session {api['session_used_pct']}%, weekly {api['weekly_used_pct']}%")
            else:
                print("  -- OAuth: not available")

        # 3) Try browser cookie -> Claude API
        if not got_usage:
            api = self._fetch_cookie_api()
            if api and api.get("source") == "api":
                self.data = api
                got_usage = True
                print(f"  OK Cookie: session {api['session_used_pct']}%, weekly {api['weekly_used_pct']}%")
            else:
                print("  -- Cookie: not available")

        # 4) Always try JSONL for cost data
        cost = self._fetch_jsonl()
        if cost:
            self.data["cost_today"] = cost["cost_today"]
            self.data["cost_today_tokens"] = cost["cost_today_tokens"]
            self.data["cost_30d"] = cost["cost_30d"]
            self.data["cost_30d_tokens"] = cost["cost_30d_tokens"]
            if self.data["source"] == "none":
                self.data["source"] = "logs"
            print(f"  OK Logs: today ${cost['cost_today']:.2f}, 30d ${cost['cost_30d']:.2f}")
        else:
            print("  -- Logs: no JSONL found")

        self.data["updated"] = datetime.now().strftime("Updated %H:%M")
        self.data["installed"] = self._is_claude_installed()
        return self.data

    def _fetch_cli(self):
        """Spawn an interactive Claude session via PTY, send /usage, parse."""
        if PtyProcess is None:
            return None
        cmd = self._find_claude()
        if not cmd:
            return None
        try:
            raw = self._pty_usage(cmd)
            if raw and "%" in raw and ("session" in raw.lower() or "week" in raw.lower()):
                return self._parse_usage(raw)
        except Exception as e:
            print(f"    CLI err: {e}")
        return None

    @staticmethod
    def _pty_usage(cmd, startup_wait=5, trust_wait=3, cmd_wait=8):
        """Open claude in a PTY, send /usage, collect output, send /exit."""
        neutral_cwd = str(Path.home())
        proc = PtyProcess.spawn(
            [cmd],
            dimensions=(40, 120),
            cwd=neutral_cwd,
        )
        chunks = []
        stop = threading.Event()

        def reader():
            while not stop.is_set():
                try:
                    d = proc.read(8192)
                    if d:
                        chunks.append(d)
                except EOFError:
                    break
                except Exception:
                    time.sleep(0.1)

        t = threading.Thread(target=reader, daemon=True)
        t.start()

        try:
            time.sleep(startup_wait)
            proc.write("\n")
            time.sleep(trust_wait)
            proc.write("/usage\n")
            time.sleep(cmd_wait)
        finally:
            stop.set()
            try:
                proc.write("/exit\n")
            except Exception:
                pass
            time.sleep(1)
            try:
                proc.close(force=True)
            except Exception:
                pass
            t.join(timeout=3)

        return "".join(chunks)

    def _find_claude(self):
        places = [
            Path.home() / ".local" / "bin" / "claude",
            Path.home() / ".npm-global" / "bin" / "claude",
            Path.home() / ".nvm" / "current" / "bin" / "claude",
            Path("/usr/local/bin/claude"),
            Path("/usr/bin/claude"),
            Path.home() / ".claude" / "local" / "claude",
        ]
        # Also check common nvm paths
        nvm_dir = Path.home() / ".nvm" / "versions" / "node"
        if nvm_dir.exists():
            for node_ver in sorted(nvm_dir.iterdir(), reverse=True):
                p = node_ver / "bin" / "claude"
                if p.exists():
                    places.insert(0, p)
                    break

        for p in places:
            if p.exists():
                print(f"    Found claude: {p}")
                return str(p)
        r = shutil.which("claude")
        if r:
            print(f"    Found claude in PATH: {r}")
        return r

    def _parse_usage(self, raw):
        """Parse the /usage output from the interactive Claude CLI."""
        clean = re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', '', raw)
        clean = re.sub(r'\x1b\][^\x07\x1b]*[\x07]', '', clean)
        clean = re.sub(r'\x1b[()>][0-9A-Z]', '', clean)
        clean = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', clean)

        d = self._empty()
        d["source"] = "cli"

        clean = re.sub(r'(Current\s+session)', r'\n\1', clean, flags=re.I)
        clean = re.sub(r'(Current\s+week)', r'\n\1', clean, flags=re.I)
        clean = re.sub(r'(\d+\s*%\s*used)', r'\n\1', clean, flags=re.I)
        clean = re.sub(r'([Rr]es(?:et)?s?\s+\w)', r'\n\1', clean)

        lines = clean.split("\n")
        section = None

        for line in lines:
            lo = line.lower().strip()
            if "current session" in lo:
                section = "session"
            elif "current week" in lo and "sonnet" not in lo:
                section = "weekly"
            elif "sonnet" in lo and "week" in lo:
                section = "sonnet"
            if not section:
                continue

            m = re.search(r'(\d+)\s*%\s*used', line, re.I)
            if m:
                pct = int(m.group(1))
                if section == "session":
                    d["session_used_pct"] = pct
                elif section == "weekly":
                    d["weekly_used_pct"] = pct

            rm = re.search(r'[Rr]es[et]*s?\s*(.+)', line)
            if rm:
                val = rm.group(1).strip()
                val = re.sub(r'\s*Esc.*$', '', val).rstrip(". ")
                val = re.sub(r'\s*\([^)]*\)\s*$', '', val).strip()
                if val and len(val) > 2:
                    if section == "session":
                        d["session_reset"] = val
                    elif section == "weekly":
                        d["weekly_reset"] = val

        m = re.search(r'Claude\s*(Max|Pro|Team|Enterprise|Free)', clean, re.I)
        if m:
            d["plan"] = m.group(1).title()
        return d

    # ── OAuth token fetcher ───────────────────

    _CREDS_PATH = Path.home() / ".claude" / ".credentials.json"

    def _fetch_oauth_api(self):
        if not self._CREDS_PATH.exists():
            return None
        try:
            with open(self._CREDS_PATH, "r", encoding="utf-8") as f:
                creds = json.load(f)
            oauth = creds.get("claudeAiOauth") or {}
            token = oauth.get("accessToken")
            if not token:
                return None
            tier = oauth.get("rateLimitTier") or oauth.get("subscriptionType") or ""
            plan_local = tier.replace("default_claude_", "").replace("_", " ").title() or "Pro"
            print(f"    OAuth token found ({len(token)} chars), plan hint: {plan_local}")
        except Exception as e:
            print(f"    OAuth creds err: {e}")
            return None

        result = self._call_claude_api(
            auth_header=("Authorization", f"Bearer {token}"),
            plan_hint=plan_local,
            source_label="api",
        )
        if result is None and plan_local:
            self.data["plan"] = plan_local
        return result

    # ── cookie-based API fetcher ────────────────

    def _fetch_cookie_api(self):
        session_key, browser = _CookieDecryptor.get_session_key()
        if not session_key:
            return None
        print(f"    Got sessionKey from {browser} ({len(session_key)} chars)")
        return self._call_claude_api(
            auth_header=("Cookie", f"sessionKey={session_key}"),
            plan_hint=None,
            source_label="api",
        )

    # ── shared API call logic ──────────────────

    def _call_claude_api(self, *, auth_header, plan_hint, source_label):
        headers = {
            auth_header[0]: auth_header[1],
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/131.0.0.0 Safari/537.36",
            "Accept": "application/json",
        }
        try:
            req = Request("https://api.claude.ai/api/organizations", headers=headers)
            with urlopen(req, timeout=15) as resp:
                orgs = json.loads(resp.read())
        except (URLError, HTTPError, json.JSONDecodeError) as e:
            print(f"    API /organizations err: {e}")
            return None

        if not isinstance(orgs, list) or len(orgs) == 0:
            print("    API: empty org list")
            return None

        org = orgs[0]
        org_id = org.get("uuid") or org.get("id") or org.get("organization_id")
        if not org_id:
            print(f"    API: no org id in {list(org.keys())}")
            return None
        print(f"    Org: {org.get('name', '?')} ({org_id[:12]}...)")

        try:
            req = Request(
                f"https://api.claude.ai/api/organizations/{org_id}/usage",
                headers=headers)
            with urlopen(req, timeout=15) as resp:
                usage = json.loads(resp.read())
        except (URLError, HTTPError, json.JSONDecodeError) as e:
            print(f"    API /usage err: {e}")
            return None

        return self._parse_api_usage(usage, org, plan_hint, source_label)

    def _parse_api_usage(self, usage, org, plan_hint=None, source_label="api"):
        d = self._empty()
        d["source"] = source_label

        plan_found = False
        for key in ("rate_limit_tier", "plan", "billing_type"):
            v = org.get(key)
            if v:
                d["plan"] = str(v).replace("_", " ").replace("default claude ", "").title()
                plan_found = True
                break
        if not plan_found and plan_hint:
            d["plan"] = plan_hint

        def pct_from(blob, *keys):
            if blob is None:
                return None
            for k in keys:
                for suffix in ("_pct", "_percent", "_percentage", "_used_pct"):
                    v = blob.get(f"{k}{suffix}")
                    if v is not None:
                        return max(0, min(100, int(v)))
            used = blob.get("used") or blob.get("tokens_used") or 0
            limit = blob.get("limit") or blob.get("max_tokens") or blob.get("allowed") or 0
            if limit > 0:
                return max(0, min(100, int(used / limit * 100)))
            return None

        def reset_from(blob):
            if blob is None:
                return None
            for k in ("reset_at", "resets_at", "reset_time", "expires_at"):
                v = blob.get(k)
                if not v:
                    continue
                try:
                    dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
                    delta = dt - datetime.now(dt.tzinfo)
                    secs = max(0, int(delta.total_seconds()))
                    h, m = divmod(secs // 60, 60)
                    if h >= 24:
                        return f"{h // 24}d {h % 24}h"
                    return f"{h}h {m:02d}m"
                except Exception:
                    pass
            return None

        session_blob = (usage.get("daily_usage")
                        or usage.get("session_limit")
                        or usage.get("session")
                        or usage.get("messageLimit"))
        weekly_blob  = (usage.get("monthly_usage")
                        or usage.get("weekly_limit")
                        or usage.get("weekly")
                        or usage.get("longTermUsage"))

        sp = pct_from(session_blob, "daily", "session", "message", "used")
        wp = pct_from(weekly_blob,  "monthly", "weekly", "long_term", "used")

        if sp is None:
            sp = pct_from(usage, "daily", "session", "message")
        if wp is None:
            wp = pct_from(usage, "monthly", "weekly", "long_term")

        if sp is None and isinstance(session_blob, dict):
            rem = session_blob.get("remaining")
            tot = session_blob.get("total") or session_blob.get("limit")
            if rem is not None and tot:
                sp = max(0, min(100, int((1 - rem / tot) * 100)))

        if sp is not None:
            d["session_used_pct"] = sp
        if wp is not None:
            d["weekly_used_pct"] = wp

        sr = reset_from(session_blob) or reset_from(usage)
        wr = reset_from(weekly_blob)
        if sr:
            d["session_reset"] = sr
        if wr:
            d["weekly_reset"] = wr

        print(f"    API usage keys: {list(usage.keys())}")
        if session_blob and isinstance(session_blob, dict):
            print(f"    session blob keys: {list(session_blob.keys())}")
        return d

    def _fetch_jsonl(self):
        dirs = [Path.home() / ".claude" / "projects", Path.home() / ".claude"]
        total_in = total_out = total_cache = today_in = today_out = 0
        seen = set()
        today = datetime.now().date()
        nfiles = 0

        for d in dirs:
            if not d.exists(): continue
            for f in d.rglob("*.jsonl"):
                nfiles += 1
                try:
                    with open(f, 'r', encoding='utf-8', errors='ignore') as fh:
                        for line in fh:
                            line = line.strip()
                            if not line or len(line) < 10: continue
                            try: entry = json.loads(line)
                            except Exception: continue
                            if entry.get("type") != "assistant": continue
                            usage = entry.get("message",{}).get("usage",{})
                            if not usage: continue
                            mid = entry.get("message",{}).get("id","")
                            rid = entry.get("requestId","")
                            key = f"{mid}:{rid}"
                            if key in seen: continue
                            seen.add(key)
                            inp = usage.get("input_tokens",0)
                            out = usage.get("output_tokens",0)
                            cr = usage.get("cache_read_input_tokens",0)
                            cc = usage.get("cache_creation_input_tokens",0)
                            total_in += inp; total_out += out; total_cache += cr+cc
                            ts = entry.get("timestamp","")
                            if ts:
                                try:
                                    if datetime.fromisoformat(ts.replace("Z","+00:00")).date() == today:
                                        today_in += inp; today_out += out
                                except Exception: pass
                except Exception: continue

        print(f"    Scanned {nfiles} files, {len(seen)} messages")
        if total_in + total_out == 0: return None

        c30 = (total_in*3 + total_out*15 + total_cache*1.5) / 1e6
        ct = (today_in*3 + today_out*15) / 1e6

        def fmt(n):
            if n >= 1e6: return f"{n/1e6:.0f}M"
            if n >= 1e3: return f"{n/1e3:.0f}K"
            return str(n)

        return {
            "cost_today": round(ct,2), "cost_today_tokens": fmt(today_in+today_out),
            "cost_30d": round(c30,2), "cost_30d_tokens": fmt(total_in+total_out+total_cache),
        }


# ─────────────────────────────────────────────
# Tray icon
# ─────────────────────────────────────────────

def _load_logo(name="claude-logo.png", size=28):
    """Load and resize a logo from assets/."""
    logo_path = _resource_path("assets") / name
    if not logo_path.exists():
        return None
    try:
        img = Image.open(logo_path).convert("RGBA")
        w, h = img.size
        if w / h > 1.5:
            square = min(w, h)
            img = img.crop((0, 0, square, square))
        img = img.resize((size, size), Image.LANCZOS)
        return img
    except Exception:
        return None


def _make_openai_icon(size=28):
    """Generate a simple OpenAI-style icon (green hexagonal knot)."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    import math
    cx, cy = size / 2, size / 2
    r = size * 0.42
    pts = []
    for i in range(6):
        angle = math.radians(60 * i - 30)
        pts.append((cx + r * math.cos(angle), cy + r * math.sin(angle)))
    d.polygon(pts, outline=(16, 163, 127, 255), fill=None)
    lw = max(1, size // 14)
    for i in range(6):
        x1, y1 = pts[i]
        x2, y2 = pts[(i + 2) % 6]
        d.line([(x1, y1), (x2, y2)], fill=(16, 163, 127, 255), width=lw)
    for i in range(6):
        x1, y1 = pts[i]
        x2, y2 = pts[(i + 1) % 6]
        d.line([(x1, y1), (x2, y2)], fill=(16, 163, 127, 255), width=lw)
    return img


def make_icon(sp=1.0, wp=1.0, sz=64, provider="claude"):
    """Generate a system-tray icon for Claude or OpenAI."""
    if provider == "openai":
        logo = _load_logo("openai-icon.png", sz)
        if logo:
            return logo
        img = Image.new('RGBA', (sz, sz), (0, 0, 0, 0))
        ImageDraw.Draw(img).ellipse([4, 4, sz-4, sz-4], fill=(16, 163, 127, 255))
        return img

    img = Image.new('RGBA', (sz, sz), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    logo = _load_logo("claude-logo.png", sz)
    if logo:
        img.paste(logo, (0, 0), logo)
    else:
        d.ellipse([4, 4, sz - 4, sz - 4], fill=(217, 119, 87, 255))
    return img


# ─────────────────────────────────────────────
# OpenAI Codex data fetcher
# ─────────────────────────────────────────────

class CodexDataFetcher:
    """Fetch usage data from OpenAI Codex local session files (~/.codex/)."""

    CODEX_DIR = Path.home() / ".codex"

    @staticmethod
    def _empty():
        return {
            "provider": "Codex", "plan": "Plus",
            "updated": "Never", "source": "none",
            "session_used_pct": 0, "session_reset": "unknown",
            "weekly_used_pct": 0, "weekly_reset": "unknown",
            "cost_today": 0, "cost_today_tokens": "0",
            "cost_30d": 0, "cost_30d_tokens": "0",
            "model": "",
            "error": None, "available": False,
        }

    def fetch(self):
        d = self._empty()
        if not self.CODEX_DIR.exists():
            d["error"] = "Codex not installed"
            return d
        d["available"] = True

        try:
            config = self.CODEX_DIR / "config.toml"
            if config.exists():
                for line in config.read_text().splitlines():
                    if line.startswith("model"):
                        d["model"] = line.split("=", 1)[1].strip().strip('"')
                        break
        except Exception:
            pass

        try:
            auth = self.CODEX_DIR / "auth.json"
            if auth.exists():
                aj = json.loads(auth.read_text(encoding="utf-8"))
                tokens = aj.get("tokens", {})
                at = tokens.get("access_token", "")
                if at:
                    parts = at.split(".")
                    if len(parts) >= 2:
                        payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
                        claims = json.loads(base64.b64decode(payload))
                        plan = claims.get("https://api.openai.com/auth", {}).get(
                            "chatgpt_plan_type", "")
                        if plan:
                            d["plan"] = plan.capitalize()
        except Exception:
            pass

        self._scan_sessions(d)
        d["updated"] = datetime.now().strftime("Updated %H:%M")
        return d

    def _scan_sessions(self, d):
        sessions_dir = self.CODEX_DIR / "sessions"
        if not sessions_dir.exists():
            d["source"] = "config"
            return

        jsonl_files = sorted(sessions_dir.rglob("*.jsonl"),
                             key=lambda f: f.stat().st_mtime, reverse=True)
        if not jsonl_files:
            d["source"] = "config"
            return

        print(f"    Codex: scanning {len(jsonl_files)} session files")

        latest_limits = None
        for jf in jsonl_files[:5]:
            limits = self._extract_rate_limits(jf)
            if limits:
                latest_limits = limits
                break

        if latest_limits:
            rl = latest_limits
            primary = rl.get("primary", {})
            if primary:
                d["session_used_pct"] = int(primary.get("used_percent", 0))
                resets_at = primary.get("resets_at")
                if resets_at:
                    d["session_reset"] = self._format_reset(resets_at)
            secondary = rl.get("secondary", {})
            if secondary:
                d["weekly_used_pct"] = int(secondary.get("used_percent", 0))
                resets_at = secondary.get("resets_at")
                if resets_at:
                    d["weekly_reset"] = self._format_reset(resets_at)
            plan = rl.get("plan_type", "")
            if plan:
                d["plan"] = plan.capitalize()
            d["source"] = "sessions"
        else:
            d["source"] = "config"

        total_in = total_out = today_in = today_out = 0
        today = datetime.now().date()

        for jf in jsonl_files:
            try:
                tokens = self._extract_total_tokens(jf)
                if not tokens:
                    continue
                inp = tokens.get("input_tokens", 0)
                out = tokens.get("output_tokens", 0)
                total_in += inp
                total_out += out
                try:
                    ts_str = jf.stem.split("rollout-")[1][:10]
                    if datetime.strptime(ts_str, "%Y-%m-%d").date() == today:
                        today_in += inp
                        today_out += out
                except Exception:
                    pass
            except Exception:
                continue

        c30 = (total_in * 2.5 + total_out * 10) / 1e6
        ct = (today_in * 2.5 + today_out * 10) / 1e6

        def fmt(n):
            if n >= 1e6: return f"{n / 1e6:.1f}M"
            if n >= 1e3: return f"{n / 1e3:.0f}K"
            return str(n)

        d["cost_today"] = round(ct, 2)
        d["cost_today_tokens"] = fmt(today_in + today_out)
        d["cost_30d"] = round(c30, 2)
        d["cost_30d_tokens"] = fmt(total_in + total_out)

    @staticmethod
    def _extract_rate_limits(jsonl_path):
        last = None
        try:
            with open(jsonl_path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or "rate_limits" not in line:
                        continue
                    try:
                        e = json.loads(line)
                        p = e.get("payload", {})
                        if isinstance(p, dict) and p.get("type") == "token_count":
                            rl = p.get("rate_limits")
                            if rl:
                                last = rl
                    except Exception:
                        pass
        except Exception:
            pass
        return last

    @staticmethod
    def _extract_total_tokens(jsonl_path):
        last = None
        try:
            with open(jsonl_path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or "total_token_usage" not in line:
                        continue
                    try:
                        e = json.loads(line)
                        p = e.get("payload", {})
                        if isinstance(p, dict) and p.get("type") == "token_count":
                            t = p.get("info", {}).get("total_token_usage")
                            if t:
                                last = t
                    except Exception:
                        pass
        except Exception:
            pass
        return last

    @staticmethod
    def _format_reset(epoch):
        try:
            dt = datetime.fromtimestamp(epoch)
            delta = dt - datetime.now()
            secs = max(0, int(delta.total_seconds()))
            h, m = divmod(secs // 60, 60)
            if h >= 24:
                return f"{h // 24}d {h % 24}h"
            return f"{h}h {m:02d}m"
        except Exception:
            return "unknown"


# ─────────────────────────────────────────────
# Native popup window — Multi-provider
# ─────────────────────────────────────────────

class CodexBarPopup(ctk.CTkToplevel):
    """Borderless popup with Claude + OpenAI tabs and smooth transitions."""

    WIDTH = 370
    FINAL_ALPHA = 0.94

    # ── Claude palette ──
    CL_BG       = "#FFFFFF"
    CL_SURFACE  = "#FAF9F7"
    CL_PRIMARY  = "#191918"
    CL_SECOND   = "#6F6E77"
    CL_TERTIARY = "#A8A7B0"
    CL_ACCENT   = "#D97757"
    CL_LITE     = "#FCEEE8"
    CL_BADGE_FG = "#C25B3B"
    CL_BADGE_BG = "#FDF0EB"
    CL_TRACK    = "#F0EFED"
    CL_DIVIDER  = "#ECEAE6"
    CL_HOVER    = "#F5F3EF"

    # ── OpenAI palette ──
    OA_BG       = "#212121"
    OA_SURFACE  = "#2A2A2A"
    OA_PRIMARY  = "#ECECEC"
    OA_SECOND   = "#A0A0A0"
    OA_TERTIARY = "#6E6E6E"
    OA_GREEN    = "#10A37F"
    OA_GREEN_LT = "#1A3A2F"
    OA_TRACK    = "#3A3A3A"
    OA_DIVIDER  = "#333333"
    OA_HOVER    = "#333333"
    OA_CARD     = "#2F2F2F"

    def __init__(self, master, claude_data, codex_data=None, *,
                 on_close=None, on_refresh=None, on_quit=None,
                 on_tab_switch=None):
        super().__init__(master)
        self._claude = claude_data
        self._codex = codex_data or CodexDataFetcher._empty()
        self._on_close = on_close
        self._on_refresh = on_refresh
        self._on_quit = on_quit
        self._on_tab_switch = on_tab_switch
        self._active_tab = "claude"

        self.overrideredirect(True)
        self.configure(fg_color=self.CL_BG)
        self.attributes("-topmost", True)
        self.attributes("-alpha", 0.0)

        cl_tab = _load_logo("claude-logo.png", 18)
        self._cl_tab_icon = ctk.CTkImage(cl_tab, size=(18, 18)) if cl_tab else None
        oa_tab = _load_logo("openai-icon.png", 18)
        self._oa_tab_icon = ctk.CTkImage(oa_tab, size=(18, 18)) if oa_tab else None

        cl_big = _load_logo("claude-logo.png", 32)
        self._cl_logo_big = ctk.CTkImage(cl_big, size=(32, 32)) if cl_big else None
        oa_big = _load_logo("openai-icon.png", 28)
        self._oa_logo_big = ctk.CTkImage(oa_big, size=(28, 28)) if oa_big else None

        self._build_ui()

        self.update_idletasks()
        work = self._work_area()
        w = self.WIDTH
        tab_h = self._tab_bar.winfo_reqheight()
        foot_h = self._footer_frame.winfo_reqheight()
        h = tab_h + self._fixed_panel_h + foot_h
        self._target_x = max(work[2] + 8, work[0] - w - 12)
        self._target_y = max(work[3] + 8, work[1] - h - 12)
        self.geometry(f"{w}x{h}+{self._target_x}+{self._target_y + 14}")

        self.bind("<Escape>", lambda e: self._close())
        self.bind("<FocusOut>", self._on_focus_out)
        self.focus_force()
        self.after(40, self._animate_in, 0)

    # ── work area (Linux: tkinter fallback) ──

    def _work_area(self):
        """Return (right, bottom, left, top) of the usable screen area."""
        # Try reading _NET_WORKAREA from X11
        try:
            result = subprocess.run(
                ["xdotool", "getdisplaygeometry"],
                capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                parts = result.stdout.strip().split()
                if len(parts) == 2:
                    w, h = int(parts[0]), int(parts[1])
                    return (w, h, 0, 0)
        except Exception:
            pass

        # Try xprop for _NET_WORKAREA
        try:
            result = subprocess.run(
                ["xprop", "-root", "_NET_WORKAREA"],
                capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0 and "=" in result.stdout:
                vals = result.stdout.split("=")[1].strip().split(",")
                if len(vals) >= 4:
                    x, y, w, h = [int(v.strip()) for v in vals[:4]]
                    return (x + w, y + h, x, y)
        except Exception:
            pass

        # Fallback: tkinter screen size
        return (self.winfo_screenwidth(), self.winfo_screenheight(), 0, 0)

    # ── animation ──

    def _animate_in(self, step, total=14):
        if step > total:
            return
        t = step / total
        ease = 1.0 - (1.0 - t) ** 3
        y = int(self._target_y + 18 * (1.0 - ease))
        alpha = min(ease * 1.0, self.FINAL_ALPHA)
        try:
            self.geometry(f"+{self._target_x}+{y}")
            self.attributes("-alpha", alpha)
            self.after(14, self._animate_in, step + 1, total)
        except Exception:
            pass

    # ── focus ──

    def _on_focus_out(self, event):
        self.after(120, self._check_focus)

    def _check_focus(self):
        try:
            fw = self.focus_get()
            if fw is not None and str(fw).startswith(str(self)):
                return
        except Exception:
            pass
        self._close()

    # ── tab transition ──

    def _switch_tab(self, tab):
        if tab == self._active_tab:
            return
        self._active_tab = tab
        if self._on_tab_switch:
            self._on_tab_switch(tab)
        self._m_step = 0
        self._m_phase = "out"
        self._morph_tick()

    def _do_swap(self):
        tab = self._active_tab
        F = _font()

        if tab == "claude":
            self._tab_bar.configure(fg_color=self.CL_BG)
            self._tab_inner.configure(fg_color=self.CL_TRACK)
            self._cl_tab_btn.configure(fg_color=self.CL_LITE, hover_color=self.CL_LITE)
            self._oa_tab_btn.configure(fg_color="transparent", hover_color=self.CL_HOVER)
            self.configure(fg_color=self.CL_BG)
            self._footer_frame.configure(fg_color=self.CL_BG)
            self._footer_divider.configure(fg_color=self.CL_DIVIDER)
            self._dash_btn.configure(text_color=self.CL_ACCENT, hover_color=self.CL_HOVER)
            self._quit_btn.configure(text_color=self.CL_TERTIARY, hover_color=self.CL_HOVER)
            self._refresh_btn.configure(fg_color=self.CL_ACCENT, hover_color="#C4654A")
        else:
            self._tab_bar.configure(fg_color=self.OA_BG)
            self._tab_inner.configure(fg_color=self.OA_TRACK)
            self._cl_tab_btn.configure(fg_color="transparent", hover_color=self.OA_HOVER)
            self._oa_tab_btn.configure(fg_color=self.OA_GREEN_LT, hover_color=self.OA_GREEN_LT)
            self.configure(fg_color=self.OA_BG)
            self._footer_frame.configure(fg_color=self.OA_BG)
            self._footer_divider.configure(fg_color=self.OA_DIVIDER)
            self._dash_btn.configure(text_color=self.OA_GREEN, hover_color=self.OA_HOVER)
            self._quit_btn.configure(text_color=self.OA_TERTIARY, hover_color=self.OA_HOVER)
            self._refresh_btn.configure(fg_color=self.OA_GREEN, hover_color="#0D8A6A")

        self._claude_frame.pack_forget()
        self._openai_frame.pack_forget()
        self._footer_frame.pack_forget()
        if tab == "claude":
            self._claude_frame.pack(fill="both", expand=True)
        else:
            self._openai_frame.pack(fill="both", expand=True)
        self._footer_frame.pack(fill="x", side="bottom")

        self.update_idletasks()
        tab_h = self._tab_bar.winfo_reqheight()
        foot_h = self._footer_frame.winfo_reqheight()
        h = tab_h + self._fixed_panel_h + foot_h
        work = self._work_area()
        self._target_x = max(work[2] + 8, work[0] - self.WIDTH - 12)
        self._target_y = max(work[3] + 8, work[1] - h - 12)
        self.geometry(f"{self.WIDTH}x{h}+{self._target_x}+{self._target_y}")

    def _morph_tick(self):
        try:
            if self._m_phase == "out":
                total = 7
                s = self._m_step
                if s >= total:
                    self.attributes("-alpha", 0.0)
                    self.geometry(f"+{self._target_x}+-9999")
                    self._do_swap()
                    self.attributes("-alpha", 0.0)
                    self._m_step = 0
                    self._m_phase = "in"
                    self.after(20, self._morph_tick)
                    return
                t = s / total
                ease = t * t
                alpha = self.FINAL_ALPHA * (1.0 - ease)
                self.attributes("-alpha", max(alpha, 0.0))
                self._m_step += 1
                self.after(14, self._morph_tick)

            elif self._m_phase == "in":
                total = 12
                s = self._m_step
                if s >= total:
                    self.attributes("-alpha", self.FINAL_ALPHA)
                    self.geometry(f"+{self._target_x}+{self._target_y}")
                    return
                t = s / total
                ease = 1.0 - (1.0 - t) ** 3
                alpha = self.FINAL_ALPHA * ease
                y_off = int(8 * (1.0 - ease))
                self.attributes("-alpha", alpha)
                self.geometry(f"+{self._target_x}+{self._target_y + y_off}")
                self._m_step += 1
                self.after(14, self._morph_tick)
        except Exception:
            pass

    # ── bar colour helpers ──

    @staticmethod
    def _cl_bar_color(pct):
        if pct <= 50:  return "#D97757"
        if pct <= 80:  return "#E8943E"
        return "#D94A3D"

    @staticmethod
    def _oa_bar_color(pct):
        if pct <= 50:  return "#10A37F"
        if pct <= 80:  return "#E8A83E"
        return "#E24B4A"

    # ═══════════════════════════════════════
    # MAIN UI BUILD
    # ═══════════════════════════════════════

    def _build_ui(self):
        F = _font()

        tab_bar = ctk.CTkFrame(self, fg_color=self.CL_BG, corner_radius=0, height=34)
        tab_bar.pack(fill="x")
        tab_bar.pack_propagate(False)
        self._tab_bar = tab_bar

        self._tab_inner = ctk.CTkFrame(tab_bar, fg_color=self.CL_TRACK, corner_radius=9)
        self._tab_inner.pack(side="left", padx=14, pady=4)
        tab_inner = self._tab_inner

        self._cl_tab_btn = ctk.CTkButton(
            tab_inner, text="", image=self._cl_tab_icon,
            font=(F, 1), fg_color=self.CL_LITE, hover_color=self.CL_LITE,
            corner_radius=8, height=26, width=34,
            command=lambda: self._switch_tab("claude"))
        self._cl_tab_btn.pack(side="left", padx=(2, 1), pady=2)

        self._oa_tab_btn = ctk.CTkButton(
            tab_inner, text="", image=self._oa_tab_icon,
            font=(F, 1), fg_color="transparent", hover_color=self.CL_HOVER,
            corner_radius=8, height=26, width=34,
            command=lambda: self._switch_tab("openai"))
        self._oa_tab_btn.pack(side="left", padx=(1, 2), pady=2)

        self._claude_frame = ctk.CTkFrame(self, fg_color=self.CL_BG, corner_radius=0)
        self._build_claude_panel(self._claude_frame)
        self._claude_frame.pack(fill="both", expand=True)

        self._openai_frame = ctk.CTkFrame(self, fg_color=self.OA_BG, corner_radius=0)
        self._build_openai_panel(self._openai_frame)

        self.update_idletasks()
        ch = self._claude_frame.winfo_reqheight()
        self._openai_frame.pack(fill="both", expand=True)
        self.update_idletasks()
        oh = self._openai_frame.winfo_reqheight()
        self._openai_frame.pack_forget()
        self._fixed_panel_h = max(ch, oh)

        self._footer_frame = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        self._build_footer(self._footer_frame)
        self._footer_frame.pack(fill="x", side="bottom")

    # ═══════════════════════════════════════
    # CLAUDE PANEL
    # ═══════════════════════════════════════

    def _build_claude_panel(self, parent):
        F = _font()
        d = self._claude
        sp = d["session_used_pct"]
        wp = d["weekly_used_pct"]
        op = d["opus_used_pct"]
        has_data = d["source"] != "none"
        has_cost = d["cost_today"] > 0 or d["cost_30d"] > 0

        for color, h in [
            ("#FCEEE8", 4), ("#FDF1EC", 3), ("#FDF4F0", 3),
            ("#FEF6F3", 3), ("#FEF8F6", 2), ("#FFFCFB", 2),
        ]:
            ctk.CTkFrame(parent, fg_color=color, height=h,
                         corner_radius=0).pack(fill="x")

        hero = ctk.CTkFrame(parent, fg_color="transparent")
        hero.pack(fill="x", padx=22, pady=(4, 0))

        row = ctk.CTkFrame(hero, fg_color="transparent")
        row.pack(fill="x")
        if self._cl_logo_big:
            ctk.CTkLabel(row, text="", image=self._cl_logo_big,
                         width=32, height=32).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(row, text="Claude", font=(F+" Semibold" if "Sans" not in F else F, 22, "bold"),
                     text_color=self.CL_PRIMARY).pack(side="left")
        ctk.CTkLabel(row, text=f"  {d['plan']}  ", font=(F, 11, "bold"),
                     text_color=self.CL_BADGE_FG, fg_color=self.CL_BADGE_BG,
                     corner_radius=10).pack(side="right")

        meta = ctk.CTkFrame(hero, fg_color="transparent")
        meta.pack(fill="x", pady=(5, 0))
        ctk.CTkFrame(meta, fg_color="#5CB176", corner_radius=4,
                     width=7, height=7).pack(side="left", padx=(1, 7), pady=5)
        ctk.CTkLabel(meta, text=d["updated"], font=(F, 12),
                     text_color=self.CL_SECOND).pack(side="left")
        ctk.CTkLabel(meta, text=f"  {d['source']}", font=(F, 11),
                     text_color=self.CL_TERTIARY).pack(side="left")

        if has_data:
            ctk.CTkFrame(parent, fg_color=self.CL_DIVIDER,
                         height=1, corner_radius=0).pack(fill="x", padx=20, pady=(12, 0))
            ctk.CTkLabel(parent, text="Usage", font=(F, 13, "bold"),
                         text_color=self.CL_TERTIARY,
                         anchor="w").pack(fill="x", padx=22, pady=(10, 2))
            self._cl_usage_bar(parent, "Session", sp, d["session_reset"])
            self._cl_usage_bar(parent, "Weekly", wp, d["weekly_reset"])
            if op > 0:
                self._cl_usage_bar(parent, "Opus", op)

        if has_cost:
            ctk.CTkFrame(parent, fg_color=self.CL_DIVIDER,
                         height=1, corner_radius=0).pack(fill="x", padx=20, pady=(8, 0))
            ctk.CTkLabel(parent, text="API Cost Estimate",
                         font=(F, 13, "bold"),
                         text_color=self.CL_TERTIARY,
                         anchor="w").pack(fill="x", padx=22, pady=(10, 0))
            ctk.CTkLabel(parent, text="Estimated API equivalent — not billed",
                         font=(F, 10),
                         text_color=self.CL_TERTIARY,
                         anchor="w").pack(fill="x", padx=22, pady=(0, 4))
            card = ctk.CTkFrame(parent, fg_color=self.CL_SURFACE, corner_radius=10)
            card.pack(fill="x", padx=20, pady=(0, 2))
            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="x", padx=14, pady=10)
            for label, val in [("Today", f"${d['cost_today']:.2f}"),
                               ("Last 30 days", f"${d['cost_30d']:.2f}")]:
                r = ctk.CTkFrame(inner, fg_color="transparent")
                r.pack(fill="x", pady=1)
                ctk.CTkLabel(r, text=label, font=(F, 12),
                             text_color=self.CL_SECOND).pack(side="left")
                ctk.CTkLabel(r, text=val, font=(F, 13, "bold"),
                             text_color=self.CL_PRIMARY).pack(side="right")

        if not d.get("installed", True) and not has_data and not has_cost:
            ctk.CTkFrame(parent, fg_color=self.CL_DIVIDER,
                         height=1, corner_radius=0).pack(fill="x", padx=20, pady=(12, 0))
            nd = ctk.CTkFrame(parent, fg_color="transparent")
            nd.pack(fill="x", padx=20, pady=(20, 8))
            ctk.CTkLabel(nd, text="Claude Code not detected",
                         font=(F, 14, "bold"),
                         text_color=self.CL_PRIMARY).pack(pady=(0, 4))
            ctk.CTkLabel(nd, text="Install the CLI to see your usage",
                         font=(F, 11),
                         text_color=self.CL_SECOND).pack(pady=(0, 12))
            ctk.CTkButton(nd, text="Install Claude Code",
                          font=(F, 13, "bold"),
                          text_color="#FFFFFF", fg_color=self.CL_ACCENT,
                          hover_color="#C4654A", corner_radius=10,
                          height=38, width=200,
                          command=lambda: self._open_url(
                              "https://docs.anthropic.com/en/docs/claude-code/overview")
                          ).pack()
        elif not has_data and not has_cost:
            nd = ctk.CTkFrame(parent, fg_color="transparent")
            nd.pack(fill="x", padx=20, pady=24)
            ctk.CTkLabel(nd, text="No session data yet", font=(F, 13),
                         text_color=self.CL_SECOND).pack()
            ctk.CTkLabel(nd, text="Run /usage in Claude Code",
                         font=(F, 11),
                         text_color=self.CL_TERTIARY).pack(pady=(4, 0))

        ctk.CTkFrame(parent, fg_color="transparent", height=6).pack(fill="x")

    def _cl_usage_bar(self, parent, label, pct, reset=None):
        F = _font()
        color = self._cl_bar_color(pct)
        sec = ctk.CTkFrame(parent, fg_color="transparent")
        sec.pack(fill="x", padx=20, pady=(3, 2))
        row = ctk.CTkFrame(sec, fg_color="transparent")
        row.pack(fill="x")
        ctk.CTkLabel(row, text=label, font=(F, 13, "bold"),
                     text_color=self.CL_PRIMARY).pack(side="left")
        ctk.CTkLabel(row, text=f"{pct}%", font=(F, 13, "bold"),
                     text_color=color).pack(side="right")
        track = ctk.CTkFrame(sec, fg_color=self.CL_TRACK, height=8, corner_radius=4)
        track.pack(fill="x", pady=(4, 3))
        track.pack_propagate(False)
        ctk.CTkFrame(track, fg_color=color, corner_radius=4, height=8).place(
            relx=0, rely=0, relwidth=max(pct / 100, 0.015), relheight=1)
        if reset and reset != "unknown":
            ctk.CTkLabel(sec, text=f"Resets {reset}", font=(F, 11),
                         text_color=self.CL_TERTIARY, anchor="w").pack(fill="x")

    # ═══════════════════════════════════════
    # OPENAI PANEL
    # ═══════════════════════════════════════

    def _build_openai_panel(self, parent):
        F = _font()
        d = self._codex
        available = d.get("available", False)
        sp = d["session_used_pct"]
        wp = d["weekly_used_pct"]
        has_data = d["source"] not in ("none", "config")
        has_cost = d["cost_today"] > 0 or d["cost_30d"] > 0

        for color, h in [
            ("#2A2E2C", 4), ("#282C2A", 3), ("#262A28", 3),
            ("#252826", 3), ("#242725", 2), ("#232524", 2),
        ]:
            ctk.CTkFrame(parent, fg_color=color, height=h,
                         corner_radius=0).pack(fill="x")

        hero = ctk.CTkFrame(parent, fg_color="transparent")
        hero.pack(fill="x", padx=22, pady=(4, 0))

        row = ctk.CTkFrame(hero, fg_color="transparent")
        row.pack(fill="x")
        if self._oa_logo_big:
            ctk.CTkLabel(row, text="", image=self._oa_logo_big,
                         width=28, height=28).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(row, text="Codex", font=(F, 22, "bold"),
                     text_color=self.OA_PRIMARY).pack(side="left")
        plan_text = d["plan"]
        if d["model"]:
            plan_text = d["model"]
        ctk.CTkLabel(row, text=f"  {plan_text}  ", font=(F, 11, "bold"),
                     text_color=self.OA_GREEN, fg_color=self.OA_GREEN_LT,
                     corner_radius=10).pack(side="right")

        meta = ctk.CTkFrame(hero, fg_color="transparent")
        meta.pack(fill="x", pady=(5, 0))
        dot_color = self.OA_GREEN if available else self.OA_TERTIARY
        ctk.CTkFrame(meta, fg_color=dot_color, corner_radius=4,
                     width=7, height=7).pack(side="left", padx=(1, 7), pady=5)
        ctk.CTkLabel(meta, text=d["updated"], font=(F, 12),
                     text_color=self.OA_SECOND).pack(side="left")
        ctk.CTkLabel(meta, text=f"  {d['source']}", font=(F, 11),
                     text_color=self.OA_TERTIARY).pack(side="left")

        if not available:
            ctk.CTkFrame(parent, fg_color=self.OA_DIVIDER,
                         height=1, corner_radius=0).pack(fill="x", padx=20, pady=(12, 0))
            nd = ctk.CTkFrame(parent, fg_color="transparent")
            nd.pack(fill="x", padx=20, pady=(20, 8))
            ctk.CTkLabel(nd, text="Codex not detected",
                         font=(F, 14, "bold"),
                         text_color=self.OA_PRIMARY).pack(pady=(0, 4))
            ctk.CTkLabel(nd, text="Install the CLI to see your usage",
                         font=(F, 11),
                         text_color=self.OA_SECOND).pack(pady=(0, 12))
            ctk.CTkButton(nd, text="Install Codex",
                          font=(F, 13, "bold"),
                          text_color="#FFFFFF", fg_color=self.OA_GREEN,
                          hover_color="#0D8A6A", corner_radius=10,
                          height=38, width=200,
                          command=lambda: self._open_url(
                              "https://github.com/openai/codex")
                          ).pack()
            ctk.CTkFrame(parent, fg_color="transparent", height=6).pack(fill="x")
            return

        if has_data:
            ctk.CTkFrame(parent, fg_color=self.OA_DIVIDER,
                         height=1, corner_radius=0).pack(fill="x", padx=20, pady=(12, 0))
            ctk.CTkLabel(parent, text="Usage", font=(F, 13, "bold"),
                         text_color=self.OA_TERTIARY,
                         anchor="w").pack(fill="x", padx=22, pady=(10, 2))
            self._oa_usage_bar(parent, "Session (5h)", sp, d["session_reset"])
            self._oa_usage_bar(parent, "Weekly", wp, d["weekly_reset"])

        if has_cost:
            ctk.CTkFrame(parent, fg_color=self.OA_DIVIDER,
                         height=1, corner_radius=0).pack(fill="x", padx=20, pady=(8, 0))
            ctk.CTkLabel(parent, text="API Cost Estimate",
                         font=(F, 13, "bold"),
                         text_color=self.OA_TERTIARY,
                         anchor="w").pack(fill="x", padx=22, pady=(10, 0))
            ctk.CTkLabel(parent, text="Estimated API equivalent — not billed",
                         font=(F, 10),
                         text_color=self.OA_TERTIARY,
                         anchor="w").pack(fill="x", padx=22, pady=(0, 4))
            card = ctk.CTkFrame(parent, fg_color=self.OA_CARD, corner_radius=10)
            card.pack(fill="x", padx=20, pady=(0, 2))
            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="x", padx=14, pady=10)
            for label, val in [("Today", f"${d['cost_today']:.2f}"),
                               ("All sessions", f"${d['cost_30d']:.2f}")]:
                r = ctk.CTkFrame(inner, fg_color="transparent")
                r.pack(fill="x", pady=1)
                ctk.CTkLabel(r, text=label, font=(F, 12),
                             text_color=self.OA_SECOND).pack(side="left")
                ctk.CTkLabel(r, text=val, font=(F, 13, "bold"),
                             text_color=self.OA_PRIMARY).pack(side="right")

        if not has_data and not has_cost:
            ctk.CTkFrame(parent, fg_color=self.OA_DIVIDER,
                         height=1, corner_radius=0).pack(fill="x", padx=20, pady=(12, 0))
            nd = ctk.CTkFrame(parent, fg_color="transparent")
            nd.pack(fill="x", padx=20, pady=24)
            ctk.CTkLabel(nd, text="No session data yet", font=(F, 13),
                         text_color=self.OA_SECOND).pack()
            ctk.CTkLabel(nd, text="Run a session in Codex CLI",
                         font=(F, 11),
                         text_color=self.OA_TERTIARY).pack(pady=(4, 0))

        ctk.CTkFrame(parent, fg_color="transparent", height=6).pack(fill="x")

    def _oa_usage_bar(self, parent, label, pct, reset=None):
        F = _font()
        color = self._oa_bar_color(pct)
        sec = ctk.CTkFrame(parent, fg_color="transparent")
        sec.pack(fill="x", padx=20, pady=(3, 2))
        row = ctk.CTkFrame(sec, fg_color="transparent")
        row.pack(fill="x")
        ctk.CTkLabel(row, text=label, font=(F, 13, "bold"),
                     text_color=self.OA_PRIMARY).pack(side="left")
        ctk.CTkLabel(row, text=f"{pct}%", font=(F, 13, "bold"),
                     text_color=color).pack(side="right")
        track = ctk.CTkFrame(sec, fg_color=self.OA_TRACK, height=8, corner_radius=4)
        track.pack(fill="x", pady=(4, 3))
        track.pack_propagate(False)
        ctk.CTkFrame(track, fg_color=color, corner_radius=4, height=8).place(
            relx=0, rely=0, relwidth=max(pct / 100, 0.015), relheight=1)
        if reset and reset != "unknown":
            ctk.CTkLabel(sec, text=f"Resets {reset}", font=(F, 11),
                         text_color=self.OA_TERTIARY, anchor="w").pack(fill="x")

    # ═══════════════════════════════════════
    # FOOTER
    # ═══════════════════════════════════════

    def _build_footer(self, parent):
        F = _font()
        self._footer_divider = ctk.CTkFrame(parent, fg_color=self.CL_DIVIDER,
                     height=1, corner_radius=0)
        self._footer_divider.pack(fill="x", padx=20)

        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=(6, 6))

        self._dash_btn = ctk.CTkButton(
            row, text="Dashboard", font=(F, 12),
            text_color=self.CL_ACCENT, fg_color="transparent",
            hover_color=self.CL_HOVER, anchor="w", height=30,
            corner_radius=8, width=80,
            command=lambda: self._open_url(
                "https://platform.openai.com/usage" if self._active_tab == "openai"
                else "https://claude.ai/settings/billing"))
        self._dash_btn.pack(side="left", padx=2)

        self._quit_btn = ctk.CTkButton(
            row, text="Quit", font=(F, 12),
            text_color=self.CL_TERTIARY, fg_color="transparent",
            hover_color=self.CL_HOVER, anchor="center", height=30,
            corner_radius=8, width=50, command=self._do_quit)
        self._quit_btn.pack(side="right", padx=2)

        self._refresh_btn = ctk.CTkButton(
            row, text="Refresh", font=(F, 12, "bold"),
            text_color="#FFFFFF", fg_color=self.CL_ACCENT,
            hover_color="#C4654A", anchor="center", height=30,
            corner_radius=8, width=70, command=self._do_refresh)
        self._refresh_btn.pack(side="right", padx=2)

    # ── helpers ──

    def _open_url(self, url):
        webbrowser.open(url)
        self._close()

    def _close(self):
        try:
            self.destroy()
        except Exception:
            pass
        if self._on_close:
            self._on_close()

    def _do_refresh(self):
        self._close()
        if self._on_refresh:
            self._on_refresh()

    def _do_quit(self):
        self._close()
        if self._on_quit:
            self._on_quit()


# ─────────────────────────────────────────────
# App  (tkinter main loop + pystray background)
# ─────────────────────────────────────────────

class CodexBarApp:
    def __init__(self):
        self.fetcher = ClaudeDataFetcher()
        self.codex_fetcher = CodexDataFetcher()
        self.root = None
        self.tray = None
        self.popup = None
        self.running = True
        self.codex_data = None

    def start(self):
        print("[CodexBar] Fetching your real usage data...\n")
        self.fetcher.fetch_all()
        print(f"\n[CodexBar] Source: {self.fetcher.data['source']}")
        try:
            self.codex_data = self.codex_fetcher.fetch()
            print(f"[CodexBar] Codex: {'available' if self.codex_data.get('available') else 'not found'}")
        except Exception as e:
            print(f"[CodexBar] Codex fetch err: {e}")
            self.codex_data = CodexDataFetcher._empty()

        ctk.set_appearance_mode("light")
        self.root = ctk.CTk()
        self.root.withdraw()

        d = self.fetcher.data
        sl = (100 - d["session_used_pct"]) / 100
        wl = (100 - d["weekly_used_pct"]) / 100

        menu = Menu(
            MenuItem('Open CodexBar', self._tray_open, default=True),
            MenuItem('Refresh', self._tray_refresh),
            Menu.SEPARATOR,
            MenuItem('Quit', self._tray_quit),
        )
        self.tray = pystray.Icon('CodexBar', make_icon(sl, wl), 'CodexBar', menu)
        threading.Thread(target=self.tray.run, daemon=True).start()

        self.root.after(300_000, self._auto_refresh)

        print("\n" + "=" * 50)
        print("  CodexBar running in system tray!")
        print("  Look for the icon in your panel/tray area.")
        print("  Click to open the panel.")
        print("=" * 50 + "\n")

        self.root.mainloop()

    def _tray_open(self, *_):
        self.root.after(0, self._show_popup)

    def _tray_refresh(self, *_):
        self.root.after(0, self._do_refresh)

    def _tray_quit(self, *_):
        self.root.after(0, self._do_quit)

    def _show_popup(self):
        if self.popup is not None:
            try:
                self.popup.destroy()
            except Exception:
                pass
            self.popup = None

        self.popup = CodexBarPopup(
            self.root,
            self.fetcher.data,
            codex_data=self.codex_data,
            on_close=self._on_popup_closed,
            on_refresh=lambda: self.root.after(0, self._do_refresh),
            on_quit=lambda: self.root.after(0, self._do_quit),
            on_tab_switch=self._on_tab_switch,
        )

    def _on_popup_closed(self):
        self.popup = None

    def _on_tab_switch(self, tab):
        self._set_tray_icon(tab)

    def _set_tray_icon(self, provider):
        try:
            p = "openai" if provider == "openai" else "claude"
            self.tray.icon = make_icon(provider=p)
        except Exception:
            pass

    def _do_refresh(self):
        def bg():
            self.fetcher.fetch_all()
            try:
                self.codex_data = self.codex_fetcher.fetch()
            except Exception:
                pass
            d = self.fetcher.data
            self.tray.icon = make_icon(
                (100 - d["session_used_pct"]) / 100,
                (100 - d["weekly_used_pct"]) / 100)
            print("[CodexBar] Refreshed")
        threading.Thread(target=bg, daemon=True).start()

    def _auto_refresh(self):
        if not self.running:
            return
        self._do_refresh()
        self.root.after(300_000, self._auto_refresh)

    def _do_quit(self):
        print("[CodexBar] Bye!")
        self.running = False
        try:
            self.tray.stop()
        except Exception:
            pass
        try:
            self.root.quit()
            self.root.destroy()
        except Exception:
            pass
        sys.exit(0)


# ─────────────────────────────────────────────

if __name__ == '__main__':
    print(r"""
   ========================================
    CodexBar for Linux v1.0.0
    Native popup — no browser needed
   ========================================
    """)
    CodexBarApp().start()
