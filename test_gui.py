"""Quick GUI test with fake data — bypasses all data fetching."""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from codexbar import (
    CodexBarPopup, CodexDataFetcher, make_icon,
    _load_logo, _font
)
import customtkinter as ctk
import pystray
from pystray import MenuItem, Menu
import threading


def main():
    # Fake Claude data
    claude_data = {
        "provider": "Claude",
        "plan": "Max",
        "updated": "Updated 03:35",
        "session_used_pct": 42,
        "session_reset": "3h 20m",
        "weekly_used_pct": 67,
        "weekly_reset": "Mar 27, 9:59am",
        "opus_used_pct": 15,
        "cost_today": 4.82,
        "cost_today_tokens": "156K",
        "cost_30d": 87.50,
        "cost_30d_tokens": "2.8M",
        "source": "cli",
        "error": None,
        "installed": True,
    }

    # Fake Codex data
    codex_data = {
        "provider": "Codex",
        "plan": "Plus",
        "updated": "Updated 03:35",
        "source": "sessions",
        "session_used_pct": 28,
        "session_reset": "2h 10m",
        "weekly_used_pct": 53,
        "weekly_reset": "4d 12h",
        "cost_today": 1.20,
        "cost_today_tokens": "48K",
        "cost_30d": 22.30,
        "cost_30d_tokens": "890K",
        "model": "gpt-4o",
        "error": None,
        "available": True,
    }

    print(f"[test] Using font: {_font()}")
    print("[test] Launching GUI...")

    ctk.set_appearance_mode("light")
    root = ctk.CTk()
    root.withdraw()

    def show_popup():
        popup = CodexBarPopup(
            root,
            claude_data,
            codex_data=codex_data,
            on_close=lambda: None,
            on_refresh=lambda: print("[test] Refresh clicked"),
            on_quit=lambda: (root.quit(), sys.exit(0)),
        )

    # Show popup immediately
    root.after(100, show_popup)

    # Also start tray icon
    menu = Menu(
        MenuItem('Open CodexBar', lambda *_: root.after(0, show_popup), default=True),
        MenuItem('Quit', lambda *_: root.after(0, lambda: (root.quit(), sys.exit(0)))),
    )
    tray = pystray.Icon('CodexBar', make_icon(), 'CodexBar - Test', menu)
    threading.Thread(target=tray.run, daemon=True).start()

    print("[test] GUI should be visible now!")
    print("[test] Press Ctrl+C or click Quit to exit.")
    root.mainloop()


if __name__ == "__main__":
    main()
