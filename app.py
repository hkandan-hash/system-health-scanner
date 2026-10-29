"""System Health Scanner desktop app.

Double-click: starts the dashboard and opens it in its own window; closing the window quits.
Also works as a CLI: SystemHealthScanner.exe scan | report | dashboard | fix [--apply]
"""
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

import sysfix
import sysscan

URL = "http://127.0.0.1:8765"
EDGE_PATHS = [r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
              r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"]


def running():
    try:
        urllib.request.urlopen(URL, timeout=1)
        return True
    except OSError:
        return False


def ensure_config():
    """On first run of the .exe, put an editable apps.yml next to it."""
    cfg = sysscan.HERE / "apps.yml"
    bundled = Path(getattr(sys, "_MEIPASS", sysscan.HERE)) / "apps.yml"
    if not cfg.exists() and bundled.exists():
        shutil.copy(bundled, cfg)


def open_window():
    """Open the dashboard as an app window and wait until it is closed."""
    edge = shutil.which("msedge") or next((p for p in EDGE_PATHS if Path(p).exists()), None)
    if not edge:
        webbrowser.open(URL)
        return False
    profile = Path(os.environ.get("LOCALAPPDATA", sysscan.HERE)) / "SystemHealthScanner" / "window"
    subprocess.run([edge, f"--app={URL}", f"--user-data-dir={profile}", "--window-size=1100,900",
                    "--no-first-run", "--no-default-browser-check"])
    return True


def main():
    ensure_config()
    args = sys.argv[1:]
    if args[:1] == ["fix"]:
        sys.exit(sysfix.main(args[1:]))
    if args:
        sysscan.main(args)
        return

    server = None
    if not running():
        server = threading.Thread(target=sysscan.main, args=(["dashboard"],), daemon=True)
        server.start()
        for _ in range(60):
            if running():
                break
            time.sleep(0.5)
    if not open_window() and server:
        server.join()  # no app window available: keep serving in the browser tab


if __name__ == "__main__":
    main()
