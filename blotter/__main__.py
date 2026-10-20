"""Start Blotter: python -m blotter  (Start Blotter.bat does this for you)."""

import json
import socket
import sys
import threading
import time
import urllib.request
import webbrowser

from . import config, keys


def _ping() -> str:
    """'blotter' if Blotter already runs on the port, 'other' if something else does, '' if free."""
    try:
        with urllib.request.urlopen(f"{config.URL}/api/ping", timeout=1) as r:
            return "blotter" if json.load(r).get("app") == "blotter" else "other"
    except (OSError, ValueError):
        with socket.socket() as s:
            return "other" if s.connect_ex((config.HOST, config.PORT)) == 0 else ""


def _open_when_ready():
    for _ in range(50):
        if _ping() == "blotter":
            webbrowser.open(config.URL)
            return
        time.sleep(0.2)


def main() -> int:
    state = _ping()
    if state == "blotter":
        print(f"Blotter is already running. Opening {config.URL}")
        webbrowser.open(config.URL)
        return 0
    if state == "other":
        print(f"Another program is using port {config.PORT}, so Blotter can't start.")
        return 1

    import uvicorn

    from .app import clean_incoming, create_app

    if not keys.backend_ok():
        print(f"Warning: Windows Credential Manager isn't available ({keys.backend_name()}); keys can't be saved.")
    clean_incoming()
    if "--no-browser" not in sys.argv:
        threading.Thread(target=_open_when_ready, daemon=True).start()
    print(f"Blotter is running at {config.URL}")
    print("Keep this window open while you use it. Close it to stop Blotter.")
    uvicorn.run(create_app(), host=config.HOST, port=config.PORT, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
