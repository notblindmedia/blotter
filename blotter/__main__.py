"""Start Blotter: python -m blotter  (Start Blotter.bat does this for you)."""

import json
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser

from . import config, keys

# Every start gets a new random code. The page only works when opened with it (see app.py). It is kept
# in %LOCALAPPDATA%\Blotter\session-token so a second "Start Blotter" can open the running Blotter.
TOKEN_FILE = config.HOME / "session-token"


def _saved_token() -> str:
    try:
        return TOKEN_FILE.read_text(encoding="ascii").strip()
    except OSError:
        return ""


def _ping() -> str:
    """'blotter' if Blotter already runs on the port, 'other' if something else does, '' if free."""
    request = urllib.request.Request(f"{config.URL}/api/ping", headers={"X-Blotter-Token": _saved_token()})
    try:
        with urllib.request.urlopen(request, timeout=1) as r:
            return "blotter" if json.load(r).get("app") == "blotter" else "other"
    except urllib.error.HTTPError as e:
        try:
            return "blotter" if json.load(e).get("app") == "blotter" else "other"
        except ValueError:
            return "other"
    except (OSError, ValueError):
        with socket.socket() as s:
            return "other" if s.connect_ex((config.HOST, config.PORT)) == 0 else ""


def _page() -> str:
    return f"{config.URL}/?token={_saved_token()}"


def _open_when_ready():
    for _ in range(50):
        if _ping() == "blotter":
            webbrowser.open(_page())
            return
        time.sleep(0.2)


def main() -> int:
    state = _ping()
    if state == "blotter":
        print(f"Blotter is already running. Opening {config.URL}")
        webbrowser.open(_page())
        return 0
    if state == "other":
        print(f"Another program is using port {config.PORT}, so Blotter can't start.")
        return 1

    import uvicorn

    from . import clamav, sandbox, updates
    from .analyze import yararules
    from .app import clean_incoming, create_app

    if not keys.backend_ok():
        print(f"Warning: Windows Credential Manager isn't available ({keys.backend_name()}); keys can't be saved.")
    clean_incoming()
    yararules.migrate()  # rules from older versions were plain files; keep them encrypted now
    # Set up the sandbox (first start: copies a private Python runtime, ~35 MB) and compile the rules
    # here, because sandboxed workers may not write to the rules folder.
    threading.Thread(target=lambda: (sandbox.prepare(), yararules.load()), daemon=True).start()
    token = secrets.token_urlsafe(32)
    config.HOME.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(token, encoding="ascii")
    app = create_app(token=token)
    # Weekly YARA Forge refresh (skipped when the rules are less than a week old), and ClamAV while open.
    threading.Thread(target=lambda: (updates.rules(), yararules.load()), daemon=True).start()
    clamav.service.start()
    if "--no-browser" not in sys.argv:
        threading.Thread(target=_open_when_ready, daemon=True).start()
    print(f"Blotter is running at {config.URL}")
    print("Keep this window open while you use it. Close it to stop Blotter.")
    try:
        uvicorn.run(app, host=config.HOST, port=config.PORT, log_level="warning")
    finally:
        clamav.service.stop("stopped")
        TOKEN_FILE.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
