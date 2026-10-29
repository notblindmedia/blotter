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
    """'blotter' (or 'blotter-test-mode') if Blotter already runs on the port, 'other' if something else
    does, '' if free. A Blotter that refuses the saved code counts as 'blotter': Defender on."""
    request = urllib.request.Request(f"{config.URL}/api/ping", headers={"X-Blotter-Token": _saved_token()})
    try:
        with urllib.request.urlopen(request, timeout=1) as r:
            body = json.load(r)
            if body.get("app") != "blotter":
                return "other"
            return "blotter-test-mode" if body.get("test_mode") else "blotter"
    except urllib.error.HTTPError as e:
        try:
            return "blotter" if json.load(e).get("app") == "blotter" else "other"
        except ValueError:
            return "other"
    except (OSError, ValueError):
        with socket.socket() as s:
            return "other" if s.connect_ex((config.HOST, config.PORT)) == 0 else ""


_CLOSE_EVENTS = (2, 5, 6)  # the window's X, logging off, shutting down


def _on_close(stop) -> None:
    """Call `stop` when Blotter's window is closed (Windows then gives a program about 5 seconds)."""
    if sys.platform != "win32":
        return
    import ctypes
    from ctypes import wintypes

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
    def handler(event):
        if event in _CLOSE_EVENTS:
            stop()
        return False  # then Windows closes Blotter as usual

    _on_close.handler = handler  # must stay alive as long as Blotter runs
    ctypes.windll.kernel32.SetConsoleCtrlHandler(handler, True)


def _stopper(app):
    """Closing Blotter, once: cancel the deep-check queue, stop ClamAV, forget the page's code."""
    from . import clamav
    once = threading.Lock()

    def stop():
        if not once.acquire(blocking=False):
            return
        app.state.runner.close(wait=3)
        clamav.service.stop("stopped")
        TOKEN_FILE.unlink(missing_ok=True)

    return stop


def _page() -> str:
    return f"{config.URL}/?token={_saved_token()}"


def _open_when_ready():
    for _ in range(50):
        if _ping().startswith("blotter"):
            webbrowser.open(_page())
            return
        time.sleep(0.2)


def main() -> int:
    test_mode = "--test-mode" in sys.argv  # for Claude's test runs: no Defender check; every card says so
    state = _ping()
    if state == "blotter" and test_mode:
        print("Blotter is already running with Defender on, so it can't switch to test mode. "
              "Close its window, then start it again with --test-mode.")
        return 1
    if state.startswith("blotter"):
        print(f"Blotter is already running. Opening {config.URL}")
        if state == "blotter-test-mode":
            print("It is in test mode (Defender off). Close its window and start it again for a full check.")
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
    app = create_app(token=token, test_mode=test_mode)
    stop = _stopper(app)
    _on_close(stop)
    # Weekly YARA Forge refresh (skipped when the rules are less than a week old), and ClamAV while open.
    threading.Thread(target=lambda: (updates.rules(), yararules.load()), daemon=True).start()
    clamav.service.start()
    if "--no-browser" not in sys.argv:
        threading.Thread(target=_open_when_ready, daemon=True).start()
    print(f"Blotter is running at {config.URL}")
    if test_mode:
        print("Test mode: Defender off. Every card says so.")
    print("Keep this window open while you use it. Close it to stop Blotter.")
    try:
        uvicorn.run(app, host=config.HOST, port=config.PORT, log_level="warning")
    finally:
        stop()  # Ctrl+C, or the server stopping by itself
    return 0


if __name__ == "__main__":
    sys.exit(main())
