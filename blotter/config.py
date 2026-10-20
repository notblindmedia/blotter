"""Where Blotter keeps its things. Environment variables exist so tests can use a throwaway copy."""

import os
from pathlib import Path

HOST = "127.0.0.1"
PORT = int(os.environ.get("BLOTTER_PORT", "4848"))
URL = f"http://{HOST}:{PORT}"

# Cache and temporary copies live outside the git folder, in %LOCALAPPDATA%\Blotter.
HOME = Path(os.environ.get("BLOTTER_HOME") or Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Blotter")
DB_PATH = HOME / "cache.sqlite3"
INCOMING = HOME / "incoming"

# Name under which the API keys are stored in Windows Credential Manager.
KEYRING_SERVICE = os.environ.get("BLOTTER_KEYRING_SERVICE", "Blotter")

MAX_UPLOAD = 2 * 1024 ** 3  # 2 GB
