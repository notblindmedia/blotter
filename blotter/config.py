"""Where Blotter keeps its things. Environment variables exist so tests can use a throwaway copy."""

import os
from pathlib import Path

HOST = "127.0.0.1"
PORT = int(os.environ.get("BLOTTER_PORT", "4848"))
URL = f"http://{HOST}:{PORT}"

# The Blotter folder (the git folder) and our own YARA rules inside it.
ROOT = Path(__file__).resolve().parent.parent
OWN_RULES = ROOT / "rules"

# Cache, settings and temporary copies live outside the git folder, in %LOCALAPPDATA%\Blotter.
HOME = Path(os.environ.get("BLOTTER_HOME") or Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Blotter")
DB_PATH = HOME / "cache.sqlite3"
TRUST_PATH = HOME / "trusted.sqlite3"
SETTINGS_PATH = HOME / "settings.json"
INCOMING = HOME / "incoming"
QUARANTINE = HOME / "quarantine"

# Downloaded rules and tools. The YARA rules are kept encrypted (vault.py) so antivirus programs
# don't mistake them for malware; the old plain files are moved into the vault on start-up.
YARA_FORGE = HOME / "rules" / "yara-forge-core.7z"
YARA_COMPILED = HOME / "rules" / "compiled.7z"
OLD_PLAIN_RULES = [HOME / "rules" / "yara-forge-core.yar", HOME / "rules" / "compiled.yarc",
                   HOME / "rules" / "compiled.key"]
CAPA_RULES = HOME / "rules" / "capa"
CAPA_SIGS = HOME / "rules" / "capa-sigs"
CLAMAV_DIR = HOME / "clamav"
CLAMAV_DB = HOME / "clamav-db"
CLAMD_PORT = int(os.environ.get("BLOTTER_CLAMD_PORT", "4849"))

# Name under which the API keys are stored in Windows Credential Manager.
KEYRING_SERVICE = os.environ.get("BLOTTER_KEYRING_SERVICE", "Blotter")

MAX_UPLOAD = 2 * 1024 ** 3  # 2 GB

# Remembered online answers (VirusTotal, MalwareBazaar, CIRCL) are asked again after this long: a file nobody
# flagged last week can be flagged today.
ONLINE_MAX_AGE = 7 * 24 * 3600

# Archives: limits against "zip bombs" (archives that unpack to something enormous).
ARCHIVE_MAX_TOTAL = 500 * 1024 ** 2   # unpacked size of everything inside
ARCHIVE_MAX_MEMBERS = 1000            # files inside
ARCHIVE_MAX_DEPTH = 3                 # archives inside archives
ARCHIVE_MAX_RATIO = 100               # unpacked size / packed size, for anything over 1 MB unpacked
ARCHIVE_PASSWORD = "infected"         # what malware researchers use; tried on locked archives

# Each check that reads the file runs in its own process with at most this much memory.
WORKER_MEMORY = 2 * 1024 ** 3
