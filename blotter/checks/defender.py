"""Microsoft Defender custom scan of the one file, with MpCmdRun.exe.

If Defender finds a threat it quarantines Blotter's copy. That is a detection, not an error.
"""

import os
import re
import subprocess
from pathlib import Path

from ..findings import CLEAR, ERROR, MALICIOUS, UNCHECKED, Finding, detected

ID = "defender"
NAME = "Microsoft Defender"
ORDER = 30
TIMEOUT = 180
CACHE = False          # local and free, and definitions update daily: always scan again
NEEDS_FILE = True
SANDBOX = False        # hands the file to Defender's service; doesn't parse it itself

SCAN_TIMEOUT = TIMEOUT - 10
EXE_NAME = "MpCmdRun.exe"
PLATFORM = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Windows Defender" / "Platform"
FALLBACK = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender" / EXE_NAME

OTHER_ANTIVIRUS = "0x800106ba"  # Defender is switched off, usually because another antivirus took over
KNOWN_ERRORS = {
    OTHER_ANTIVIRUS: "Microsoft Defender isn't running on this PC (another antivirus may have taken over), so it "
                     "couldn't scan the file. Set up ClamAV so Blotter has an antivirus engine of its own: run "
                     "setup.bat again and answer Y to ClamAV.",
    "0x80070005": "Microsoft Defender refused access to the scan.",
}


def find_scanner() -> Path | None:
    """Newest MpCmdRun.exe under the Defender platform folder, else the one in Program Files."""
    override = os.environ.get("BLOTTER_DEFENDER_EXE")  # tests only
    if override:
        return Path(override) if Path(override).is_file() else None
    candidates = []
    try:
        for folder in PLATFORM.iterdir():
            exe = folder / EXE_NAME
            if exe.is_file():
                candidates.append((_version_key(folder.name), exe))
    except OSError:
        pass
    if candidates:
        return max(candidates)[1]
    return FALLBACK if FALLBACK.is_file() else None


def _version_key(name: str) -> tuple:
    return tuple(int(p) if p.isdigit() else -1 for p in re.split(r"[.-]", name))


def _decode(raw: bytes) -> str:
    if not raw:
        return ""
    if b"\x00" in raw:
        return raw.decode("utf-16-le", errors="replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("oem", errors="replace")


def scan(path) -> list[Finding]:
    return [detected(f, "Defender", (f.details.get("threats") or [None])[0]) if f.level == MALICIOUS else f
            for f in _scan(path)]


def _scan(path) -> list[Finding]:
    path = Path(path)
    if not path.exists():
        return [Finding(ID, MALICIOUS,
                        "Microsoft Defender removed Blotter's copy of this file the moment it was saved. "
                        "Defender's real-time protection does that when it recognises a threat.",
                        {"copy_removed": True})]
    exe = find_scanner()
    if not exe:
        return [Finding(ID, ERROR, "Microsoft Defender's scanner (MpCmdRun.exe) wasn't found on this PC.")]
    command = [str(exe), "-Scan", "-ScanType", "3", "-File", str(path)]
    try:
        proc = subprocess.run(
            command, capture_output=True, stdin=subprocess.DEVNULL, timeout=SCAN_TIMEOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        return [Finding(ID, ERROR, f"Microsoft Defender took longer than {SCAN_TIMEOUT} seconds, so the scan was stopped.",
                        {}, [UNCHECKED])]
    except OSError as e:
        return [Finding(ID, ERROR, f"Microsoft Defender's scanner couldn't be started ({e.strerror or e}).")]
    output = (_decode(proc.stdout) + "\n" + _decode(proc.stderr)).strip()
    return interpret(proc.returncode, output, still_there=path.exists(), scanner=str(exe))


def interpret(code: int, output: str, still_there: bool, scanner: str = "") -> list[Finding]:
    return [detected(f, "Defender", (f.details.get("threats") or [None])[0]) if f.level == MALICIOUS else f
            for f in _interpret(code, output, still_there, scanner)]


def _interpret(code: int, output: str, still_there: bool, scanner: str = "") -> list[Finding]:
    threats = list(dict.fromkeys(re.findall(r"^\s*Threat\s*:\s*(.+?)\s*$", output, re.M)))
    found = re.search(r"Found\s+(\d+)\s+threats?", output, re.I)
    details = {"scanner": scanner, "exit_code": code, "threats": threats,
               "copy_removed": not still_there, "output": output[-3000:]}
    if threats or code == 2 or (found and int(found.group(1)) > 0):
        names = ", ".join(threats) or "a threat"
        tail = " and quarantined Blotter's copy" if not still_there else ""
        return [Finding(ID, MALICIOUS, f"Microsoft Defender detected {names} in this file{tail}.", details)]
    if code == 0:
        return [Finding(ID, CLEAR, "Microsoft Defender scanned the file and found no threats.", details)]
    if not still_there:
        return [Finding(ID, MALICIOUS,
                        "Microsoft Defender removed Blotter's copy while scanning it, "
                        "which it does when it recognises a threat.", details)]
    hr = re.search(r"0x[0-9a-fA-F]{8}", output)
    hr = hr.group(0).lower() if hr else None
    text = KNOWN_ERRORS.get(hr) or f"Microsoft Defender couldn't scan the file (exit code {code}{', ' + hr if hr else ''})."
    if hr == OTHER_ANTIVIRUS:
        details["other_antivirus"] = True  # app.py's /api/status shows a hint on the page
    return [Finding(ID, ERROR, text, details)]
