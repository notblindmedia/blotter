"""ClamAV scan of the file (sent as bytes to Blotter's own ClamAV on this PC; nothing leaves the PC)."""

import time

from .. import clamav, settings
from ..findings import CLEAR, ERROR, MALICIOUS, SKIPPED, SUSPICIOUS, Finding, unchecked

ID = "clamav"
NAME = "ClamAV"
ORDER = 35
TIMEOUT = 180
CACHE = False          # signatures change daily, and it is local and free
NEEDS_FILE = True
SANDBOX = False        # only streams the bytes to Blotter's ClamAV (on 127.0.0.1, which a sandbox can't reach)

WAIT_FOR_READY = 90


def scan(path) -> list[Finding]:
    if not settings.load()["clamav"]:
        return [Finding(ID, SKIPPED, "ClamAV is turned off in Settings.")]
    if not clamav.installed():
        return [Finding(ID, SKIPPED, "ClamAV isn't set up (optional; see README.txt, \"ClamAV\").")]
    deadline = time.monotonic() + WAIT_FOR_READY
    while True:
        state = clamav.read_state()
        if state.get("state") == "ready":
            break
        if state.get("state") in ("failed", "off", "not_installed", "stopped") or time.monotonic() > deadline:
            why = state.get("message") or {"stopped": "it isn't running"}.get(state.get("state"), state.get("state"))
            return [Finding(ID, ERROR, f"ClamAV wasn't ready ({why}).")]
        time.sleep(2)
    try:
        with open(path, "rb") as f:
            answer = clamav.scan_stream(f, timeout=TIMEOUT - 20)
    except OSError as e:
        return [Finding(ID, ERROR, f"Blotter couldn't reach its ClamAV scanner ({e.strerror or e}).")]
    return interpret(answer, state.get("message", ""))


def interpret(answer: str, version: str = "") -> list[Finding]:
    details = {"answer": answer, "version": version}
    when = ""
    if version.count("/") >= 2:
        when = f" (signatures from {version.split('/', 2)[2].strip()})"
    if answer.endswith(" OK"):
        return [Finding(ID, CLEAR, f"ClamAV found nothing{when}.", details)]
    if answer.endswith(" FOUND"):
        name = answer.split(": ", 1)[-1][:-len(" FOUND")].strip()
        details["signature"] = name
        if "eicar" in name.lower():
            return [Finding(ID, MALICIOUS, f"ClamAV recognises the EICAR antivirus test file ({name}). It is "
                                           "harmless, but every scanner treats it as malware.", details)]
        if name.startswith("Heuristics.Limits.Exceeded"):
            return [unchecked(ID, f"The file is over one of ClamAV's size limits ({name}), so ClamAV didn't scan "
                                  "all of it.", details)]
        if name.startswith(("Heuristics.", "PUA.")):
            return [Finding(ID, SUSPICIOUS, f"ClamAV's broader rules flag it ({name}). That is a warning sign "
                                            "rather than a known-malware match.", details)]
        return [Finding(ID, MALICIOUS, f"ClamAV recognises it as malware: {name}.", details)]
    return [Finding(ID, ERROR, f"ClamAV couldn't scan it ({answer[:160] or 'no answer'}).", details)]
