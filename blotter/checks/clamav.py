"""ClamAV scan of the file (sent as bytes to Blotter's own ClamAV on this PC; nothing leaves the PC)."""

import re
import time

from .. import clamav, settings
from ..findings import CLEAR, ERROR, MALICIOUS, SKIPPED, SUSPICIOUS, Finding, detected, unchecked

ID = "clamav"
NAME = "ClamAV"
ORDER = 35
TIMEOUT = 300          # includes waiting for ClamAV to load its signatures after a rest
CACHE = False          # signatures change daily, and it is local and free
NEEDS_FILE = True
SANDBOX = False        # only streams the bytes to Blotter's ClamAV (on 127.0.0.1, which a sandbox can't reach)

WAIT_FOR_READY = 150
# ClamAV names that are guesses about how a file is built, not a known malware family: its heuristics,
# "potentially unwanted" tools, and packer/generic names (e.g. Win.Packed.Mikey-9859574-0). These are weak
# engine signals: Suspicious at most, and Unusual for a program from a well-known publisher (verdict.py).
# Every other name (Win.Trojan.AgentTesla-..., Win.Ransomware.Lockbit-...) stays Malicious.
GENERIC = re.compile(r"^(?:Heuristics|PUA)\.|^\w+\.(?:Packed|Packer|Packers)\.|\.(?:Generic|Heuristic|Heur)(?![a-z])", re.I)
PACKER = re.compile(r"^\w+\.(?:Packed|Packer|Packers)\.", re.I)


def prepare():
    """Runs in Blotter itself before the check: start ClamAV if it is resting. Returns what to call afterwards."""
    clamav.service.wake()
    return clamav.service.release


def scan(path) -> list[Finding]:
    if not settings.load()["clamav"]:
        return [Finding(ID, SKIPPED, "ClamAV is turned off in Settings.")]
    if not clamav.installed():
        return [Finding(ID, SKIPPED, "ClamAV isn't set up (optional; see README.txt, \"ClamAV\").")]
    began = time.monotonic()
    deadline = began + WAIT_FOR_READY
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
            answer = clamav.scan_stream(f, timeout=max(60, TIMEOUT - 20 - (time.monotonic() - began)))
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
            return [detected(Finding(ID, MALICIOUS, f"ClamAV recognises the EICAR antivirus test file ({name}). It is "
                                           "harmless, but every scanner treats it as malware.", details), "ClamAV", name)]
        if name.startswith("Heuristics.Limits.Exceeded"):
            return [unchecked(ID, f"The file is over one of ClamAV's size limits ({name}), so ClamAV didn't scan "
                                  "all of it.", details)]
        if PACKER.search(name):
            details["generic"] = "packer"
            return [detected(Finding(ID, SUSPICIOUS, f"ClamAV makes a generic packer guess about it ({name}): it "
                                                     "is built the way packed malware often is. That is a warning "
                                                     "sign, not a match with known malware.", details), "ClamAV", name)]
        if GENERIC.search(name):
            details["generic"] = "generic"
            return [detected(Finding(ID, SUSPICIOUS, f"ClamAV's broader rules flag it ({name}). That is a warning "
                                                     "sign rather than a known-malware match.", details), "ClamAV", name)]
        return [detected(Finding(ID, MALICIOUS, f"ClamAV recognises it as malware: {name}.", details), "ClamAV", name)]
    return [Finding(ID, ERROR, f"ClamAV couldn't scan it ({answer[:160] or 'no answer'}).", details)]
