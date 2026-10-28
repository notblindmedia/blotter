"""Layer 2: Windows program checks: packing and risky Windows functions (the signature is signature.py)."""

from ..analyze import filetype, program
from ..findings import SKIPPED, Finding

ID = "program"
NAME = "Program check"
ORDER = 50
TIMEOUT = 90
CACHE = False
NEEDS_FILE = True


def scan(path) -> list[Finding]:
    ft = filetype.detect(path)
    if ft.real != "pe":
        return [Finding(ID, SKIPPED, "Not a Windows program, so there was no program structure to check.")]
    return program.analyze(ID, path, check_signature=False)  # the signature has its own check (signature.py)
