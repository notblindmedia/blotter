"""Layer 2: the program's digital signature: is it signed, by whom, and is the signature still valid?

Windows itself checks it (PowerShell's Get-AuthenticodeSignature, in its own process with a time
limit). It runs outside the sandbox because Windows' signature service can't be reached from inside
one; it doesn't parse the file in Blotter's own code.
"""

from ..analyze import filetype, program
from ..findings import SKIPPED, Finding

ID = "signature"
NAME = "Digital signature"
ORDER = 48
TIMEOUT = 60
CACHE = False
NEEDS_FILE = True
SANDBOX = False


def scan(path) -> list[Finding]:
    if filetype.detect(path).real != "pe":
        return [Finding(ID, SKIPPED, "Not a Windows program, so there was no signature to check.")]
    return program.signature_findings(ID, path)
