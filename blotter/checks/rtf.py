"""Layer 2: RTF documents and the objects embedded in them, with oletools' rtfobj. Never opened in Word."""

from ..analyze import filetype, rtf
from ..findings import SKIPPED, Finding, unchecked

ID = "rtf"
NAME = "RTF objects"
ORDER = 61
TIMEOUT = 90
CACHE = False
NEEDS_FILE = True
MAX_SIZE = 200 * 1024 * 1024


def scan(path) -> list[Finding]:
    ft = filetype.detect(path)
    if ft.real != "rtf":
        return [Finding(ID, SKIPPED, "Not an RTF document, so there were no embedded objects to look for.")]
    with open(path, "rb") as f:
        data = f.read(MAX_SIZE + 1)
    if len(data) > MAX_SIZE:
        return [unchecked(ID, f"The document is over {MAX_SIZE // 1024 ** 2} MB, so Blotter didn't look for "
                              "embedded objects in it.")]
    return rtf.analyze(ID, data)
