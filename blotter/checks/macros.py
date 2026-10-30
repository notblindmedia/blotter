"""Layer 2: Office macros and document tricks, with oletools. The document is never opened in Office."""

from ..analyze import archives, filetype, office
from ..findings import SKIPPED, Finding, unchecked

ID = "macros"
NAME = "Office macros"
ORDER = 60
TIMEOUT = 90
CACHE = False
NEEDS_FILE = True
MAX_SIZE = 200 * 1024 * 1024


def scan(path) -> list[Finding]:
    ft = filetype.detect(path)
    end = None
    if ft.real == "zip":  # an Office file with a zip glued after it reads as two zips: check the document part
        part = archives.document_part(path, limit=MAX_SIZE)
        if part:
            ft, end = part
    if ft.real not in office.OFFICE_REALS:
        return [Finding(ID, SKIPPED, "Not an Office document, so there were no macros to look for.")]
    if ft.real == "rtf":
        return [Finding(ID, SKIPPED, "RTF files can't hold macros; the RTF check looks at what is embedded in it.")]
    with open(path, "rb") as f:
        data = f.read(MAX_SIZE + 1 if end is None else end)
    if len(data) > MAX_SIZE:
        return [unchecked(ID, f"The document is over {MAX_SIZE // 1024 ** 2} MB, so Blotter didn't look for macros "
                              "in it.")]
    return office.analyze(ID, ft, data)
