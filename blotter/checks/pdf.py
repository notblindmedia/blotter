"""Layer 2: PDF documents. Reads the PDF's keywords as bytes (the way the well-known pdfid tool does)
and never opens it in a PDF reader.

What matters in a PDF: JavaScript, actions that run by themselves when it opens, "Launch" actions that
start programs, and files packed inside. Names disguised with #-codes (/J#61vaScript) are a trick to
slip past scanners. Keywords hidden in compressed object streams are unpacked (with a limit) and read too.
"""

import re
import zlib

from ..analyze import filetype
from ..findings import CLEAR, NOTE, SKIPPED, SUSPICIOUS, Finding, hiding, risky, unchecked, weak

ID = "pdf"
NAME = "PDF check"
ORDER = 62
TIMEOUT = 60
CACHE = False
NEEDS_FILE = True

MAX_READ = 100 * 1024 * 1024
MAX_UNPACKED = 20 * 1024 * 1024
KEYWORDS = ["JS", "JavaScript", "OpenAction", "AA", "Launch", "EmbeddedFile", "EmbeddedFiles", "RichMedia",
            "SubmitForm", "GoToR", "Encrypt", "ObjStm"]
NAME_RE = re.compile(rb"/([A-Za-z0-9#]{2,40})")
_OVER_BUDGET = b"\x00blotter-over-budget"
OBJSTM_RE = re.compile(rb"<<(?:(?!>>).){0,500}?/ObjStm(?:(?!>>).){0,500}?>>\s*stream\r?\n", re.S)


def _names(data: bytes):
    """Count each keyword; note those written with #-codes."""
    counts, disguised = dict.fromkeys(KEYWORDS, 0), set()
    for raw in NAME_RE.findall(data):
        name = re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), raw).decode("latin-1")
        if name in counts:
            counts[name] += 1
            if b"#" in raw:
                disguised.add(name)
    return counts, disguised


def _object_streams(data: bytes) -> bytes:
    """Unpack compressed object streams (where keywords can hide), up to MAX_UNPACKED in total."""
    out, budget = [], MAX_UNPACKED
    for m in OBJSTM_RE.finditer(data):
        end = data.find(b"endstream", m.end())
        if end < 0 or budget <= 0:
            break
        try:
            d = zlib.decompressobj()
            chunk = d.decompress(data[m.end():end], budget)
        except zlib.error:
            continue
        budget -= len(chunk)
        out.append(chunk)
    if budget <= 0:
        out.append(_OVER_BUDGET)
    return b"\n".join(out)


def analyze(check, data: bytes, scope=None, offset=0) -> list[Finding]:
    """offset: where the %PDF header starts (filetype.detect accepts it within the first 1024 bytes)."""
    s = {"scope": scope} if scope else {}
    counts, disguised = _names(data)
    over = False
    if counts["ObjStm"]:
        inner = _object_streams(data)
        over = inner.endswith(_OVER_BUDGET)
        inner_counts, inner_disguised = _names(inner)
        counts = {k: counts[k] + inner_counts[k] for k in counts}
        disguised |= inner_disguised
    details = {**s, "keywords": {k: v for k, v in counts.items() if v}}
    script = counts["JS"] + counts["JavaScript"]
    auto = counts["OpenAction"] + counts["AA"]
    out = []
    if script and auto and counts["Launch"]:
        out.append(risky(check, "pdf-autorun-launch",
            "It runs JavaScript by itself when opened and can start programs (a Launch action). Real documents "
            "don't need that combination.", details, level=SUSPICIOUS))
    elif script and auto:
        out.append(risky(check, "pdf-autorun-script",
            "It runs JavaScript by itself when it is opened. Some forms do that, but it is also how many "
            "malicious PDFs start their attack.", details))
    elif script:
        out.append(weak(check, "pdf-script",
            "It contains JavaScript, which runs only if your PDF reader allows it. Fillable forms often use it.",
            details))
    if counts["Launch"] and not (script and auto):
        out.append(risky(check, "pdf-launch",
            "It contains a Launch action, which can try to start a program or command from the document.",
            details))
    if counts["EmbeddedFile"] or counts["EmbeddedFiles"]:
        out.append(weak(check, "pdf-embedded",
            "It has files packed inside it. Some reports and invoices attach data like that.", details))
    if counts["RichMedia"]:
        out.append(weak(check, "pdf-richmedia",
            "It embeds Flash content (RichMedia), which current readers no longer play and attacks used to abuse.",
            details))
    if disguised:
        out.append(hiding(check, "pdf-disguised-names",
            f"Some of its internal names are disguised with #-codes ({', '.join(sorted(disguised))}), a trick to "
            "slip past scanners. Normal PDF programs don't write them that way.", details))
    if over:
        out.append(unchecked(check, f"Its compressed parts unpack to more than {MAX_UNPACKED // 1024 ** 2} MB, so "
                                    "Blotter didn't read all of them.", details))
    if counts["Encrypt"] and not out:
        out.append(Finding(check, NOTE, "The PDF is encrypted, so some of its contents couldn't be read; its "
                                        "structure showed nothing risky.", details))
    if not out:
        out.append(Finding(check, CLEAR, "Blotter read the PDF's structure: no JavaScript, self-starting actions, "
                                         "program launches or packed-in files.", details))
    if offset:
        out.append(hiding(check, "pdf-header-moved",
            f"Its PDF header isn't at the start of the file ({offset:,} bytes of something else come first). PDF "
            "readers still open it, but it is a trick to confuse scanners that only look at the start.",
            {**details, "pdf_offset": offset}))
    return out


def scan(path) -> list[Finding]:
    ft = filetype.detect(path)
    if ft.real != "pdf":
        return [Finding(ID, SKIPPED, "Not a PDF, so there was no PDF structure to read.")]
    with open(path, "rb") as f:
        data = f.read(MAX_READ + 1)
    found = analyze(ID, data[:MAX_READ], offset=ft.detail.get("pdf_offset", 0))
    if len(data) > MAX_READ:
        found.append(unchecked(ID, f"Only the first {MAX_READ // 1024 ** 2} MB of this PDF were read."))
    return found
