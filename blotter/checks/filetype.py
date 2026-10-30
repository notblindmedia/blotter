"""Layer 0: what the file really is (from its first bytes), and whether its name lies about that."""

from .. import hashing
from ..analyze import archives, filetype
from ..findings import CLEAR, DISGUISED, HIDING, LYING_NAME, NOTE, Finding

ID = "filetype"
NAME = "Real file type"
ORDER = 1
TIMEOUT = 30
CACHE = False
NEEDS_FILE = True


def scan(path) -> list[Finding]:
    return judge(archives.real_type(path), hashing.original_name(path))


def judge(ft, name, scope=None) -> list[Finding]:
    """Findings about one file's type and name. `scope` is set for files inside an archive."""
    where = {"scope": scope} if scope else {}
    shown = filetype.visible(name) if name else None
    details = {**ft.to_dict(), **where}
    findings = []
    tricks = filetype.name_problems(name or "")
    if tricks.get("bidi"):
        findings.append(Finding(ID, NOTE,
            f"Its name ({shown}) contains a hidden character that makes Windows show the name backwards, "
            "so the real ending looks like something else. That is a malware trick; normal files don't need it.",
            {**details, "ability": "name-trick"}, [DISGUISED, HIDING]))
    if tricks.get("padding"):
        findings.append(Finding(ID, NOTE,
            f"Its name ({shown}) has a long run of spaces that pushes the real ending out of sight.",
            {**details, "ability": "name-trick"}, [DISGUISED, HIDING]))
    if "double" in tricks:
        fake, real = tricks["double"]
        findings.append(Finding(ID, NOTE,
            f"Its name ends in .{fake}.{real}: Windows often hides the last part, so it looks like a .{fake} "
            f"file but runs as a .{real}. That is a common malware trick.",
            {**details, "ability": "double-extension"}, [DISGUISED, LYING_NAME]))

    claim = filetype.compare(ft, name)
    details.update(claimed=claim["claimed"], ext=claim["ext"])
    if claim["disguised"]:
        findings.append(Finding(ID, NOTE,
            f"This is really {ft.label}, but its name ends in .{claim['ext']}. "
            "Programs dressed up as documents, pictures or videos are a common malware trick.",
            {**details, "ability": "disguised"}, [DISGUISED, LYING_NAME]))
    elif claim["match"] is False:
        findings.append(Finding(ID, NOTE,
            f"Its name ends in .{claim['ext']}, but it's really {ft.label}. On its own that's usually "
            "harmless (a renamed file), but it is a warning sign together with other signs.",
            {**details, "ability": "wrong-ending"}, [LYING_NAME]))
    if not findings:
        ending = f" and its name (.{claim['ext']}) fits" if claim["match"] else ""
        findings.append(Finding(ID, CLEAR, f"It is {ft.label}{ending}.", details))
    return findings
