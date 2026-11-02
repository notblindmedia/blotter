"""Layer 2: scripts and shortcuts (.ps1 .bat .cmd .vbs .js .hta .wsf .lnk ...). Reads the text, never runs it."""

from .. import hashing
from ..analyze import filetype, scripts
from ..findings import CLEAR, SKIPPED, Finding, unchecked

ID = "scripts"
NAME = "Script check"
ORDER = 65
TIMEOUT = 60
CACHE = False
NEEDS_FILE = True


def scan(path) -> list[Finding]:
    ft = filetype.detect(path)
    with open(path, "rb") as f:
        data = f.read(scripts.MAX_TEXT + 1)
    found = judge(ft, hashing.original_name(path), data[:scripts.MAX_TEXT])
    if len(data) > scripts.MAX_TEXT and found[0].level != SKIPPED:
        found.append(unchecked(ID, f"Only the first {scripts.MAX_TEXT // 1024 ** 2} MB of this script were read."))
    return found


def judge(ft, name, data, scope=None) -> list[Finding]:
    s = {"scope": scope} if scope else {}
    exts = filetype.extensions(name or "")
    ext = exts[-1] if exts else ""
    if ft.real == "lnk":
        found = scripts.analyze_lnk(ID, data, scope)
        return found or [Finding(ID, CLEAR, "The shortcut just opens a program or file, with no hidden command.", s)]
    if ft.kind == "text" and ext in scripts.HTML_EXTS:
        found = scripts.analyze_html(ID, scripts.decode(data), scope)
        return found or [Finding(ID, CLEAR, f"Blotter read the .{ext} file's scripts and found no hidden download "
                                            "(HTML smuggling) and none of the usual malware tricks.", s)]
    if ft.kind != "text" or ext not in scripts.SCRIPT_EXTS:
        return [Finding(ID, SKIPPED, "Not a script or shortcut, so there was nothing to read here.", s)]
    found = scripts.analyze_text(ID, scripts.decode(data), ext, scope)
    return found or [Finding(ID, CLEAR, f"Blotter read the .{ext} script and found none of the usual malware "
                                        "tricks (download-and-run, hidden windows, encoded commands).", s)]
