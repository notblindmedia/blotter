"""Layer 0: look inside zip, rar and 7z archives, and run the file checks on every file in them.

Each file inside gets the type/disguise check, YARA, and the program, macro, PDF or script check
that fits it. capa and the online lookups only look at the archive itself (capa would take too long
for every file, and lookups for each file would use up the VirusTotal quota).
"""

import os

from .. import config, hashing
from ..analyze import archives, filetype, office, program, scripts, yararules
from . import filetype as filetype_check
from . import pdf as pdf_check
from . import scripts as scripts_check
from ..findings import CLEAR, ERROR, NOTE, SKIPPED, UNCHECKED, Finding

ID = "archive"
NAME = "Archive contents"
ORDER = 2
TIMEOUT = 240
CACHE = False
NEEDS_FILE = True

ARCHIVES = {"zip", "rar", "7z"}
MAX_SIGNATURES = 10  # Windows signature checks are slow-ish; programs beyond this are still checked otherwise


class Sweep:
    def __init__(self, password=None):
        self.password = password
        self.budget = archives.Budget()
        self.findings: list[Finding] = []
        self.checked = 0
        self.locked: list[str] = []
        self.too_big: list[str] = []
        self.damaged: list[str] = []   # files inside that couldn't be read whole, or archives cut off
        self.repaired: list[str] = []  # archives with a broken table of contents, read whole from file headers
        self.signatures = MAX_SIGNATURES
        self.rules = None
        try:
            self.rules = yararules.load()
        except Exception:
            self.rules = None

    def archive(self, path, real, prefix, depth):
        try:
            notes = archives.walk(path, real, lambda name, p: self.member(prefix + name, p, depth), self.budget,
                                  [self.password])
            self.locked += [prefix + n for n in notes.get("locked", [])]
            self.damaged += [prefix + n for n in notes.get("damaged", [])]
            where = prefix.rstrip("/") or "the archive"
            if notes.get("lenient") and not notes.get("complete"):
                self.damaged.append(f"{where} (cut off or damaged: files after the damage may be missing)")
            elif notes.get("lenient") and not notes.get("damaged"):
                self.repaired.append(where)
        except archives.Locked:
            self.locked.append(prefix.rstrip("/") or "the archive")
        except archives.Bomb as e:
            self.too_big.append(f"{prefix.rstrip('/') or 'the archive'}: {e}")

    def member(self, name, path, depth):
        self.checked += 1
        try:
            self._member(name, path, depth)
        except (archives.Bomb, archives.Locked):
            raise
        except Exception as e:  # one damaged file inside must not stop the rest
            self.findings.append(Finding(ID, ERROR, f"Inside the archive, {name}: Blotter couldn't check this file "
                                                    f"({type(e).__name__}).", {"scope": name}))

    def _member(self, name, path, depth):
        ft = filetype.detect(path)
        found = [f for f in filetype_check.judge(ft, name, scope=name) if f.level != CLEAR]
        if ft.real == "pe":
            # Inside the sandbox Windows' signature check isn't available, so only the archive's own
            # programs outside a sandbox get one (Blotter falls back to it when no sandbox could start).
            found += program.analyze(ID, path, scope=name,
                                     check_signature=self.signatures > 0 and not os.environ.get("BLOTTER_WORK"))
            self.signatures -= 1
        elif ft.real in office.OFFICE_REALS:
            found += office.analyze(ID, ft, path.read_bytes(), scope=name)
        elif ft.real == "pdf":
            with open(path, "rb") as f:
                found += pdf_check.analyze(ID, f.read(pdf_check.MAX_READ), scope=name)
        elif ft.real == "lnk" or ft.kind == "text":
            with open(path, "rb") as f:
                text = f.read(scripts.MAX_TEXT)
            found += [f for f in scripts_check.judge(ft, name, text, scope=name) if f.level != SKIPPED]
        if self.rules is not None:
            try:
                found += yararules.scan_target(self.rules, ID, path=path, scope=name)
            except Exception:
                pass
        if ft.real in ARCHIVES:
            if depth >= config.ARCHIVE_MAX_DEPTH:
                self.too_big.append(f"{name}: archives are nested more than {config.ARCHIVE_MAX_DEPTH} deep")
            else:
                self.archive(path, ft.real, name + "/", depth + 1)
        for f in found:
            f.check = ID
            if f.level == CLEAR and not f.signals:
                continue  # "nothing unusual" for each file would bury what matters
            f.text = f"Inside the archive, {name}: {f.text}"
            self.findings.append(f)


def scan(path) -> list[Finding]:
    ft = filetype.detect(path)
    if ft.real not in ARCHIVES:
        return [Finding(ID, SKIPPED, "Not a zip, rar or 7z archive, so there was nothing to unpack.")]
    sweep = Sweep(hashing.password(path))
    try:
        sweep.archive(path, ft.real, "", 1)
    except Exception as e:  # a damaged archive is a finding, not a crash
        return [Finding(ID, ERROR, f"Blotter couldn't unpack this archive ({type(e).__name__}).",
                        {"error": str(e)[:200]})]
    return summarize(sweep)


def summarize(sweep) -> list[Finding]:
    out = list(sweep.findings)
    if sweep.damaged:
        shown = ", ".join(sweep.damaged[:5]) + (" …" if len(sweep.damaged) > 5 else "")
        out.append(Finding(ID, NOTE, f"Part of the archive is damaged, so Blotter couldn't read all of it ({shown}). "
                                     "Whatever it could read was checked.", {"damaged": sweep.damaged}, [UNCHECKED]))
    if sweep.repaired:
        out.append(Finding(ID, NOTE, "The archive's table of contents is damaged, so Windows can't open it, but "
                                     "7-Zip and similar tools still can. Blotter read every file from their own "
                                     "headers, the same way, and checked them.", {"repaired": sweep.repaired}))
    if sweep.too_big:
        out.append(Finding(ID, NOTE, "Blotter stopped unpacking because " + "; ".join(sweep.too_big[:3]) +
                           ". Files past that point weren't checked.", {"limits": sweep.too_big}, [UNCHECKED]))
    if sweep.locked:
        shown = ", ".join(sweep.locked[:5]) + (" …" if len(sweep.locked) > 5 else "")
        tried = ("The password you typed didn't open them either" if sweep.password else
                 "Type its password below and Blotter checks again")
        out.append(Finding(ID, NOTE, f"Some contents are password-protected and the password isn't "
                                     f"\"{config.ARCHIVE_PASSWORD}\", so Blotter couldn't look at them ({shown}). "
                                     f"{tried}.",
                           {"locked": sweep.locked, "needs_password": True}, [UNCHECKED]))
    files = "1 file" if sweep.checked == 1 else f"{sweep.checked} files"
    if not out:
        out.append(Finding(ID, CLEAR, f"Blotter unpacked {files} from the archive and checked each one; "
                                      "none showed anything unusual.", {"files": sweep.checked}))
    elif sweep.checked:
        out.append(Finding(ID, CLEAR, f"Blotter unpacked and checked {files} from the archive.",
                           {"files": sweep.checked}))
    return out
