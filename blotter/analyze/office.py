"""Office documents: macros (oletools' olevba) and remote templates. RTF files go to rtf.py (embedded objects).

Reads the document's parts; never opens it in Office and never runs a macro.
"""

import logging
import re
import warnings
import zipfile
from io import BytesIO

from ..findings import CLEAR, ERROR, NOTE, SUSPICIOUS, UNCHECKED, Finding, hiding, risky

OFFICE_REALS = {"ole", "ooxml", "rtf"}
logging.getLogger("olevba").setLevel(logging.CRITICAL)
for name in ("oletools", "olevba", "rtfobj", "crypto", "msoffcrypto"):
    logging.getLogger(name).setLevel(logging.CRITICAL)

# olevba keyword -> what it means. Anything that runs, downloads or writes counts as "can run programs".
RUNS = re.compile(r"^(shell|wscript\.shell|shell\.application|run|exec|createobject|getobject|"
                  r"urldownloadtofile|xmlhttp|serverxmlhttp|winhttp|powershell|cmd|mshta|"
                  r"callbyname|macscript|environ|createprocess|virtualalloc|rtlmovememory|"
                  r"call|declare|lib|savetofile|write|put|open|binary|kill|filecopy|copyfile)", re.I)
OBFUSCATED = {"hex string", "base64 string", "dridex string", "vba string", "vba obfuscated strings"}


def analyze(check, ft, data: bytes, scope=None) -> list[Finding]:
    s = {"scope": scope} if scope else {}
    out = []
    if ft.real == "rtf":  # RTF can't hold macros; its embedded objects are what matters
        from . import rtf
        return rtf.analyze(check, data, scope)
    if ft.real == "ooxml":
        out += _remote_template(check, data, s)
    out += _macros(check, data, s)
    return out


def _macros(check, data, s) -> list[Finding]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # oletools uses older pyparsing names; harmless but noisy
        from oletools import olevba
    try:
        vba = olevba.VBA_Parser("document", data=data, relaxed=True)
    except Exception as e:  # olevba raises many kinds; any of them means "couldn't read"
        if "encrypt" in str(e).lower() or "password" in str(e).lower():
            return [Finding(check, NOTE, "The document is password-protected, so Blotter couldn't look for "
                                         "macros inside.", s, [UNCHECKED])]
        return [Finding(check, ERROR, f"Blotter couldn't read the document's parts ({type(e).__name__}).", s)]
    try:
        if not vba.detect_macros():
            return [Finding(check, CLEAR, "It contains no macros (small programs inside documents).", s)]
        results = vba.analyze_macros() or []
        try:
            stomped = vba.detect_vba_stomping()
        except Exception:
            stomped = False
    finally:
        vba.close()

    kinds = {str(kind).lower() for kind, _, _ in results}
    words = sorted({str(word) for kind, word, _ in results if str(kind).lower() == "suspicious"})
    autorun = sorted({str(word) for kind, word, _ in results if str(kind).lower() == "autoexec"})
    runs = [w for w in words if RUNS.match(w)]
    details = {**s, "autorun": autorun, "keywords": words[:20]}
    out = []
    if autorun and runs:
        out.append(risky(check, "macro-autorun-exec",
            f"Its macro runs by itself when the document is opened ({', '.join(autorun[:3])}) and can run "
            f"programs, download or write files ({', '.join(runs[:4])}). That combination is how most "
            "malicious documents work.", details, level=SUSPICIOUS))
    elif autorun:
        out.append(risky(check, "macro-autorun",
            f"Its macro runs by itself as soon as the document is opened ({', '.join(autorun[:3])}). "
            "Some company spreadsheets do that too, but it is the most common way documents spread malware.",
            details))
    elif runs:
        out.append(risky(check, "macro-exec",
            f"It contains a macro that can run programs, download or write files ({', '.join(runs[:4])}). "
            "It only runs if you allow macros.", details))
    else:
        out.append(Finding(check, NOTE, "It contains macros, but they don't start by themselves and don't "
                                        "use any of the risky commands Blotter looks for.", details))
    if kinds & OBFUSCATED:
        out.append(hiding(check, "macro-obfuscation",
            "Its macro code is scrambled (encoded or chopped-up text) so it's hard to read. "
            "Normal macros don't need that.", s))
    if stomped:
        out.append(hiding(check, "vba-stomping",
            "The macro's readable source doesn't match the code that would really run (\"VBA stomping\"), "
            "a trick to fool scanners.", s))
    return out


def _remote_template(check, data, s) -> list[Finding]:
    try:
        with zipfile.ZipFile(BytesIO(data)) as z:
            rels = [n for n in z.namelist() if n.endswith(".rels")][:200]
            text = " ".join(z.read(n)[:200_000].decode("utf-8", "replace") for n in rels)
    except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError):
        return []
    hits = re.findall(r'<Relationship[^>]*Type="[^"]*/(attachedTemplate|oleObject|frame|subDocument)"[^>]*'
                      r'Target="(https?://[^"]+|\\\\[^"]+)"[^>]*TargetMode="External"', text, re.I)
    hits += [(t, u) for u, t in re.findall(r'<Relationship[^>]*Target="(https?://[^"]+|\\\\[^"]+)"[^>]*'
                                            r'Type="[^"]*/(attachedTemplate|oleObject|frame|subDocument)"'
                                            r'[^>]*TargetMode="External"', text, re.I)]
    if not hits:
        return []
    kind, url = hits[0]
    return [risky(check, "remote-template",
        f"When opened, it fetches a {kind} from {url[:120]}. Documents that pull content from the internet "
        "like this are a known way to deliver malware without macros inside.", {**s, "url": url}, hiding=True)]
