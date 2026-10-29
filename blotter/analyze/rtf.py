"""RTF documents: the objects embedded in them, with oletools' rtfobj. Never opened in Word.

RTF can't hold macros itself, but it can embed objects, and that is how RTF attacks work: an old
Equation Editor object, a linked object (OLE2Link) that fetches a document from the internet, an
ActiveX control with a known flaw, or a program packed inside ("OLE Package"). Which objects are tied
to known flaws comes from oletools (its CLSID list and the classes rtfobj itself flags), not from Blotter.
"""

import logging
import re

from ..findings import CLEAR, DISGUISED, ERROR, HIDING, NOTE, RISKY, SUSPICIOUS, UNCHECKED, Finding, hiding

MAX_OBJECTS = 50
OFFICE_CLASS = re.compile(r"^(word\.document|excel\.sheet|powerpoint\.(show|slide))", re.I)
logging.getLogger("rtfobj").setLevel(logging.CRITICAL)


def analyze(check, data: bytes, scope=None) -> list[Finding]:
    from oletools import rtfobj
    s = {"scope": scope} if scope else {}
    try:
        parser = rtfobj.RtfObjParser(data)
        parser.parse()
    except Exception as e:  # rtfobj raises many kinds; any of them means it didn't read the whole file
        return [Finding(check, ERROR, f"Blotter couldn't read the RTF file's structure ({type(e).__name__}).", s)]
    objects = parser.objects
    if not objects:
        return [Finding(check, CLEAR, "It contains no embedded objects (the way RTF files carry attacks or hidden "
                                      "files).", s)]
    out = []
    for n, obj in enumerate(objects[:MAX_OBJECTS], 1):
        out += _object(check, obj, n, s, rtfobj)
    if len(objects) > MAX_OBJECTS:
        out.append(Finding(check, NOTE, f"It embeds {len(objects)} objects; Blotter looked at the first "
                                        f"{MAX_OBJECTS} only.", s, [UNCHECKED]))
    warned = [f for f in out if f.level == SUSPICIOUS or RISKY in f.signals]
    if warned and b"\\objupdate" in data:
        out.append(hiding(check, "rtf-autoload", "It forces its embedded objects to load as soon as the document "
                                                 "opens (\\objupdate), without a click.", s))
    if all(f.level == CLEAR for f in out):
        shown = ", ".join(sorted({f.details["class"] for f in out if f.details.get("class")})) or "unnamed"
        return [Finding(check, CLEAR, f"It embeds {_count(len(objects))} ({shown}); none of a kind used in attacks.",
                        {**s, "objects": len(objects)})]
    return out


def _count(n):
    return "1 object" if n == 1 else f"{n} objects"


def _object(check, obj, n, s, rtfobj) -> list[Finding]:
    where = f"Embedded object {n}"
    if not obj.is_ole:
        return [Finding(check, NOTE, f"{where} isn't a well-formed object, so Blotter couldn't read it. Broken "
                                     "objects are a known way to hide attack code in RTF files.",
                        {**s, "ability": "rtf-malformed", "object": n}, [UNCHECKED, HIDING])]
    raw = obj.class_name or b""
    cls = (raw.decode("latin-1", "replace") if isinstance(raw, bytes) else str(raw)).rstrip("\0")
    d = {**s, "class": cls, "object": n}
    out = []
    if cls == "OLE2Link":
        urls = sorted({w for w in re.findall(r"https?://[^\s\"'<>\x00]{4,200}",
                                             (obj.oledata or b"").decode("utf-16-le", "replace"))})
        fetch = f" from {urls[0]}" if urls else ""
        out.append(Finding(check, SUSPICIOUS, f"{where} is a linked object (OLE2Link) that fetches content{fetch} "
                                              "when the document opens; oletools marks this as a likely attack on "
                                              "an Office flaw (CVE-2017-0199).", {**d, "urls": urls[:5]}))
    elif cls.lower().startswith("equation.3"):
        out.append(Finding(check, SUSPICIOUS, f"{where} is an old Equation Editor object ({cls}). Real documents "
                                              "almost never contain these any more; oletools marks them as a likely "
                                              "attack on an old Office flaw (CVE-2017-11882).", d))
    elif obj.clsid_desc and "CVE" in obj.clsid_desc:
        out.append(Finding(check, SUSPICIOUS, f"{where} is a kind of object that oletools links to attacks on known "
                                              f"Office flaws: {obj.clsid_desc}.", {**d, "clsid": obj.clsid}))
    if obj.is_package:
        out += _package(check, obj, where, d, rtfobj)
    elif OFFICE_CLASS.match(cls) and obj.oledata:
        from .office import _macros
        for f in _macros(check, obj.oledata, s):
            if f.level == CLEAR and not f.signals:
                continue
            f.text = f"In its embedded {cls} document: {f.text}"
            out.append(f)
    if not out:
        out.append(Finding(check, CLEAR, f"{where} is an ordinary {cls or 'unnamed'} object.", d))
    return out


def _package(check, obj, where, d, rtfobj) -> list[Finding]:
    """An "OLE Package": a whole file inside the document that opens when its icon is double-clicked."""
    name = obj.filename or ""
    temp = obj.temp_path or ""
    data = obj.olepkgdata or b""
    ext = lambda p: ("." + p.rsplit(".", 1)[-1]) if "." in p else ""  # noqa: E731
    program = bool(rtfobj.re_executable_extensions.match(ext(name)) or rtfobj.re_executable_extensions.match(
        ext(temp)) or data[:2] == b"MZ")
    d = {**d, "ability": "embedded-file", "embedded": name, "temp_path": temp, "size": len(data)}
    if program:
        return [Finding(check, NOTE, f"{where} is a program or script packed inside the document "
                                     f"({name or 'no name'}); it runs if you double-click its icon. Real documents "
                                     "rarely carry programs; it is a known way to deliver malware.", d,
                        [RISKY, DISGUISED])]
    out = [Finding(check, NOTE, f"{where} is a file packed inside the document ({name or 'no name'}) that can be "
                                "opened from it.", d)]
    if ext(name).lower() != ext(temp).lower() and temp:
        out.append(hiding(check, "renamed-package", f"{where}'s name ({name}) doesn't match the name it gets when "
                                                    f"opened ({temp.rsplit(chr(92), 1)[-1]}).", d))
    return out
