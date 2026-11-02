"""The real file type from its first bytes ("magic bytes"), and whether its name tells the truth."""

import re
import struct
import unicodedata
import zipfile
from dataclasses import dataclass

HEAD = 64 * 1024

# What a name ending promises. Only endings listed here are compared with the contents.
FAMILIES = {
    "program": "exe dll scr com sys cpl ocx msi drv efi pif msp".split(),
    "script": "ps1 psm1 psd1 bat cmd vbs vbe js jse wsf wsh hta reg scf url py sh".split(),
    "shortcut": ["lnk"],
    "document": ("pdf doc docx docm dot dotx dotm xls xlsx xlsm xlsb xlt xltm ppt pptx pptm pps ppsx "
                 "rtf odt ods odp txt csv md log ini json xml epub one").split(),
    "archive": "zip rar 7z gz tgz tar cab iso img vhd vhdx jar apk xpi vsix nupkg whl".split(),
    "image": "jpg jpeg png gif bmp ico webp tif tiff heic svg".split(),
    "media": "mp3 mp4 mkv avi mov wav flac ogg m4a webm wmv".split(),
}
FAMILY_OF = {ext: fam for fam, exts in FAMILIES.items() for ext in exts}
RUNNABLE = {"program", "script", "shortcut"}
LOOKS_HARMLESS = {"document", "image", "media", "archive"}

# Name endings that are compatible with each real type (a .docx is a zip inside, and so on).
COMPATIBLE = {
    "zip": {"zip", "jar", "apk", "xpi", "vsix", "nupkg", "whl", "epub", "docx", "docm", "dotx", "dotm",
            "xlsx", "xlsm", "xltm", "xlsb", "pptx", "pptm", "ppsx", "odt", "ods", "odp"},
    "ole": {"doc", "dot", "xls", "xlt", "ppt", "pps", "msi", "msp", "msg"},
    "pe": {"exe", "dll", "scr", "com", "sys", "cpl", "ocx", "drv", "efi", "pif"},
    "text": set(FAMILIES["script"]) | {"txt", "csv", "md", "log", "ini", "json", "xml", "svg", "rtf"},
}

# Real type -> the name endings that fit it.
EXPECTED = {
    "pe": COMPATIBLE["pe"], "mz": {"exe", "com"}, "elf": set(), "macho": set(), "wasm": set(),
    "zip": COMPATIBLE["zip"], "ooxml": COMPATIBLE["zip"], "odf": COMPATIBLE["zip"], "jar": COMPATIBLE["zip"],
    "ole": COMPATIBLE["ole"], "text": COMPATIBLE["text"], "lnk": {"lnk"}, "rtf": {"rtf", "doc"},
    "pdf": {"pdf"}, "rar": {"rar"}, "7z": {"7z"}, "gzip": {"gz", "tgz"}, "cab": {"cab"}, "chm": set(),
    "iso": {"iso", "img"}, "vhd": {"vhd", "vhdx"}, "tar": {"tar"}, "onenote": {"one"},
    "msi": {"msi", "msp", "msm", "mst"},
    "java": set(), "png": {"png"}, "jpeg": {"jpg", "jpeg"}, "gif": {"gif"}, "bmp": {"bmp"}, "ico": {"ico"},
    "mp3": {"mp3"}, "flac": {"flac"}, "ogg": {"ogg"}, "mkv": {"mkv", "webm"}, "riff": {"webp", "avi", "wav"},
    "mp4": {"mp4", "mov", "m4a"},
}

BIDI = re.compile("[‪-‮⁦-⁩‎‏]")


@dataclass
class FileType:
    kind: str      # program, script, shortcut, document, archive, image, media, text, unknown
    label: str     # plain words, e.g. "a Windows program (EXE)"
    real: str      # short code: pe, elf, macho, zip, ooxml, ole, rar, 7z, pdf, png, ...
    detail: dict

    def to_dict(self):
        return {"kind": self.kind, "label": self.label, "real": self.real, **self.detail}


def _pe(head: bytes):
    if len(head) < 0x40:
        return None
    offset = struct.unpack_from("<I", head, 0x3C)[0]
    if offset + 24 > len(head) or head[offset:offset + 4] != b"PE\0\0":
        return None
    characteristics = struct.unpack_from("<H", head, offset + 22)[0]
    opt = offset + 24
    magic = struct.unpack_from("<H", head, opt)[0] if opt + 2 <= len(head) else 0
    subsystem_at = opt + 68
    subsystem = struct.unpack_from("<H", head, subsystem_at)[0] if subsystem_at + 2 <= len(head) else 0
    dotnet = False
    dirs = opt + (96 if magic == 0x10B else 112)
    if dirs + 15 * 8 <= len(head):
        dotnet = struct.unpack_from("<II", head, dirs + 14 * 8) != (0, 0)
    if subsystem == 1:
        return "a Windows driver (SYS)", {"pe": "driver", "dotnet": dotnet}
    if characteristics & 0x2000:
        return "a Windows program library (DLL)", {"pe": "dll", "dotnet": dotnet}
    return "a Windows program (EXE)", {"pe": "exe", "dotnet": dotnet}


def _zip_kind(path):
    try:
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist()[:5000])
    except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError):
        return "zip", "a ZIP archive", {}
    if "[Content_Types].xml" in names:
        macros = any(n.lower().endswith("vbaproject.bin") for n in names)
        what = "an Office document" + (" with macros" if macros else "")
        return "ooxml", what, {"macros": macros}
    if "META-INF/MANIFEST.MF" in names and any(n.endswith(".class") for n in names):
        return "jar", "a Java program (JAR)", {}
    if "mimetype" in names:
        return "odf", "an OpenDocument or e-book file", {}
    return "zip", "a ZIP archive", {}


def zip_type(source) -> "FileType":
    """What a zip really is: an Office or OpenDocument file, a Java program or a plain zip. source: a path or a
    file object (e.g. the first of two zips glued together)."""
    real, label, detail = _zip_kind(source)
    kind = {"ooxml": "document", "odf": "document", "jar": "program"}.get(real, "archive")
    return FileType(kind, label, real, detail)


MAGIC_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
MAGIC = [
    (b"%PDF", "pdf", "document", "a PDF document"),
    (b"Rar!\x1a\x07", "rar", "archive", "a RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "archive", "a 7-Zip archive"),
    (b"\x1f\x8b", "gzip", "archive", "a GZIP archive"),
    (b"MSCF", "cab", "archive", "a Windows cabinet (CAB) archive"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "document", "an older Office document or installer (OLE)"),
    (b"{\\rt", "rtf", "document", "a rich-text document (RTF)"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk", "shortcut", "a Windows shortcut (LNK)"),
    (b"\x7fELF", "elf", "program", "a Linux program (ELF)"),
    (b"\xcf\xfa\xed\xfe", "macho", "program", "a macOS program (Mach-O)"),
    (b"\xce\xfa\xed\xfe", "macho", "program", "a macOS program (Mach-O)"),
    (b"\xca\xfe\xba\xbe", "java", "program", "a Java class or macOS program"),
    (b"\x00asm", "wasm", "program", "a WebAssembly program"),
    (b"ITSF", "chm", "document", "a compiled Windows help file (CHM)"),
    (b"\x89PNG\r\n\x1a\n", "png", "image", "a PNG picture"),
    (b"\xff\xd8\xff", "jpeg", "image", "a JPEG picture"),
    (b"GIF8", "gif", "image", "a GIF picture"),
    (b"BM", "bmp", "image", "a BMP picture"),
    (b"\x00\x00\x01\x00", "ico", "image", "a Windows icon"),
    (b"ID3", "mp3", "media", "an MP3 audio file"),
    (b"fLaC", "flac", "media", "a FLAC audio file"),
    (b"OggS", "ogg", "media", "an OGG audio or video file"),
    (b"\x1a\x45\xdf\xa3", "mkv", "media", "a Matroska or WebM video"),
    (b"vhdxfile", "vhd", "archive", "a virtual hard disk (VHD)"),
    (b"conectix", "vhd", "archive", "a virtual hard disk (VHD)"),
    (bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3"), "onenote", "document", "a OneNote notebook section"),
]
# Windows Installer packages are OLE files; their root entry's class ID says so (MSI and merge module, patch,
# transform).
MSI_CLASSES = {bytes.fromhex(h) for h in ("84100c0000000000c000000000000046", "86100c0000000000c000000000000046",
                                          "82100c0000000000c000000000000046")}
# Where a CD/DVD image (ISO 9660 or UDF) names its format: one of these 5-byte tags at 0x8001, 0x8801 or 0x9001.
DISC_TAGS = (b"CD001", b"BEA01", b"NSR02", b"NSR03")


def _is_text(head: bytes) -> bool:
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return True
    sample = head[:8192]
    if not sample or b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError as e:
        if e.start > len(sample) - 4:
            return True  # cut in the middle of a character
        return sum(32 <= b < 127 or b in (9, 10, 13) for b in sample) / len(sample) > 0.95


def _ole_class(f, head: bytes) -> bytes:
    """The class ID of an OLE file's root entry (the first directory entry), or b"" when it can't be read."""
    if len(head) < 0x34:
        return b""
    shift, first_dir = struct.unpack_from("<H", head, 0x1E)[0], struct.unpack_from("<I", head, 0x30)[0]
    if shift not in (9, 12) or first_dir >= 0xFFFFFFFA:
        return b""
    f.seek(((first_dir + 1) << shift) + 0x50)
    return f.read(16)


PDF_HEADER = re.compile(rb"%PDF-\d\.\d")
PDF_SEARCH = 1024  # Adobe Reader accepts the header anywhere in the first 1024 bytes


def detect(path) -> FileType:
    with open(path, "rb") as f:
        head = f.read(HEAD)
        msi = head.startswith(MAGIC_OLE) and _ole_class(f, head) in MSI_CLASSES
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - 512))
        tail = f.read(512) if size >= 1024 else b""
    if head.startswith(b"MZ"):
        pe = _pe(head)
        if pe:
            return FileType("program", pe[0], "pe", pe[1])
        return FileType("program", "an old DOS program (MZ)", "mz", {})
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return zip_type(path)
    if msi:
        return FileType("program", "a Windows installer package (MSI)", "msi", {})
    for magic, real, kind, label in MAGIC:
        if head.startswith(magic):
            return FileType(kind, label, real, {})
    if any(head[at:at + 5] in DISC_TAGS for at in (0x8001, 0x8801, 0x9001)):
        return FileType("archive", "a disc image (ISO)", "iso", {})
    if tail.startswith(b"conectix"):  # a fixed-size VHD keeps its footer at the end only
        return FileType("archive", "a virtual hard disk (VHD)", "vhd", {})
    if head[257:262] == b"ustar":
        return FileType("archive", "a TAR archive", "tar", {})
    pdf = PDF_HEADER.search(head[:PDF_SEARCH + 8])
    if pdf and pdf.start() <= PDF_SEARCH:
        return FileType("document", "a PDF document", "pdf", {"pdf_offset": pdf.start()})
    rtf = head.lstrip(b" \t\r\n")
    if rtf.startswith(b"{\\rt") and len(head) - len(rtf) <= PDF_SEARCH:
        return FileType("document", "a rich-text document (RTF)", "rtf", {"rtf_offset": len(head) - len(rtf)})
    if head[8:12] in (b"WEBP", b"AVI ", b"WAVE") and head.startswith(b"RIFF"):
        kind = "image" if head[8:12] == b"WEBP" else "media"
        return FileType(kind, "a WebP picture" if kind == "image" else "an audio or video file", "riff", {})
    if head[4:8] == b"ftyp":
        return FileType("media", "an MP4 or QuickTime video", "mp4", {})
    if _is_text(head):
        return FileType("text", "a text file", "text", {})
    return FileType("unknown", "a file of a kind Blotter doesn't recognise", "unknown", {})


def extensions(name: str) -> list[str]:
    """['pdf', 'exe'] for 'invoice.pdf.exe'. Only short, letter-and-digit endings count."""
    base = name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    parts = base.split(".")[1:]
    return [p.strip().lower() for p in parts if 0 < len(p.strip()) <= 5 and p.strip().isalnum()]


def name_problems(name: str) -> dict:
    """Tricks in the name itself, whatever the contents."""
    out = {}
    if BIDI.search(name):
        out["bidi"] = True  # a hidden character that flips text, so 'gpj.exe' shows as 'exe.jpg'
    if re.search(r"\s{5,}\.\w{1,5}$", name) or re.search(r"\.\w{1,5}\s{5,}\.\w{1,5}$", name):
        out["padding"] = True  # many spaces push the real ending out of sight
    exts = extensions(name)
    if len(exts) >= 2 and FAMILY_OF.get(exts[-1]) in RUNNABLE and FAMILY_OF.get(exts[-2]) in LOOKS_HARMLESS:
        out["double"] = (exts[-2], exts[-1])
    return out


def visible(name: str) -> str:
    """The name with invisible characters shown, so the card doesn't flip text either."""
    return "".join(f"[U+{ord(c):04X}]" if unicodedata.category(c) in ("Cf",) else c for c in name)


def compare(ft: FileType, name: str | None) -> dict:
    """{'ext', 'claimed': family or None, 'match': True/False/None, 'disguised': bool}"""
    exts = extensions(name or "")
    ext = exts[-1] if exts else None
    family = FAMILY_OF.get(ext)
    result = {"ext": ext, "claimed": family, "match": None, "disguised": False}
    expected = EXPECTED.get(ft.real)
    if not family or expected is None:
        return result  # an ending we don't judge, or contents we don't recognise
    result["match"] = ext in expected
    result["disguised"] = not result["match"] and ft.kind in ("program", "shortcut") and family in LOOKS_HARMLESS
    return result
