"""Rule packs at rest, inside a password-protected 7z archive (AES-256), unpacked only in memory.

YARA rules describe malware, so they contain pieces of it (text and byte patterns). Stored as plain
files, an antivirus program (Defender, or a friend's antivirus) could mistake Blotter's own rules
for malware. Encrypted, no scanner can read them. The password is not a secret: it only keeps
scanners out. Anyone can open the archive with 7-Zip using it.
"""

import io
import os
import tempfile
from pathlib import Path

import py7zr
from py7zr.io import BytesIOFactory

PASSWORD = "blotter-rules"
FILTERS = [{"id": py7zr.FILTER_LZMA2, "preset": 1}, {"id": py7zr.FILTER_CRYPTO_AES256_SHA256}]
MAX_MEMBER = 512 * 1024 * 1024


def write(path, members: dict[str, bytes]) -> None:
    """Replace the archive at path with these members, atomically (a half-written vault is never used)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    os.close(fd)
    try:
        with py7zr.SevenZipFile(tmp, "w", filters=FILTERS, password=PASSWORD) as z:
            z.set_encrypted_header(True)  # file names hidden too
            for name, data in members.items():
                z.writef(io.BytesIO(data), name)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def read(path) -> dict[str, bytes]:
    """All members, in memory. Raises OSError or py7zr errors if the archive is missing or damaged."""
    factory = BytesIOFactory(MAX_MEMBER)
    with py7zr.SevenZipFile(path, "r", password=PASSWORD) as z:
        names = z.getnames()
        z.extract(factory=factory)
    out = {}
    for name in names:
        member = factory.get(name)
        member.seek(0)
        out[name] = member.read()
    return out
