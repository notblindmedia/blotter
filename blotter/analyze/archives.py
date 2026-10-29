"""Unpack zip, rar and 7z archives safely: one file at a time, into Blotter's own folder, with limits.

Limits (config.py) stop "zip bombs", archives built to unpack into something enormous:
total unpacked size, number of files, archives inside archives, and how tightly data is packed.
Unpacked files get neutral names (m0001.blotter); nothing is ever opened or run.
Locked archives are tried with the password the person typed in (if any), then "infected"
(what malware researchers use). A zip whose table of contents is broken is read from each file's
own header instead, as 7-Zip, WinRAR and tar do, so breaking it can't hide what is inside.
"""

import mmap
import os
import shutil
import struct
import subprocess
import uuid
import zipfile
import zlib
from pathlib import Path

from .. import config

CHUNK = 1024 * 1024
WINDOWS_TAR = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "tar.exe"
RAR_TOOLS = [Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "WinRAR" / "UnRAR.exe",
             Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "7-Zip" / "7z.exe"]


class Bomb(Exception):
    """The archive would unpack beyond a limit."""


class Locked(Exception):
    """The archive (or a file in it) is password-protected and 'infected' isn't the password."""


class Budget:
    def __init__(self):
        self.total = 0
        self.members = 0

    def member(self, name, declared, packed):
        self.members += 1
        if self.members > config.ARCHIVE_MAX_MEMBERS:
            raise Bomb(f"it holds more than {config.ARCHIVE_MAX_MEMBERS} files")
        if declared is not None and self.total + declared > config.ARCHIVE_MAX_TOTAL:
            raise Bomb(f"it would unpack to more than {config.ARCHIVE_MAX_TOTAL // 1024 ** 2} MB")
        if declared and packed and declared > CHUNK and declared / max(packed, 1) > config.ARCHIVE_MAX_RATIO:
            raise Bomb(f"{name} is packed {declared // max(packed, 1)} times smaller than its real size, "
                       "like a zip bomb")

    def add(self, n):
        self.total += n
        if self.total > config.ARCHIVE_MAX_TOTAL:
            raise Bomb(f"it unpacks to more than {config.ARCHIVE_MAX_TOTAL // 1024 ** 2} MB")


def workdir() -> Path:
    """Inside a sandboxed worker: its own work folder (the only place it may write)."""
    base = Path(os.environ.get("BLOTTER_WORK") or config.INCOMING)
    path = base / f"unpack-{uuid.uuid4().hex}"
    path.mkdir(parents=True)
    return path


def _copy_limited(source, target: Path, budget: Budget, declared=None):
    written = 0
    with open(target, "wb") as out:
        while chunk := source.read(CHUNK):
            written += len(chunk)
            budget.add(len(chunk))
            if declared is not None and written > declared + CHUNK:
                raise Bomb("a file inside is bigger than the archive says")
            out.write(chunk)
    return written


def walk(path, real, visit, budget: Budget, passwords=None):
    """Call visit(name, unpacked_path) for every file in the archive. Returns notes (e.g. which files were locked)."""
    passwords = [p for p in (passwords or []) if p] + [config.ARCHIVE_PASSWORD]
    folder = workdir()
    try:
        if real == "zip":
            return _zip(path, visit, budget, folder, passwords)
        if real == "7z":
            return _7z(path, visit, budget, folder, passwords)
        if real == "rar":
            return _rar(path, visit, budget, folder, passwords)
        raise ValueError(real)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def _zip(path, visit, budget, folder, passwords):
    locked = []
    try:
        z = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, EOFError, ValueError, OSError, struct.error):
        # The table of contents at the end is damaged or missing. 7-Zip, WinRAR and tar still unpack such
        # zips from each file's own header, so Blotter reads them that way too.
        return _zip_lenient(path, visit, budget, folder)
    visited = set()
    with z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        declared_total = sum(i.file_size for i in infos)
        if declared_total > config.ARCHIVE_MAX_TOTAL:
            raise Bomb(f"it would unpack to more than {config.ARCHIVE_MAX_TOTAL // 1024 ** 2} MB")
        for n, info in enumerate(infos, 1):
            budget.member(info.filename, info.file_size, info.compress_size)
            target = folder / f"m{n:04d}.blotter"
            try:
                opened = _zip_member(z, path, info, target, budget, passwords)
            except (zipfile.BadZipFile, zlib.error, EOFError, OSError):
                # The table of contents points to the wrong place, or this file's data is damaged: read the
                # rest from the files' own headers (files already checked aren't checked twice).
                target.unlink(missing_ok=True)
                notes = _zip_lenient(path, visit, budget, folder, skip=visited)
                return {**notes, "locked": locked + notes["locked"]}
            if not opened:
                locked.append(info.filename)
                continue
            visit(info.filename, target)
            visited.add(info.filename)
            target.unlink(missing_ok=True)
    return {"locked": locked, "damaged": []}


LOCAL_HEADER = b"PK\x03\x04"
DESCRIPTOR = b"PK\x07\x08"
DIRECTORY = (b"PK\x01\x02", b"PK\x05\x06", b"PK\x06\x06")  # the table of contents: no more files after it


def _zip_lenient(path, visit, budget, folder, skip=()):
    """Unpack a zip whose table of contents is broken by walking the files' own headers from the start.
    Notes: 'damaged' names files that couldn't be read whole (what could be read is still checked),
    'complete' says whether the walk reached the table of contents, so no file can be missing."""
    locked, damaged, count, last_end = [], [], 0, None
    with open(path, "rb") as fh:
        if os.fstat(fh.fileno()).st_size == 0:
            raise zipfile.BadZipFile("the file is empty")
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as m:
            pos = m.find(LOCAL_HEADER)
            if pos < 0:
                raise zipfile.BadZipFile("no file headers in it")
            while pos >= 0:
                entry = _local_entry(m, pos)
                if entry is None:  # cut off inside a header
                    damaged.append(f"the file at byte {pos}")
                    last_end = None
                    break
                name = entry["name"]
                if name.endswith("/") and not entry["csize"]:
                    last_end = entry["data"]
                    pos = m.find(LOCAL_HEADER, last_end)
                    continue
                count += 1
                if name not in skip:
                    budget.member(name, entry["usize"] or None, entry["csize"] or None)
                target = folder / f"m{count:04d}.blotter"
                if entry["flags"] & 0x1:  # locked: the normal reader tries passwords, this one doesn't
                    locked.append(name)
                    last_end = entry["data"] + entry["csize"] if entry["csize"] else None
                else:
                    last_end, whole = _lenient_member(m, entry, target, budget if name not in skip else Budget())
                    if not whole:
                        damaged.append(name)
                    if target.is_file() and target.stat().st_size and name not in skip:
                        visit(name, target)  # whole or not: check what is there
                    target.unlink(missing_ok=True)
                pos = m.find(LOCAL_HEADER, last_end if last_end is not None else entry["data"])
            complete = last_end is not None and m[last_end:last_end + 4] in DIRECTORY
    return {"locked": locked, "damaged": damaged, "lenient": True, "complete": complete}


def _local_entry(m, pos):
    """One local file header: name, flags, compression, CRC, sizes and where its data starts. None if cut off."""
    if pos + 30 > len(m):
        return None
    _, _, flags, method, _, _, crc, csize, usize, name_len, extra_len = struct.unpack_from("<4sHHHHHIIIHH", m, pos)
    data = pos + 30 + name_len + extra_len
    if data > len(m):
        return None
    name = m[pos + 30:pos + 30 + name_len].decode("utf-8" if flags & 0x800 else "cp437", "replace")
    extra = m[pos + 30 + name_len:data]
    if 0xFFFFFFFF in (csize, usize):  # ZIP64: the real sizes are in an extra field
        i = 0
        while i + 4 <= len(extra):
            tag, size = struct.unpack_from("<HH", extra, i)
            if tag == 1:
                values = list(struct.unpack_from(f"<{min(size, 16, len(extra) - i - 4) // 8}Q", extra, i + 4))
                if usize == 0xFFFFFFFF and values:
                    usize = values.pop(0)
                if csize == 0xFFFFFFFF and values:
                    csize = values.pop(0)
                break
            i += 4 + size
    return {"name": name, "flags": flags, "method": method, "crc": crc, "csize": csize, "usize": usize,
            "data": data}


def _lenient_member(m, e, target, budget):
    """Unpack one file from its own header. Returns (where its data ends or None, whether it was read whole)."""
    start, sized = e["data"], not (e["flags"] & 0x8) or e["csize"]
    written, crc = 0, 0
    end, whole = None, False
    with open(target, "wb") as out:
        def put(chunk):
            nonlocal written, crc
            written += len(chunk)
            budget.add(len(chunk))
            if sized and e["usize"] and written > e["usize"] + CHUNK:
                raise Bomb("a file inside is bigger than the archive says")
            crc = zlib.crc32(chunk, crc)
            out.write(chunk)

        if e["method"] == 0:  # stored
            stop = start + e["csize"] if sized else _next_signature(m, start)
            whole = stop <= len(m)
            stop = min(stop, len(m))
            for i in range(start, stop, CHUNK):
                put(m[i:min(i + CHUNK, stop)])
            end = stop if whole else None
        elif e["method"] == 8:  # deflate: the stream itself says where it ends, whatever the header claims
            d, i = zlib.decompressobj(-15), start
            try:
                while i < len(m) and not d.eof:
                    piece = m[i:i + CHUNK]
                    put(d.decompress(piece, CHUNK))
                    while d.unconsumed_tail and not d.eof:
                        put(d.decompress(d.unconsumed_tail, CHUNK))
                    i += len(piece)
                if d.eof:
                    end, whole = i - len(d.unused_data), True
            except zlib.error:
                pass
        else:  # bzip2, LZMA and the rest only through the normal reader
            return None, False
    expected = e["crc"]
    if end is not None and e["flags"] & 0x8:  # a "data descriptor" with the CRC and sizes follows the data
        if m[end:end + 4] == DESCRIPTOR:
            expected = struct.unpack_from("<I", m, end + 4)[0] if end + 8 <= len(m) else None
            zip64 = (m[end + 16:end + 20] not in (LOCAL_HEADER, *DIRECTORY)
                     and m[end + 24:end + 28] in (LOCAL_HEADER, *DIRECTORY))
            end += 24 if zip64 else 16
        else:
            expected = struct.unpack_from("<I", m, end)[0] if end + 4 <= len(m) else None
            end += 12
    return end, whole and crc == expected


def _next_signature(m, start):
    """Where a stored file of unknown size ends: at its data descriptor, or else at the next header."""
    found = [i for i in (m.find(DESCRIPTOR, start), m.find(LOCAL_HEADER, start),
                         *(m.find(sig, start) for sig in DIRECTORY)) if i >= 0]
    return min(found) if found else len(m) + 1


def _zip_member(z, path, info, target, budget, passwords) -> bool:
    """Unpack one zip entry, trying each password if it is locked. False if none opens it."""
    if not info.flag_bits & 0x1:
        try:
            with z.open(info) as source:
                _copy_limited(source, target, budget, info.file_size)
            return True
        except NotImplementedError:  # an unusual compression: let Windows' tar try
            return _tar_member(path, info.filename, target, budget, info.file_size, None)
    for password in passwords:
        try:
            with z.open(info, pwd=password.encode("utf-8")) as source:
                _copy_limited(source, target, budget, info.file_size)
            return True
        except RuntimeError:  # wrong password
            continue
        except zipfile.BadZipFile:  # a wrong password can pass the quick check and fail the checksum
            continue
        except NotImplementedError:  # AES encryption: Windows' tar can read it
            if _tar_member(path, info.filename, target, budget, info.file_size, password):
                return True
    return False


def _tar_member(archive, name, target, budget, declared, password):
    """Unpack one file with Windows' own tar.exe (libarchive); it reads AES-locked zips too."""
    if not WINDOWS_TAR.is_file():
        return False
    command = [str(WINDOWS_TAR), "-x", "-O", *(["--passphrase", password] if password else []),
               "-f", str(archive), name]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        written = _copy_limited(proc.stdout, target, budget, declared)
    except BaseException:
        proc.kill()
        raise
    finally:
        proc.stdout.close()
    return proc.wait(timeout=60) == 0 and (written > 0 or declared == 0)


def _7z_password(path, passwords):
    """None if the archive isn't locked, else the first password that opens it (or raise Locked)."""
    import py7zr
    try:
        with py7zr.SevenZipFile(path) as probe:
            if not probe.needs_password():
                return None
    except py7zr.exceptions.PasswordRequired:
        pass  # the file list itself is locked
    for password in passwords:
        try:
            with py7zr.SevenZipFile(path, password=password) as trial:
                if trial.testzip() is None:  # decrypts and checks every file's checksum, writes nothing
                    return password
        except Exception:  # wrong passwords show up as many different errors
            continue
    raise Locked("none of the passwords opens it")


def _7z(path, visit, budget, folder, passwords):
    import py7zr
    from py7zr.io import Py7zIO, WriterFactory

    password = _7z_password(path, passwords)
    try:
        archive = py7zr.SevenZipFile(path, password=password)
        infos = [i for i in archive.list() if not i.is_directory]
    except (py7zr.exceptions.PasswordRequired, py7zr.exceptions.Bad7zFile) as e:
        raise Locked(str(e))
    except Exception as e:
        if password:
            raise Locked(str(e))
        raise
    declared_total = sum(i.uncompressed or 0 for i in infos)
    packed_total = os.path.getsize(path)
    if declared_total > config.ARCHIVE_MAX_TOTAL:
        raise Bomb(f"it would unpack to more than {config.ARCHIVE_MAX_TOTAL // 1024 ** 2} MB")
    if declared_total > CHUNK and declared_total / max(packed_total, 1) > config.ARCHIVE_MAX_RATIO:
        raise Bomb(f"it is packed {declared_total // max(packed_total, 1)} times smaller than its real size, "
                   "like a zip bomb")
    sizes = {i.filename: i.uncompressed for i in infos}
    counter = iter(range(1, 10 ** 6))
    opened = []

    class Member(Py7zIO):
        def __init__(self, name):
            self.name = name
            self.path = folder / f"m{next(counter):04d}.blotter"
            self.file = open(self.path, "w+b")
            opened.append(self.file)
            self.written = 0
            budget.member(name, sizes.get(name), None)

        def write(self, s):
            self.written += len(s)
            budget.add(len(s))
            declared = sizes.get(self.name)
            if declared is not None and self.written > declared + CHUNK:
                raise Bomb("a file inside is bigger than the archive says")
            return self.file.write(s)

        def read(self, size=None):
            return self.file.read(size if size is not None else -1)

        def seek(self, offset, whence=0):
            return self.file.seek(offset, whence)

        def flush(self):
            self.file.flush()

        def size(self):
            return self.written

        def close(self):
            if not self.file.closed:
                self.file.close()
                visit(self.name, self.path)
                self.path.unlink(missing_ok=True)

    class Factory(WriterFactory):
        def create(self, filename):
            return Member(filename)

    try:
        archive.extract(factory=Factory())
    except Bomb:
        raise
    except Exception as e:
        if password:
            raise Locked(str(e))
        raise
    finally:
        for f in opened:
            f.close()  # a member cut short by an error is never visited
        archive.close()
    return {"locked": []}


def _rar(path, visit, budget, folder, passwords):
    import rarfile

    rarfile.BSDTAR_TOOL = str(WINDOWS_TAR)
    for tool in RAR_TOOLS:
        if tool.is_file():
            if tool.name.lower() == "unrar.exe":
                rarfile.UNRAR_TOOL = str(tool)
            else:
                rarfile.SEVENZIP_TOOL = str(tool)
    try:
        rarfile.tool_setup(force=True)
    except rarfile.RarCannotExec:
        raise Locked("no program that can unpack RAR files was found")
    locked = []
    archive, infos = None, []
    for password in [None, *passwords]:
        try:
            archive = rarfile.RarFile(str(path))
            if password and archive.needs_password():
                archive.setpassword(password)
            infos = [i for i in archive.infolist() if not i.is_dir()]
            break
        except (rarfile.PasswordRequired, rarfile.BadRarFile, rarfile.RarWrongPassword):
            archive = None  # the file list itself is locked: try the next password
    if archive is None:
        raise Locked("none of the passwords opens it")
    with archive:
        if sum(i.file_size for i in infos) > config.ARCHIVE_MAX_TOTAL:
            raise Bomb(f"it would unpack to more than {config.ARCHIVE_MAX_TOTAL // 1024 ** 2} MB")
        for n, info in enumerate(infos, 1):
            budget.member(info.filename, info.file_size, info.compress_size)
            target = folder / f"m{n:04d}.blotter"
            if not _rar_member(archive, info, target, budget, passwords):
                locked.append(info.filename)
                continue
            visit(info.filename, target)
            target.unlink(missing_ok=True)
    return {"locked": locked}


def _rar_member(archive, info, target, budget, passwords) -> bool:
    import rarfile
    for password in ([None] if not info.needs_password() else passwords):
        try:
            with archive.open(info, pwd=password) as source:
                _copy_limited(source, target, budget, info.file_size)
            return True
        except (rarfile.PasswordRequired, rarfile.RarWrongPassword, rarfile.RarCRCError, rarfile.BadRarFile):
            continue
        except rarfile.RarCannotExec:  # locked RARs need WinRAR or 7-Zip installed
            return False
    return False
