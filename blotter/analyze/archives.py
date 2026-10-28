"""Unpack zip, rar and 7z archives safely: one file at a time, into Blotter's own folder, with limits.

Limits (config.py) stop "zip bombs", archives built to unpack into something enormous:
total unpacked size, number of files, archives inside archives, and how tightly data is packed.
Unpacked files get neutral names (m0001.blotter); nothing is ever opened or run.
Locked archives are tried with the password the person typed in (if any), then "infected"
(what malware researchers use).
"""

import os
import shutil
import subprocess
import uuid
import zipfile
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
    with zipfile.ZipFile(path) as z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        declared_total = sum(i.file_size for i in infos)
        if declared_total > config.ARCHIVE_MAX_TOTAL:
            raise Bomb(f"it would unpack to more than {config.ARCHIVE_MAX_TOTAL // 1024 ** 2} MB")
        for n, info in enumerate(infos, 1):
            budget.member(info.filename, info.file_size, info.compress_size)
            target = folder / f"m{n:04d}.blotter"
            if not _zip_member(z, path, info, target, budget, passwords):
                locked.append(info.filename)
                continue
            visit(info.filename, target)
            target.unlink(missing_ok=True)
    return {"locked": locked}


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
