"""SHA-256 of a file, read as bytes only, and the file's original name.

The runner hashes the upload while saving it and calls remember(), so checks that only
need the hash still get it if Defender has already removed the file from disk. Blotter's
copy has a neutral name (<random>.blotter); checks that care about the real name
(the disguise check) ask original_name().
"""

import hashlib
import threading

CHUNK = 1024 * 1024

_known: dict[str, tuple[str, str | None]] = {}
_passwords: dict[str, str] = {}  # an archive password the person typed in; kept in memory only
_lock = threading.Lock()


def remember(path, sha256: str, name: str | None = None, password: str | None = None) -> None:
    with _lock:
        _known[str(path)] = (sha256, name)
        if password:
            _passwords[str(path)] = password
        else:
            _passwords.pop(str(path), None)


def forget(path) -> None:
    with _lock:
        _known.pop(str(path), None)
        _passwords.pop(str(path), None)


def password(path) -> str | None:
    with _lock:
        return _passwords.get(str(path))


def original_name(path) -> str | None:
    with _lock:
        return (_known.get(str(path)) or (None, None))[1]


def sha256_file(path) -> str:
    with _lock:
        known = (_known.get(str(path)) or (None, None))[0]
    if known:
        return known
    return sha256_stream(open(path, "rb"))


def sha256_stream(stream) -> str:
    digest = hashlib.sha256()
    with stream:
        while chunk := stream.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()
