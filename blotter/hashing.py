"""SHA-256 of a file, read as bytes only.

The runner hashes the upload while saving it and calls remember(), so checks that only
need the hash still get it if Defender has already removed the file from disk.
"""

import hashlib
import threading

CHUNK = 1024 * 1024

_known: dict[str, str] = {}
_lock = threading.Lock()


def remember(path, sha256: str) -> None:
    with _lock:
        _known[str(path)] = sha256


def forget(path) -> None:
    with _lock:
        _known.pop(str(path), None)


def sha256_file(path) -> str:
    with _lock:
        known = _known.get(str(path))
    if known:
        return known
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()
