"""Move a checked file out of the way, into %LOCALAPPDATA%\\Blotter\\quarantine, with a .blotted extension.

Only for files Blotter knows the real location of (chosen with "Choose a file on this PC"),
never for drag-and-drop uploads, which are only copies. Nothing is deleted: restore puts it back.
"""

import json
import os
import re
import shutil
import threading
import time
import uuid
from pathlib import Path

from . import config, hashing

EXTENSION = ".blotted"
_lock = threading.Lock()


class QuarantineError(Exception):
    pass


def _index_path() -> Path:
    return config.QUARANTINE / "index.json"


def _load() -> list[dict]:
    try:
        return json.loads(_index_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


def _save(entries) -> None:
    config.QUARANTINE.mkdir(parents=True, exist_ok=True)
    tmp = _index_path().with_suffix(".tmp")
    tmp.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    os.replace(tmp, _index_path())


def entries() -> list[dict]:
    with _lock:
        return [e for e in _load() if Path(e["stored"]).exists()]


def _move(source: Path, target: Path, sha256: str) -> None:
    try:
        os.replace(source, target)  # same drive: instant and atomic
        return
    except OSError:
        pass
    part = target.with_suffix(target.suffix + ".part")
    shutil.copyfile(source, part)
    if hashing.sha256_stream(open(part, "rb")) != sha256:
        part.unlink(missing_ok=True)
        raise QuarantineError("The copy in quarantine didn't match the original, so nothing was moved.")
    os.replace(part, target)
    source.unlink()


def put(path, sha256: str) -> dict:
    """Move the file at `path` into quarantine, but only if it is still the file that was checked."""
    source = Path(path)
    if not source.is_file():
        raise QuarantineError("The file isn't there any more (moved, deleted or already quarantined).")
    try:
        current = hashing.sha256_stream(open(source, "rb"))
    except OSError as e:
        raise QuarantineError(f"Blotter couldn't read the file ({e.strerror or e}).")
    if current != sha256:
        raise QuarantineError("The file has changed since it was checked. Check it again first.")
    config.QUARANTINE.mkdir(parents=True, exist_ok=True)
    entry_id = uuid.uuid4().hex[:12]
    tidy = re.sub(r"[^\w.\- ]", "_", source.name)[:120]
    target = config.QUARANTINE / f"{entry_id}-{tidy}{EXTENSION}"
    try:
        _move(source, target, sha256)
    except OSError as e:
        raise QuarantineError(f"Blotter couldn't move the file ({e.strerror or e}). Is it open in another program?")
    entry = {"id": entry_id, "name": source.name, "original": str(source), "stored": str(target),
             "sha256": sha256, "at": time.time()}
    with _lock:
        _save([*_load(), entry])
    return entry


def restore(entry_id: str) -> dict:
    with _lock:
        all_entries = _load()
        entry = next((e for e in all_entries if e["id"] == entry_id), None)
        if not entry or not Path(entry["stored"]).exists():
            raise QuarantineError("That file isn't in quarantine.")
        original = Path(entry["original"])
        if original.exists():
            raise QuarantineError(f"Something else is already at {original}, so the file wasn't put back.")
        original.parent.mkdir(parents=True, exist_ok=True)
        try:
            _move(Path(entry["stored"]), original, entry["sha256"])
        except OSError as e:
            raise QuarantineError(f"Blotter couldn't move the file back ({e.strerror or e}).")
        _save([e for e in all_entries if e["id"] != entry_id])
        return entry
