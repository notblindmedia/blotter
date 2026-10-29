"""Deleting Blotter's own work folders, and nothing else.

safe_remove(path) only deletes inside Blotter's incoming folder (where copies and unpacked files live) or the
sandbox work folder of the worker it runs in. It resolves the real path first and refuses anything else. It
never follows a symbolic link or junction: it removes the link itself and leaves whatever it points to alone.
"""

import os
import stat
from pathlib import Path

from . import config


def allowed_roots() -> list[Path]:
    roots = [config.INCOMING]
    if os.environ.get("BLOTTER_WORK"):  # inside a sandboxed worker: its own work folder
        roots.append(Path(os.environ["BLOTTER_WORK"]))
    return [Path(os.path.realpath(r)) for r in roots]


def _is_link(path) -> bool:
    """A symbolic link or an NTFS junction (also a reparse point)."""
    p = Path(path)
    return p.is_symlink() or p.is_junction()


def _inside(path: Path, roots) -> bool:
    """Strictly inside one of the roots (a root itself can't be removed)."""
    return any(path != root and path.is_relative_to(root) for root in roots)


def safe_remove(path) -> bool:
    """Delete a file or folder inside Blotter's own folders. False (and nothing touched) when it refuses."""
    path = Path(path)
    roots = allowed_roots()
    if not os.path.lexists(path):
        return True
    # Where the entry itself lives: its parent's real location plus its own name (a link isn't followed).
    real = Path(os.path.realpath(path.parent)) / path.name
    if not _inside(real, roots):
        return False
    if not _is_link(real) and not _inside(Path(os.path.realpath(real)), roots):
        return False
    _remove(real)
    return True


def _remove(path: Path) -> None:
    if _is_link(path):
        _unlink_link(path)
    elif path.is_dir():
        with os.scandir(path) as entries:
            for entry in list(entries):
                _remove(Path(entry.path))
        _retry(os.rmdir, path)
    else:
        _retry(os.unlink, path)


def _unlink_link(path: Path) -> None:
    """Remove the link, never what it points to (a folder link or junction goes with rmdir, a file link with unlink)."""
    try:
        os.rmdir(path)
    except OSError:
        try:
            os.unlink(path)
        except OSError:
            pass  # left for start-up cleanup


def _retry(remove, path: Path) -> None:
    """Remove, clearing a read-only flag once if Windows refuses. Errors after that are left to start-up cleanup."""
    try:
        remove(path)
    except PermissionError:
        try:
            os.chmod(path, stat.S_IWRITE)
            remove(path)
        except OSError:
            pass
    except OSError:
        pass
