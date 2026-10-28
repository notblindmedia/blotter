"""Files you told Blotter to trust, by SHA-256. If the file changes by one byte, its hash changes and trust ends.

Kept in its own file (trusted.sqlite3), so deleting the cache doesn't forget them.
"""

import sqlite3
import threading
import time
from pathlib import Path


class TrustList:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock, self._db:
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS trusted ("
                " sha256 TEXT PRIMARY KEY, name TEXT NOT NULL, added_at REAL NOT NULL)"
            )

    def add(self, sha256: str, name: str) -> None:
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise ValueError("not a SHA-256")
        with self._lock, self._db:
            self._db.execute("INSERT OR REPLACE INTO trusted VALUES (?, ?, ?)", (sha256, name[:255], time.time()))

    def remove(self, sha256: str) -> None:
        with self._lock, self._db:
            self._db.execute("DELETE FROM trusted WHERE sha256 = ?", (sha256,))

    def get(self, sha256: str):
        """{'sha256', 'name', 'added_at'} or None."""
        with self._lock:
            row = self._db.execute("SELECT sha256, name, added_at FROM trusted WHERE sha256 = ?", (sha256,)).fetchone()
        return dict(zip(("sha256", "name", "added_at"), row)) if row else None

    def all(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT sha256, name, added_at FROM trusted ORDER BY added_at DESC").fetchall()
        return [dict(zip(("sha256", "name", "added_at"), r)) for r in rows]

    def close(self) -> None:
        with self._lock:
            self._db.close()
