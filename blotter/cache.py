"""SQLite cache of online lookups by SHA-256, so a rescan costs no API quota. Answers older than
config.ONLINE_MAX_AGE are asked again (the old row stays until the new answer replaces it)."""

import json
import sqlite3
import threading
import time
from pathlib import Path

from .findings import Finding


class Cache:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock, self._db:
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS results ("
                " sha256 TEXT NOT NULL, check_id TEXT NOT NULL,"
                " findings TEXT NOT NULL, checked_at REAL NOT NULL,"
                " PRIMARY KEY (sha256, check_id))"
            )

    def get(self, sha256: str, check_id: str, max_age=None):
        """Return (findings, checked_at), or None when there is none or it is older than max_age seconds."""
        with self._lock:
            row = self._db.execute(
                "SELECT findings, checked_at FROM results WHERE sha256 = ? AND check_id = ?",
                (sha256, check_id),
            ).fetchone()
        if not row or (max_age is not None and time.time() - row[1] > max_age):
            return None
        try:
            return [Finding.from_dict(d) for d in json.loads(row[0])], row[1]
        except (ValueError, KeyError, TypeError):
            return None  # unreadable row: treat as not cached

    def put(self, sha256: str, check_id: str, findings: list[Finding]) -> None:
        data = json.dumps([f.to_dict() for f in findings])
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO results VALUES (?, ?, ?, ?)",
                (sha256, check_id, data, time.time()),
            )

    def close(self) -> None:
        with self._lock:
            self._db.close()
