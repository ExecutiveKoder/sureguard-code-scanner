"""SQLite-backed TTL cache for advisory feeds.

We aggressively cache OSV / KEV / EPSS / registry lookups because:
  1. Generation-time calls need to be sub-second.
  2. The feeds rate-limit (especially OSV batched queries past ~1000/min).
  3. Determinism: the same input within a TTL window must yield the same finding set.

The cache key includes the rule pack version so bumping rules invalidates everything.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from . import __version__

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "sureguard"


class Cache:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (DEFAULT_CACHE_DIR / "cache.sqlite")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS entries (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                expires_at REAL NOT NULL
            )
            """
        )
        self._conn.commit()

    def _full_key(self, namespace: str, key: str) -> str:
        return f"{__version__}:{namespace}:{key}"

    def get(self, namespace: str, key: str) -> Any | None:
        row = self._conn.execute(
            "SELECT value, expires_at FROM entries WHERE key = ?",
            (self._full_key(namespace, key),),
        ).fetchone()
        if not row:
            return None
        value_json, expires_at = row
        if expires_at < time.time():
            return None
        return json.loads(value_json)

    def set(self, namespace: str, key: str, value: Any, ttl_seconds: int) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO entries(key, value, expires_at) VALUES (?, ?, ?)",
            (
                self._full_key(namespace, key),
                json.dumps(value, default=str),
                time.time() + ttl_seconds,
            ),
        )
        self._conn.commit()

    def purge_expired(self) -> int:
        cur = self._conn.execute(
            "DELETE FROM entries WHERE expires_at < ?", (time.time(),)
        )
        self._conn.commit()
        return cur.rowcount


_default: Cache | None = None


def default_cache() -> Cache:
    global _default
    if _default is None:
        _default = Cache()
    return _default
