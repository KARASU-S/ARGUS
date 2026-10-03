"""SQLite-кэш результатов разведки с TTL.

Исправления v0.3:
  • Путь к БД — абсолютный (рядом с пакетом), а не относительно CWD: старый
    кэш ломался при запуске из другой директории.
  • Соединения через контекстный менеджер (нет утечек fd при исключениях).
  • Метод clear() используется режимом --no-cache корректно, добавлен purge_expired.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

CACHE_DB = str(Path(__file__).resolve().parent.parent / "reports" / ".argus_cache.db")
CACHE_TTL_SECONDS = 86400  # 24 часа


class Cache:
    def __init__(self, db_path: str = CACHE_DB):
        self.db_path = db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    ts INTEGER NOT NULL,
                    data TEXT NOT NULL
                )
            """)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def get(self, key: str) -> list[dict] | None:
        try:
            with self._conn() as c:
                row = c.execute(
                    "SELECT ts, data FROM cache WHERE key = ?", (key,)
                ).fetchone()
                if not row:
                    return None
                if int(time.time()) - row["ts"] > CACHE_TTL_SECONDS:
                    c.execute("DELETE FROM cache WHERE key = ?", (key,))
                    return None
                return json.loads(row["data"])
        except (sqlite3.Error, json.JSONDecodeError):
            return None

    def set(self, key: str, findings: list[dict]) -> None:
        try:
            with self._conn() as c:
                c.execute(
                    "INSERT OR REPLACE INTO cache (key, ts, data) VALUES (?, ?, ?)",
                    (key, int(time.time()), json.dumps(findings, ensure_ascii=False)),
                )
        except sqlite3.Error:
            pass

    def purge_expired(self) -> int:
        try:
            with self._conn() as c:
                cur = c.execute(
                    "DELETE FROM cache WHERE ? - ts > ?",
                    (int(time.time()), CACHE_TTL_SECONDS),
                )
                return cur.rowcount
        except sqlite3.Error:
            return 0

    def clear(self) -> None:
        try:
            with self._conn() as c:
                c.execute("DELETE FROM cache")
        except sqlite3.Error:
            pass
