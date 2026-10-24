"""SQLite persistence. This layer only ever sees ciphertext."""
from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS header (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    version         INTEGER NOT NULL,
    salt            BLOB    NOT NULL,
    time_cost       INTEGER NOT NULL,
    memory_cost_kib INTEGER NOT NULL,
    parallelism     INTEGER NOT NULL,
    wrapped_key     BLOB    NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
    id         TEXT PRIMARY KEY,
    blob       BLOB NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


@dataclass
class Header:
    version: int
    salt: bytes
    time_cost: int
    memory_cost_kib: int
    parallelism: int
    wrapped_key: bytes


class Storage:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.conn: sqlite3.Connection | None = None

    def open(self, create: bool = False) -> None:
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        elif not self.path.exists():
            raise FileNotFoundError(self.path)
        self.conn = sqlite3.connect(self.path)
        self.conn.executescript(SCHEMA)
        try:  # owner-only permissions (no-op on some Windows setups)
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None

    # --- header -----------------------------------------------------------
    def read_header(self) -> Header | None:
        row = self.conn.execute(
            "SELECT version, salt, time_cost, memory_cost_kib, parallelism, "
            "wrapped_key FROM header WHERE id = 1").fetchone()
        return Header(*row) if row else None

    def write_header(self, h: Header) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO header VALUES (1, ?, ?, ?, ?, ?, ?)",
                (h.version, h.salt, h.time_cost, h.memory_cost_kib,
                 h.parallelism, h.wrapped_key))

    # --- entries ----------------------------------------------------------
    def insert_entry(self, entry_id: str, blob: bytes, now: str) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT INTO entries VALUES (?, ?, ?, ?)",
                (entry_id, blob, now, now))

    def update_entry(self, entry_id: str, blob: bytes, now: str) -> bool:
        with self.conn:
            cur = self.conn.execute(
                "UPDATE entries SET blob = ?, updated_at = ? WHERE id = ?",
                (blob, now, entry_id))
        return cur.rowcount > 0

    def delete_entry(self, entry_id: str) -> bool:
        with self.conn:
            cur = self.conn.execute(
                "DELETE FROM entries WHERE id = ?", (entry_id,))
        return cur.rowcount > 0

    def get_entry(self, entry_id: str):
        return self.conn.execute(
            "SELECT id, blob, created_at, updated_at FROM entries WHERE id = ?",
            (entry_id,)).fetchone()

    def all_entries(self):
        return self.conn.execute(
            "SELECT id, blob, created_at, updated_at FROM entries "
            "ORDER BY created_at").fetchall()
