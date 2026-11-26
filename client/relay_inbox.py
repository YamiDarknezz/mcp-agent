"""Atomic local inbox and replay cursor; stores only ciphertext and metadata."""

from contextlib import closing
import sqlite3

if __package__:
    from .relay_outbox import _state_path
else:
    from relay_outbox import _state_path


class Inbox:
    def __init__(self, origin, device_id, path=None):
        self.path = path or _state_path(origin, device_id)
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS inbox (
                    channel_id TEXT NOT NULL, seq INTEGER NOT NULL, operation_id TEXT NOT NULL,
                    device_id TEXT NOT NULL, nonce TEXT NOT NULL, ciphertext TEXT NOT NULL,
                    created_at TEXT NOT NULL, PRIMARY KEY (channel_id, seq)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS inbox_cursors (
                    channel_id TEXT PRIMARY KEY, seq INTEGER NOT NULL
                )
            """)

    def cursor(self, channel_id):
        with closing(sqlite3.connect(self.path)) as conn:
            row = conn.execute("SELECT seq FROM inbox_cursors WHERE channel_id=?", (channel_id,)).fetchone()
        return row[0] if row else 0

    def append(self, channel_id, expected, rows):
        with closing(sqlite3.connect(self.path, timeout=10)) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT seq FROM inbox_cursors WHERE channel_id=?", (channel_id,)).fetchone()
            if (existing[0] if existing else 0) != expected:
                return False
            for row in rows:
                if row["seq"] != expected + 1:
                    raise ValueError("Non-contiguous message sequence.")
                expected = row["seq"]
                conn.execute(
                    "INSERT INTO inbox VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (channel_id, expected, row["operation_id"], row["device_id"], row["nonce"],
                     row["ciphertext"], row["created_at"]),
                )
            conn.execute("""
                INSERT INTO inbox_cursors VALUES (?, ?)
                ON CONFLICT(channel_id) DO UPDATE SET seq=excluded.seq
            """, (channel_id, expected))
            return True

    def page(self, channel_id, after=0, limit=10):
        with closing(sqlite3.connect(self.path)) as conn:
            rows = conn.execute("""
                SELECT seq, operation_id, device_id, nonce, ciphertext, created_at FROM inbox
                WHERE channel_id=? AND seq>? ORDER BY seq LIMIT ?
            """, (channel_id, after, limit)).fetchall()
        return [dict(zip(("seq", "operation_id", "device_id", "nonce", "ciphertext", "created_at"), row))
                for row in rows]
