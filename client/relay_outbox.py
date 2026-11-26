"""Durable local ciphertext-only outbox for experimental Relay messages."""

import hashlib
from contextlib import closing
import os
from pathlib import Path
import sqlite3

if __package__:
    from .relay_identity import IdentityError
else:
    from relay_identity import IdentityError


def _state_path(origin: str, device_id: str) -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if not base:
            raise IdentityError("No está disponible el directorio local de Relay.")
        root = Path(base) / "Relay" / "outbox"
    else:
        root = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "relay" / "outbox"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    name = hashlib.sha256((origin + "\0" + device_id).encode("utf-8")).hexdigest()
    return root / (name + ".sqlite3")


class Outbox:
    def __init__(self, origin: str, device_id: str, path: Path | None = None):
        self.path = path or _state_path(origin, device_id)
        with closing(self._open()) as conn, conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pending (
                    operation_id TEXT PRIMARY KEY, channel_id TEXT NOT NULL,
                    nonce TEXT NOT NULL, ciphertext TEXT NOT NULL,
                    created_at INTEGER NOT NULL DEFAULT (unixepoch())
                )
            """)

    def _open(self):
        return sqlite3.connect(self.path, timeout=10)

    def add(self, payload: dict):
        with closing(self._open()) as conn, conn:
            conn.execute(
                "INSERT INTO pending (operation_id, channel_id, nonce, ciphertext) VALUES (?, ?, ?, ?)",
                (payload["operation_id"], payload["channel_id"], payload["nonce"], payload["ciphertext"]),
            )

    def pending(self, limit: int = 100) -> list[dict]:
        with closing(self._open()) as conn, conn:
            rows = conn.execute(
                "SELECT operation_id, channel_id, nonce, ciphertext FROM pending ORDER BY rowid LIMIT ?", (limit,),
            ).fetchall()
        return [dict(zip(("operation_id", "channel_id", "nonce", "ciphertext"), row)) for row in rows]

    def remove(self, operation_id: str):
        with closing(self._open()) as conn, conn:
            conn.execute("DELETE FROM pending WHERE operation_id=?", (operation_id,))
