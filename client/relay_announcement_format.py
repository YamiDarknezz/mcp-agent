"""Versioned internal announcement embedded in an ordinary encrypted message."""

import base64
import json

PREFIX = "RELAY_ANNOUNCE_V1:"


def encode(announced_channel_id: str, note: str = "") -> str:
    if not isinstance(announced_channel_id, str) or not announced_channel_id:
        raise ValueError("Invalid announced channel ID.")
    if not isinstance(note, str):
        raise ValueError("Invalid announcement note.")
    payload = json.dumps(
        {"channel_id": announced_channel_id, "note": note[:500]},
        ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    return PREFIX + base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def decode(content: str) -> dict | None:
    if not isinstance(content, str) or not content.startswith(PREFIX):
        return None
    raw = base64.urlsafe_b64decode(content[len(PREFIX):] + "=" * (-len(content[len(PREFIX):]) % 4))
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict) or set(value) != {"channel_id", "note"}:
        raise ValueError("Invalid announcement body.")
    if encode(value["channel_id"], value["note"]) != content:
        raise ValueError("Non-canonical announcement body.")
    return value
