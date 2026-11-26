"""Versioned internal announcement embedded in an ordinary encrypted message."""

import base64
import json

PREFIX = "RELAY_ANNOUNCE_V1:"
PREFIX_V2 = "RELAY_ANNOUNCE_V2:"
CLIENT_VERSION = 2


def encode(announced_channel_id: str, note: str = "", version: int = CLIENT_VERSION) -> str:
    if not isinstance(announced_channel_id, str) or not announced_channel_id:
        raise ValueError("Invalid announced channel ID.")
    if not isinstance(note, str) or version not in (1, 2):
        raise ValueError("Invalid announcement note or version.")
    body = {"channel_id": announced_channel_id, "note": note[:500]}
    if version == 2:
        body["version"] = version
    payload = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    prefix = PREFIX if version == 1 else PREFIX_V2
    return prefix + base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def decode(content: str) -> dict | None:
    if not isinstance(content, str):
        return None
    if content.startswith(PREFIX_V2):
        prefix, version = PREFIX_V2, 2
    elif content.startswith(PREFIX):
        prefix, version = PREFIX, 1
    else:
        return None
    encoded = content[len(prefix):]
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    value = json.loads(raw.decode("utf-8"))
    expected = {"channel_id", "note"} if version == 1 else {"channel_id", "note", "version"}
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("Invalid announcement body.")
    if version == 2 and value["version"] != 2:
        raise ValueError("Invalid announcement version.")
    if encode(value["channel_id"], value["note"], version) != content:
        raise ValueError("Non-canonical announcement body.")
    return value
