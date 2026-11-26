"""Versioned internal announcement embedded in an ordinary encrypted message.

V1 carries only the channel and a note. V2 adds the announcing client version so
other laptops can warn when an endpoint is running an older client. V1 remains
readable forever.
"""

import base64
import json

if __package__:
    from .relay_version import CLIENT_VERSION
else:
    from relay_version import CLIENT_VERSION

V1_PREFIX = "RELAY_ANNOUNCE_V1:"
V2_PREFIX = "RELAY_ANNOUNCE_V2:"
PREFIX = V1_PREFIX  # backwards-compatible alias


def _encode(prefix: str, payload: dict) -> str:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return prefix + base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_body(content: str, prefix: str) -> dict:
    raw = base64.urlsafe_b64decode(content[len(prefix):] + "=" * (-len(content[len(prefix):]) % 4))
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Invalid announcement body.")
    return value


def encode(announced_channel_id: str, note: str = "") -> str:
    if not isinstance(announced_channel_id, str) or not announced_channel_id:
        raise ValueError("Invalid announced channel ID.")
    if not isinstance(note, str):
        raise ValueError("Invalid announcement note.")
    return _encode(V1_PREFIX, {"channel_id": announced_channel_id, "note": note[:500]})


def encode_with_version(
    announced_channel_id: str, note: str = "", client_version: str = CLIENT_VERSION
) -> str:
    if not isinstance(announced_channel_id, str) or not announced_channel_id:
        raise ValueError("Invalid announced channel ID.")
    if not isinstance(note, str) or not isinstance(client_version, str):
        raise ValueError("Invalid announcement note or version.")
    return _encode(V2_PREFIX, {
        "channel_id": announced_channel_id,
        "note": note[:500],
        "client_version": client_version,
    })


def decode(content: str) -> dict | None:
    if not isinstance(content, str):
        return None
    if content.startswith(V2_PREFIX):
        value = _decode_body(content, V2_PREFIX)
        if set(value) != {"channel_id", "note", "client_version"}:
            raise ValueError("Invalid announcement body.")
        if encode_with_version(value["channel_id"], value["note"], value["client_version"]) != content:
            raise ValueError("Non-canonical announcement body.")
        return value
    if content.startswith(V1_PREFIX):
        value = _decode_body(content, V1_PREFIX)
        if set(value) != {"channel_id", "note"}:
            raise ValueError("Invalid announcement body.")
        if encode(value["channel_id"], value["note"]) != content:
            raise ValueError("Non-canonical announcement body.")
        return value
    return None
