"""Versioned encrypted message body, with optional account-ID mentions."""

import json
from uuid import UUID

PREFIX = b"relay-message-v1\0"
MAX_MENTIONS = 32


def encode(content: str, mentions: list[str] | None = None) -> bytes:
    if not isinstance(content, str) or not content:
        raise ValueError("Message content is empty.")
    if mentions is None:
        mentions = []
    if not isinstance(mentions, list) or len(mentions) > MAX_MENTIONS:
        raise ValueError("Invalid mention list.")
    normalized = []
    for value in mentions:
        if not isinstance(value, str):
            raise ValueError("Invalid mention ID.")
        parsed = UUID(value)
        if parsed.version != 4 or str(parsed) != value:
            raise ValueError("Invalid mention ID.")
        if value not in normalized:
            normalized.append(value)
    raw = PREFIX + json.dumps(
        {"content": content, "mentions": normalized}, ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    if len(raw) > 4096:
        raise ValueError("Message exceeds 4096 encoded bytes.")
    return raw


def decode(raw: bytes) -> tuple[str, list[str]]:
    if not raw.startswith(PREFIX):
        return raw.decode("utf-8"), []
    value = json.loads(raw[len(PREFIX):].decode("utf-8"))
    if not isinstance(value, dict) or set(value) != {"content", "mentions"}:
        raise ValueError("Invalid message body.")
    canonical = encode(value["content"], value["mentions"])
    if len(canonical) > 4096:
        raise ValueError("Invalid message body.")
    return value["content"], value["mentions"]
