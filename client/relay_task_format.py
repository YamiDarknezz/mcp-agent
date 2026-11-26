"""Versioned encrypted task body: summary, objective and optional links."""

import json

PREFIX = b"relay-task-v1\0"


def encode(summary: str, objective: str = "", links: list[str] | None = None) -> bytes:
    if not isinstance(summary, str) or not summary or not isinstance(objective, str):
        raise ValueError("Invalid task text.")
    if links is None:
        links = []
    if not isinstance(links, list) or not all(isinstance(value, str) for value in links):
        raise ValueError("Invalid task links.")
    raw = PREFIX + json.dumps(
        {"summary": summary, "objective": objective, "links": links},
        ensure_ascii=False, separators=(",", ":"),
    ).encode("utf-8")
    if len(raw) > 4096:
        raise ValueError("Task body exceeds 4096 encoded bytes.")
    return raw


def decode(raw: bytes) -> tuple[str, str, list[str]]:
    if not raw.startswith(PREFIX):
        raise ValueError("Unsupported task body.")
    value = json.loads(raw[len(PREFIX):].decode("utf-8"))
    if not isinstance(value, dict) or set(value) != {"summary", "objective", "links"}:
        raise ValueError("Invalid task body.")
    if encode(value["summary"], value["objective"], value["links"]) != raw:
        raise ValueError("Non-canonical task body.")
    return value["summary"], value["objective"], value["links"]
