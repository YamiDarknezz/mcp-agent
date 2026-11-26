"""Experimental encrypted message transport with explicit paginated reads."""

from uuid import UUID, uuid4

if __package__:
    from . import relay_keys
    from .relay_identity import IdentityError
    from .relay_workspace import _call
else:
    import relay_keys
    from relay_identity import IdentityError
    from relay_workspace import _call


def _aad_sequence(operation_id: str) -> int:
    return UUID(operation_id).int & ((1 << 64) - 1)


def send(origin: str, channel_id: str, content: str) -> dict:
    raw = content.encode("utf-8")
    if not 1 <= len(raw) <= 4096:
        raise IdentityError("El mensaje debe tener entre 1 y 4096 bytes UTF-8.")
    operation_id = str(uuid4())
    payload = relay_keys.encrypt(origin, channel_id, _aad_sequence(operation_id), raw)
    return _call(origin, "/v1/workspace/send-message", {
        "channel_id": channel_id, "operation_id": operation_id, **payload,
    })


def read(origin: str, channel_id: str, after: int = 0, limit: int = 10) -> dict:
    result = _call(origin, "/v1/workspace/read-messages", {
        "channel_id": channel_id, "after": after, "limit": limit,
    })
    for item in result["messages"]:
        try:
            item["content"] = relay_keys.decrypt(
                origin, channel_id, _aad_sequence(item["operation_id"]),
                item.pop("nonce"), item.pop("ciphertext"),
            ).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            raise IdentityError("No se pudo descifrar un mensaje del canal.") from None
    return result
