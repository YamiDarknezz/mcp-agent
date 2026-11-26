"""Experimental encrypted message transport with explicit paginated reads."""

from uuid import UUID, uuid4

if __package__:
    from . import relay_keys
    from .relay_identity import DeviceVault, IdentityError
    from .relay_outbox import Outbox
    from .relay_inbox import Inbox
    from .relay_workspace import _call
else:
    import relay_keys
    from relay_identity import DeviceVault, IdentityError
    from relay_outbox import Outbox
    from relay_inbox import Inbox
    from relay_workspace import _call


def _aad_sequence(operation_id: str) -> int:
    return UUID(operation_id).int & ((1 << 64) - 1)


def send(origin: str, channel_id: str, content: str) -> dict:
    raw = content.encode("utf-8")
    if not 1 <= len(raw) <= 4096:
        raise IdentityError("El mensaje debe tener entre 1 y 4096 bytes UTF-8.")
    device = DeviceVault(origin).load()
    if device is None:
        raise IdentityError("Esta laptop no está registrada en Relay.")
    operation_id = str(uuid4())
    encrypted = relay_keys.encrypt(origin, channel_id, _aad_sequence(operation_id), raw)
    payload = {"channel_id": channel_id, "operation_id": operation_id, **encrypted}
    outbox = Outbox(origin, device.device_id)
    outbox.add(payload)
    try:
        result = _call(origin, "/v1/workspace/send-message", payload)
    except IdentityError as error:
        return {"operation_id": operation_id, "status": "pending", "error": str(error)}
    if result.get("operation_id") != operation_id or not isinstance(result.get("seq"), int):
        return {"operation_id": operation_id, "status": "pending", "error": "Respuesta de Relay inválida."}
    outbox.remove(operation_id)
    return {**result, "status": "sent"}


def retry_pending(origin: str, limit: int = 100) -> dict:
    device = DeviceVault(origin).load()
    if device is None:
        raise IdentityError("Esta laptop no está registrada en Relay.")
    outbox = Outbox(origin, device.device_id)
    sent = []
    for payload in outbox.pending(limit):
        try:
            result = _call(origin, "/v1/workspace/send-message", payload)
        except IdentityError as error:
            return {"sent": sent, "pending": True, "error": str(error)}
        if result.get("operation_id") != payload["operation_id"] or not isinstance(result.get("seq"), int):
            return {"sent": sent, "pending": True, "error": "Respuesta de Relay inválida."}
        outbox.remove(payload["operation_id"])
        sent.append(result)
    return {"sent": sent, "pending": bool(outbox.pending(1))}


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


def read_inbox(origin: str, channel_id: str, after: int = 0, limit: int = 10) -> dict:
    device = DeviceVault(origin).load()
    if device is None:
        raise IdentityError("Esta laptop no está registrada en Relay.")
    inbox = Inbox(origin, device.device_id)
    items = inbox.page(channel_id, after, limit)
    for item in items:
        try:
            item["content"] = relay_keys.decrypt(
                origin, channel_id, _aad_sequence(item["operation_id"]),
                item.pop("nonce"), item.pop("ciphertext"),
            ).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            raise IdentityError("No se pudo descifrar un mensaje del buzón.") from None
    return {"messages": items, "cursor": inbox.cursor(channel_id)}
