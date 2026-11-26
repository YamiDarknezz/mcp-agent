"""Experimental encrypted message transport with explicit paginated reads."""

from uuid import UUID, uuid4

if __package__:
    from . import relay_keys, relay_message_format
    from .relay_identity import DeviceVault, IdentityError, identify
    from .relay_outbox import Outbox
    from .relay_inbox import Inbox
    from .relay_workspace import _call, list_subscriptions
else:
    import relay_keys
    import relay_message_format
    from relay_identity import DeviceVault, IdentityError, identify
    from relay_outbox import Outbox
    from relay_inbox import Inbox
    from relay_workspace import _call, list_subscriptions


def _aad_sequence(operation_id: str) -> int:
    return UUID(operation_id).int & ((1 << 64) - 1)


def send(origin: str, channel_id: str, content: str, mentions: list[str] | None = None) -> dict:
    try:
        raw = relay_message_format.encode(content, mentions)
    except (ValueError, TypeError, UnicodeEncodeError):
        raise IdentityError("Mensaje o lista de menciones inválidos; máximo 4096 bytes codificados.") from None
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
            raw = relay_keys.decrypt(
                origin, channel_id, _aad_sequence(item["operation_id"]),
                item.pop("nonce"), item.pop("ciphertext"),
            )
            item["content"], item["mentions"] = relay_message_format.decode(raw)
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
            raw = relay_keys.decrypt(
                origin, channel_id, _aad_sequence(item["operation_id"]),
                item.pop("nonce"), item.pop("ciphertext"),
            )
            item["content"], item["mentions"] = relay_message_format.decode(raw)
        except (ValueError, UnicodeDecodeError):
            raise IdentityError("No se pudo descifrar un mensaje del buzón.") from None
    return {"messages": items, "cursor": inbox.cursor(channel_id)}


def alerts(origin: str, channel_id: str, after: int = 0, limit: int = 10) -> dict:
    """Inspect one local page using the current subscription preference."""
    device = DeviceVault(origin).load()
    if device is None:
        raise IdentityError("Esta laptop no está registrada en Relay.")
    account_id = identify(origin, device).get("account_id")
    try:
        parsed = UUID(account_id)
        if parsed.version != 4 or str(parsed) != account_id:
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise IdentityError("Relay devolvió una identidad de cuenta inválida.") from None
    cursor = None
    mode = None
    while True:
        page = list_subscriptions(origin, 100, cursor)
        mode = next((item["mode"] for item in page["items"] if item["channel_id"] == channel_id), None)
        next_cursor = page["next_cursor"]
        if mode or not next_cursor:
            break
        if next_cursor == cursor:
            raise IdentityError("La paginación de suscripciones no avanzó.")
        cursor = next_cursor
    if mode not in {"all", "mentions", "muted"}:
        return {"mode": "unfollowed", "alerts": [], "next_after": after}
    inbox = Inbox(origin, device.device_id)
    rows = inbox.page(channel_id, after, limit)
    notices = []
    for row in rows:
        if mode == "muted" or row["device_id"] == device.device_id:
            continue
        try:
            raw = relay_keys.decrypt(origin, channel_id, _aad_sequence(row["operation_id"]),
                                     row["nonce"], row["ciphertext"])
            _, mentions = relay_message_format.decode(raw)
        except (ValueError, UnicodeDecodeError):
            raise IdentityError("No se pudo descifrar un mensaje del buzón.") from None
        if mode == "all" or account_id in mentions:
            notices.append({
                "channel_id": channel_id, "seq": row["seq"], "device_id": row["device_id"],
                "operation_id": row["operation_id"], "reason": "mention" if account_id in mentions else "message",
            })
    return {"mode": mode, "alerts": notices, "next_after": rows[-1]["seq"] if rows else after}
