"""Encrypted task transport. The MCP coordinates tasks; it never executes them."""

from uuid import uuid4

if __package__:
    from . import relay_crypto as crypto, relay_keys, relay_task_format as task_format
    from .relay_identity import DeviceVault, IdentityError
    from .relay_workspace import _call
else:
    import relay_crypto as crypto
    import relay_keys
    import relay_task_format as task_format
    from relay_identity import DeviceVault, IdentityError
    from relay_workspace import _call


def propose(
    origin: str, channel_id: str, summary: str, objective: str = "", links: list[str] | None = None
) -> dict:
    try:
        raw = task_format.encode(summary, objective, links)
    except (ValueError, TypeError, UnicodeEncodeError):
        raise IdentityError("Datos de tarea inválidos; máximo 4096 bytes codificados.") from None
    device = DeviceVault(origin).load()
    if device is None:
        raise IdentityError("Esta laptop no está registrada en Relay.")
    task_id, operation_id = str(uuid4()), str(uuid4())
    nonce, ciphertext = _encrypt(origin, channel_id, task_id, raw)
    result = _call(origin, "/v1/tasks/propose", {
        "channel_id": channel_id, "task_id": task_id, "operation_id": operation_id,
        "nonce": nonce, "ciphertext": ciphertext,
    })
    return {**result, "task_id": task_id}


def _encrypt(origin, channel_id, task_id, raw):
    key = relay_keys.ChannelKeyStore(origin).load(channel_id)
    if key is None:
        raise IdentityError("Esta laptop no tiene la clave de este canal.")
    return crypto.encrypt_task(key, channel_id, task_id, raw)


def list_tasks(origin: str, channel_id: str, status: str | None = None, limit: int = 30) -> dict:
    result = _call(origin, "/v1/tasks/list", {
        "channel_id": channel_id, "status": status, "limit": limit,
    })
    for item in result["tasks"]:
        key = relay_keys.ChannelKeyStore(origin).load(channel_id)
        if key is None:
            raise IdentityError("Esta laptop no tiene la clave de este canal.")
        try:
            raw = crypto.decrypt_task(
                key, channel_id, item["task_id"], item.pop("nonce"), item.pop("ciphertext"),
            )
        except ValueError:
            raise IdentityError("No se pudo descifrar una tarea del canal.") from None
        item["summary"], item["objective"], item["links"] = task_format.decode(raw)
    return result


def claim(origin: str, channel_id: str, task_id: str) -> dict:
    return _call(origin, "/v1/tasks/claim", {"channel_id": channel_id, "task_id": task_id})


def release(origin: str, channel_id: str, task_id: str) -> dict:
    return _call(origin, "/v1/tasks/release", {"channel_id": channel_id, "task_id": task_id})


def complete(origin: str, channel_id: str, task_id: str, generation: int) -> dict:
    return _call(origin, "/v1/tasks/complete", {
        "channel_id": channel_id, "task_id": task_id, "generation": generation,
    })
