"""Human-only invitation issue/redeem. No code ever enters an MCP tool."""

import re

if __package__:
    from .relay_identity import DeviceVault, IdentityError, _b64, request_json
else:
    from relay_identity import DeviceVault, IdentityError, _b64, request_json

CODE_PATTERN = re.compile(r"^relay_inv_[A-Za-z0-9_-]{43}$")
ROLES = {"reader", "collaborator", "admin"}


def _proof(origin, path, payload):
    key = DeviceVault(origin).load()
    if key is None:
        raise IdentityError("Esta laptop no está registrada en Relay.")
    body = {**payload, "device_id": key.device_id, "proof": key.proof(origin, "workspace")}
    return request_json(origin, path, body, max_bytes=8192)


def issue(origin, channel_id, role="reader", expires_in=None):
    """Issue a one-time invite. The returned code must only reach a human console."""
    if role not in ROLES:
        raise IdentityError("Rol inválido; usa reader, collaborator o admin.")
    payload = {"channel_id": channel_id, "role": role}
    if expires_in is not None:
        if isinstance(expires_in, bool) or not isinstance(expires_in, int) or not 60 <= expires_in <= 3600:
            raise IdentityError("La vigencia debe estar entre 60 y 3600 segundos.")
        payload["expires_in"] = expires_in
    result = _proof(origin, "/v1/invites/issue", payload)
    code = result.get("code")
    if not isinstance(code, str) or not CODE_PATTERN.fullmatch(code):
        raise IdentityError("Relay devolvió un código de invitación inválido.")
    return result


def status(origin, channel_id):
    """Read-only status for the model: counts and expiry, never a code."""
    result = _proof(origin, "/v1/invites/status", {"channel_id": channel_id})
    if type(result.get("active")) is not int or "code" in result:
        raise IdentityError("Relay devolvió un estado de invitación inválido.")
    return result


def redeem(origin, code, display_name, device_label, declared_email=None):
    """Redeem an invite from a hidden prompt. The code is never echoed or logged.

    The invited account and device are created by the server from the signed
    claims; the code alone never grants a privileged role.
    """
    if not isinstance(code, str) or not CODE_PATTERN.fullmatch(code):
        raise IdentityError("El código de invitación no tiene el formato esperado.")
    for value, name in ((display_name, "display_name"), (device_label, "device_label")):
        if not isinstance(value, str) or not 1 <= len(value.strip()) <= 100:
            raise IdentityError(f"{name} debe tener entre 1 y 100 caracteres.")
    key = DeviceVault(origin).load()
    if key is None:
        raise IdentityError("No hay una identidad local para canjear; usa activate primero.")
    claims = {"display_name": display_name.strip(), "device_label": device_label.strip()}
    if declared_email is not None:
        if not isinstance(declared_email, str) or not 1 <= len(declared_email) <= 254:
            raise IdentityError("declared_email no es válido.")
        claims["declared_email"] = declared_email.strip()
    result = request_json(origin, "/v1/invites/redeem", {
        "code": code,
        "device_id": key.device_id,
        "public_key": _b64(key.private.public_key().public_bytes_raw()),
        "proof": key.proof(origin, "invite_redeem", **claims),
    }, max_bytes=8192)
    if not isinstance(result.get("channel_id"), str) or result.get("role") not in ROLES:
        raise IdentityError("Relay no confirmó la membresía tras el canje.")
    return result
