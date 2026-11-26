"""Human-only invitation issue/redeem. No code ever enters an MCP tool."""

import re

if __package__:
    from . import relay_crypto as crypto
    from .relay_identity import DeviceVault, IdentityError, request_json
else:
    import relay_crypto as crypto
    from relay_identity import DeviceVault, IdentityError, request_json

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


def redeem(origin, code, name, label, email=None):
    """Redeem an invite for a NEW device/account. The code is never echoed or logged."""
    if not isinstance(code, str) or not CODE_PATTERN.fullmatch(code):
        raise IdentityError("El código de invitación no tiene el formato esperado.")
    for field, value in (("nombre", name), ("etiqueta", label)):
        if not isinstance(value, str) or not value.strip():
            raise IdentityError(f"Falta {field} para crear la cuenta del invitado.")
    if email is not None and not isinstance(email, str):
        raise IdentityError("El correo declarado debe ser texto.")
    key = DeviceVault(origin).load_or_create()
    public_key = crypto.b64(key.private.public_key().public_bytes_raw())
    claims = {"display_name": name.strip(), "device_label": label.strip()}
    if email and email.strip():
        claims["declared_email"] = email.strip()
    body = {
        "code": code,
        "device_id": key.device_id,
        "public_key": public_key,
        "proof": key.proof(origin, "invite_redeem", **claims),
    }
    result = request_json(origin, "/v1/invites/redeem", body, max_bytes=8192)
    if not isinstance(result.get("channel_id"), str) or result.get("role") not in ROLES:
        raise IdentityError("Relay no confirmó la membresía tras el canje.")
    return result
