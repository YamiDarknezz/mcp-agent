"""Key setup and distribution for Relay end-to-end encryption.

The server sees only signed public keys and opaque envelopes. Channel keys
are kept in the OS credential vault, one per channel and server origin.
"""

import hashlib
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

if __package__:
    from . import relay_crypto as crypto
    from .relay_identity import DeviceVault, IdentityError, request_json
else:
    import relay_crypto as crypto
    from relay_identity import DeviceVault, IdentityError, request_json


class ChannelKeyStore:
    def __init__(self, origin, backend=None):
        self.service = "Relay channel " + hashlib.sha256(origin.encode("ascii")).hexdigest()
        self.backend = backend or DeviceVault(origin).backend

    def save(self, channel_id: str, key: bytes):
        self.backend.set_password(self.service, channel_id, crypto.b64(key))

    def load(self, channel_id: str) -> bytes | None:
        value = self.backend.get_password(self.service, channel_id)
        if value is None:
            return None
        return crypto.unb64(value, crypto.KEY_SIZE)


def _signed(origin, key, payload):
    return {**payload, "device_id": key.device_id, "proof": key.proof(origin, "workspace")}


def setup(origin: str) -> dict[str, Any]:
    """Derive, sign and publish this device's encryption public key."""
    key = DeviceVault(origin).load()
    if key is None:
        raise IdentityError("Esta laptop no está registrada en Relay.")
    result = request_json(
        origin, "/v1/devices/encryption-key",
        _signed(origin, key, {
            "public_key": crypto.b64(crypto.public_bytes(key.encryption_public())),
            "signature": crypto.b64(key.encryption_signature()),
        }),
    )
    if result.get("fingerprint") != key.fingerprint():
        raise IdentityError("La huella devuelta por Relay no coincide con la clave local.")
    return {"fingerprint": key.fingerprint(), "device_id": key.device_id}


def list_devices(origin: str) -> dict[str, Any]:
    key = DeviceVault(origin).load()
    if key is None:
        raise IdentityError("Esta laptop no está registrada en Relay.")
    return request_json(origin, "/v1/devices/list", _signed(origin, key, {}))


def _verified_public(device: dict[str, Any], origin: str) -> bytes:
    public = device.get("encryption_key")
    signature = device.get("signature") or device.get("encryption_signature")
    auth = device.get("authentication_key")
    if not public or not signature or not auth:
        raise IdentityError("Un dispositivo todavía no tiene clave de cifrado publicada.")
    xpub = crypto.load_public(crypto.unb64(public, crypto.KEY_SIZE))
    edpub = Ed25519PublicKey.from_public_bytes(crypto.unb64(auth, 32))
    if not crypto.verify_encryption_key(edpub, xpub, crypto.unb64(signature, 64)):
        raise IdentityError("La clave pública de un dispositivo no está firmada por su clave de autenticación.")
    if crypto.fingerprint(crypto.public_bytes(xpub)) != device.get("fingerprint"):
        raise IdentityError("La huella de un dispositivo no coincide con su clave pública.")
    return crypto.public_bytes(xpub)


def share(
    origin: str, channel_id: str, recipients: list[str] | None = None, key_id: str | None = None
) -> dict[str, Any]:
    """Create or extend a channel key, wrapping it for each authorized device."""
    key = DeviceVault(origin).load()
    if key is None:
        raise IdentityError("Esta laptop no está registrada en Relay.")
    devices = list_devices(origin)["devices"]
    mine = next((d for d in devices if d["id"] == key.device_id), None)
    if mine is None or not mine.get("encryption_key"):
        raise IdentityError("Ejecuta setup_encryption antes de compartir una clave de canal.")
    store = ChannelKeyStore(origin)
    channel_key = store.load(channel_id) if key_id else None
    if key_id and channel_key is None:
        raise IdentityError("No tienes la clave de este canal; ejecuta load_channel_key primero.")
    if channel_key is None:
        channel_key = crypto.new_channel_key()
        key_id = str(uuid4())
    envelopes = {}
    targets = recipients or [d["id"] for d in devices if d.get("encryption_key")]
    selected = [d for d in devices if d["id"] in targets and d.get("encryption_key")]
    if not selected:
        raise IdentityError("No hay dispositivos destinatarios con clave de cifrado.")
    for device in selected:
        recipient_public = crypto.load_public(_verified_public(device, origin))
        envelopes[device["id"]] = crypto.wrap_channel_key(
            key.encryption_private(), recipient_public, channel_key,
            channel_id, key.device_id, device["id"],
        )
    body = _signed(origin, key, {
        "channel_id": channel_id, "key_id": key_id, "envelopes": envelopes,
    })
    result = request_json(origin, "/v1/keys/publish", body)
    store.save(channel_id, channel_key)
    return {**result, "recipients": sorted(envelopes)}


def load(origin: str, channel_id: str) -> dict[str, Any]:
    """Fetch and unwrap this device's channel key, verifying signer identity."""
    key = DeviceVault(origin).load()
    if key is None:
        raise IdentityError("Esta laptop no está registrada en Relay.")
    result = request_json(
        origin, "/v1/keys/fetch", _signed(origin, key, {"channel_id": channel_id})
    )
    sender = next((d for d in result["devices"] if d["id"] == result["sender_device_id"]), None)
    if sender is None:
        raise IdentityError("No se pudo verificar el dispositivo que envió la clave.")
    _verified_public(sender, origin)
    channel_key = crypto.unwrap_channel_key(
        key.encryption_private(), result["envelope"],
        result["channel_id"], result["sender_device_id"], key.device_id,
    )
    ChannelKeyStore(origin).save(channel_id, channel_key)
    return {
        "channel_id": result["channel_id"],
        "key_id": result["key_id"],
        "fingerprint": crypto.fingerprint(channel_key),
        "role": result["role"],
    }


def has_local_key(origin: str, channel_id: str) -> bool:
    return ChannelKeyStore(origin).load(channel_id) is not None


def encrypt(origin: str, channel_id: str, seq: int, plaintext: bytes) -> dict[str, str]:
    key = ChannelKeyStore(origin).load(channel_id)
    if key is None:
        raise IdentityError("Esta laptop no tiene la clave de este canal.")
    nonce, ciphertext = crypto.encrypt_message(key, channel_id, seq, plaintext)
    return {"nonce": nonce, "ciphertext": ciphertext}


def decrypt(origin: str, channel_id: str, seq: int, nonce: str, ciphertext: str) -> bytes:
    key = ChannelKeyStore(origin).load(channel_id)
    if key is None:
        raise IdentityError("Esta laptop no tiene la clave de este canal.")
    return crypto.decrypt_message(key, channel_id, seq, nonce, ciphertext)
