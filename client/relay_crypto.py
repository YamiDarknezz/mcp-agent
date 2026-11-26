"""End-to-end encryption primitives for Relay.

Nothing in this module sends data. The server only ever sees ciphertext and
public key material; channel keys and private keys never leave the laptop.

Key separation: the Ed25519 authentication seed already stored in the OS
vault is expanded with HKDF into an X25519 key for encryption. Compromise of
the seed compromises both authentication and encryption keys.
"""

import base64
import hashlib
import hmac
import os
from uuid import UUID

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ENCRYPTION_DOMAIN = b"relay-encryption-key-v1"
WRAP_DOMAIN = b"relay-wrap-v1"
MESSAGE_DOMAIN = b"relay-msg-v1"
KEY_SIZE = 32
NONCE_SIZE = 12


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64(value: str, size: int | None = None) -> bytes:
    data = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if size is not None and len(data) != size:
        raise ValueError("Unexpected key material length.")
    return data


def _aad(domain: bytes, *parts) -> bytes:
    """Length-prefixed fields so tuples cannot be confused by concatenation."""
    out = domain
    for part in parts:
        raw = part.encode("utf-8") if isinstance(part, str) else bytes(part)
        out += len(raw).to_bytes(4, "big") + raw
    return out


def derive_encryption_key(ed25519_seed: bytes) -> X25519PrivateKey:
    if len(ed25519_seed) != 32:
        raise ValueError("Invalid Ed25519 seed.")
    material = HKDF(
        algorithm=hashes.SHA256(), length=KEY_SIZE, salt=None, info=ENCRYPTION_DOMAIN
    ).derive(ed25519_seed)
    return X25519PrivateKey.from_private_bytes(material)


def private_bytes(key: X25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_encryption_key(seed: bytes) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(unb64(b64(seed), KEY_SIZE))


def public_bytes(key: X25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def load_public(data: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(data)


def fingerprint(data: bytes) -> str:
    """Short value for humans to compare out of band; not a secret."""
    return hashlib.sha256(ENCRYPTION_DOMAIN + data).hexdigest()[:24]


def sign_encryption_key(ed_private: Ed25519PrivateKey, x_public: X25519PublicKey) -> bytes:
    return ed_private.sign(ENCRYPTION_DOMAIN + b"|" + public_bytes(x_public))


def verify_encryption_key(
    ed_public: Ed25519PublicKey, x_public: X25519PublicKey, signature: bytes
) -> bool:
    try:
        ed_public.verify(signature, ENCRYPTION_DOMAIN + b"|" + public_bytes(x_public))
        return True
    except InvalidSignature:
        return False


def new_channel_key() -> bytes:
    return os.urandom(KEY_SIZE)


def _wrap_key(shared: bytes, salt: bytes, channel_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        info=WRAP_DOMAIN + b"|" + channel_id.encode("utf-8"),
    ).derive(shared)


def wrap_channel_key(
    sender_private: X25519PrivateKey,
    recipient_public: X25519PublicKey,
    channel_key: bytes,
    channel_id: str,
    sender_device_id: str,
    recipient_device_id: str,
) -> str:
    """Encrypt a channel key for one device. The server cannot unwrap it."""
    if len(channel_key) != KEY_SIZE:
        raise ValueError("Invalid channel key.")
    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = public_bytes(ephemeral.public_key())
    shared = ephemeral.exchange(recipient_public)
    nonce = os.urandom(NONCE_SIZE)
    aad = _aad(WRAP_DOMAIN, channel_id, sender_device_id, recipient_device_id, ephemeral_public)
    wrapped = AESGCM(_wrap_key(shared, ephemeral_public, channel_id)).encrypt(nonce, channel_key, aad)
    return b64(ephemeral_public + nonce + wrapped)


def unwrap_channel_key(
    recipient_private: X25519PrivateKey,
    envelope: str,
    channel_id: str,
    sender_device_id: str,
    recipient_device_id: str,
) -> bytes:
    raw = unb64(envelope)
    if len(raw) < KEY_SIZE + NONCE_SIZE + 16:
        raise ValueError("Malformed envelope.")
    ephemeral_public, nonce, wrapped = raw[:KEY_SIZE], raw[KEY_SIZE : KEY_SIZE + NONCE_SIZE], raw[KEY_SIZE + NONCE_SIZE :]
    sender_public = load_public(ephemeral_public)
    shared = recipient_private.exchange(sender_public)
    aad = _aad(WRAP_DOMAIN, channel_id, sender_device_id, recipient_device_id, ephemeral_public)
    try:
        return AESGCM(_wrap_key(shared, ephemeral_public, channel_id)).decrypt(nonce, wrapped, aad)
    except InvalidTag:
        raise ValueError("Channel key envelope failed authentication.") from None


def encrypt_message(
    channel_key: bytes, channel_id: str, seq: int, plaintext: bytes
) -> tuple[str, str]:
    """Return (base64 nonce, base64 ciphertext). AAD binds channel and sequence."""
    if len(channel_key) != KEY_SIZE or seq < 0:
        raise ValueError("Invalid encryption input.")
    nonce = os.urandom(NONCE_SIZE)
    aad = _aad(MESSAGE_DOMAIN, channel_id, seq.to_bytes(8, "big"))
    ciphertext = AESGCM(channel_key).encrypt(nonce, plaintext, aad)
    return b64(nonce), b64(ciphertext)


def decrypt_message(
    channel_key: bytes, channel_id: str, seq: int, nonce: str, ciphertext: str
) -> bytes:
    aad = _aad(MESSAGE_DOMAIN, channel_id, seq.to_bytes(8, "big"))
    try:
        return AESGCM(channel_key).decrypt(
            unb64(nonce, NONCE_SIZE), unb64(ciphertext), aad
        )
    except (InvalidTag, ValueError):
        raise ValueError("Message failed authenticated decryption.") from None


def verify_channel_key(channel_key: bytes) -> bool:
    return hmac.compare_digest(len(channel_key).to_bytes(4, "big"), (KEY_SIZE).to_bytes(4, "big"))


def parse_uuid(value: str) -> str:
    return str(UUID(value))
