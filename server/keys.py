"""Device public keys and opaque channel-key envelopes.

Only public key material is stored in plaintext. The server cannot derive a
channel key from an envelope and never receives message plaintext.
"""

import base64
import binascii
from datetime import UTC, datetime
from hashlib import sha256
from uuid import UUID, uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import text

from server import authorization as policy, identity
from server.workspace import _scope

ENCRYPTION_DOMAIN = b"relay-encryption-key-v1"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value: str, max_length: int = 128) -> bytes:
    if not isinstance(value, str) or len(value) > max_length:
        raise identity.Denied(422)
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        raise identity.Denied(422) from None


async def _one(conn, query, **params):
    return (await conn.execute(text(query), params)).mappings().one_or_none()


async def _all(conn, query, **params):
    return (await conn.execute(text(query), params)).mappings().all()


def fingerprint(data: bytes) -> str:
    return sha256(ENCRYPTION_DOMAIN + data).hexdigest()[:24]


async def publish_device_key(conn, device_id, public_b64, signature_b64):
    raw_public = _unb64(public_b64)
    raw_signature = _unb64(signature_b64)
    if len(raw_public) != 32 or len(raw_signature) != 64:
        raise identity.Denied(422)
    device = await _one(conn, "SELECT * FROM devices WHERE id = :id FOR UPDATE", id=device_id)
    if not device or device["revoked_at"] is not None or device["public_key"] is None:
        raise identity.Denied()
    signing_key = Ed25519PublicKey.from_public_bytes(device["public_key"])
    try:
        signing_key.verify(raw_signature, ENCRYPTION_DOMAIN + b"|" + raw_public)
    except Exception:
        raise identity.Denied() from None
    await conn.execute(
        text("""UPDATE devices SET encryption_public_key=:pub, encryption_signature=:sig,
                encryption_updated_at=:now WHERE id=:id"""),
        {"pub": raw_public, "sig": raw_signature, "now": datetime.now(UTC), "id": device_id},
    )
    return {"fingerprint": fingerprint(raw_public)}


async def list_devices(conn, user_id):
    rows = await _all(
        conn, """SELECT id, label, public_key, encryption_public_key, encryption_signature
                 FROM devices WHERE user_id = :user_id AND revoked_at IS NULL ORDER BY created_at, id""",
        user_id=user_id,
    )
    return {
        "devices": [
            {
                "id": str(row["id"]),
                "label": row["label"],
                "authentication_key": _b64(row["public_key"]),
                "encryption_key": _b64(row["encryption_public_key"]) if row["encryption_public_key"] else None,
                "encryption_signature": _b64(row["encryption_signature"]) if row["encryption_signature"] else None,
                "fingerprint": fingerprint(row["encryption_public_key"]) if row["encryption_public_key"] else None,
            }
            for row in rows
        ]
    }


async def _channel_access(conn, user_id, channel_id):
    channel, role = await _scope(conn, user_id, channel_id)
    if not policy.allows(role, policy.ChannelKind(channel["kind"]), policy.Permission.READ_MESSAGES):
        raise identity.Denied(404)
    return role


async def _validated_envelopes(conn, envelopes, channel_id):
    if not isinstance(envelopes, dict) or not 1 <= len(envelopes) <= 64:
        raise identity.Denied(422)
    clean = {}
    for device_id, envelope in envelopes.items():
        try:
            uuid = UUID(device_id)
            if uuid.version != 4:
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise identity.Denied(422) from None
        if not isinstance(envelope, str) or not 80 <= len(envelope) <= 4096:
            raise identity.Denied(422)
        clean[uuid] = _unb64(envelope, 4096)
        if not 80 <= len(clean[uuid]) <= 3072:
            raise identity.Denied(422)
        recipient = await _one(
            conn,
            """SELECT user_id FROM devices WHERE id = :id
               AND revoked_at IS NULL AND encryption_public_key IS NOT NULL""",
            id=uuid,
        )
        if recipient is None:
            raise identity.Denied(404)
        await _channel_access(conn, recipient["user_id"], channel_id)
    return clean


async def publish_channel_key(conn, user_id, sender_device_id, channel_id, key_id, envelopes):
    role = await _channel_access(conn, user_id, channel_id)
    if role not in (policy.Role.OWNER, policy.Role.ADMIN):
        raise identity.Denied(403)
    clean = await _validated_envelopes(conn, envelopes, channel_id)
    existing = await _one(conn, "SELECT key_id FROM channel_keys WHERE channel_id = :id", id=channel_id)
    if existing:
        # Adding recipients later must reuse the same key, never replace it.
        if existing["key_id"] != key_id:
            raise identity.Denied(409)
    else:
        await conn.execute(
            text("""INSERT INTO channel_keys (channel_id, key_id, created_by)
                    VALUES (:channel, :key_id, :sender)"""),
            {"channel": channel_id, "key_id": key_id, "sender": sender_device_id},
        )
    for device_id, envelope in clean.items():
        await conn.execute(
            text("""INSERT INTO channel_key_envelopes
                    (channel_id, recipient_device_id, sender_device_id, envelope)
                    VALUES (:channel, :recipient, :sender, :envelope)
                    ON CONFLICT (channel_id, recipient_device_id) DO NOTHING"""),
            {"channel": channel_id, "recipient": device_id, "sender": sender_device_id, "envelope": envelope},
        )
    total = await _one(
        conn, "SELECT count(*) AS n FROM channel_key_envelopes WHERE channel_id = :id", id=channel_id,
    )
    return {"channel_id": str(channel_id), "key_id": str(key_id), "recipients": total["n"]}


async def rotate_channel_key(
    conn, user_id, sender_device_id, channel_id, new_key_id, replaces_key_id, envelopes
):
    """Replace a channel key, retiring the old one and rewrapping for remaining devices."""
    role = await _channel_access(conn, user_id, channel_id)
    if role not in (policy.Role.OWNER, policy.Role.ADMIN):
        raise identity.Denied(403)
    current = await _one(conn, "SELECT key_id FROM channel_keys WHERE channel_id = :id", id=channel_id)
    if current is None:
        raise identity.Denied(404)
    if str(current["key_id"]) != str(replaces_key_id):
        raise identity.Denied(409)
    if str(new_key_id) == str(replaces_key_id):
        raise identity.Denied(422)
    clean = await _validated_envelopes(conn, envelopes, channel_id)
    now = datetime.now(UTC)
    await conn.execute(
        text("""UPDATE channel_keys
                SET key_id = :new, rotated_at = :now, rotation_required = false
                WHERE channel_id = :channel AND key_id = :old"""),
        {"new": new_key_id, "now": now, "channel": channel_id, "old": replaces_key_id},
    )
    await conn.execute(
        text("""INSERT INTO channel_key_history (channel_id, key_id, retired_at)
                VALUES (:channel, :old, :now) ON CONFLICT DO NOTHING"""),
        {"channel": channel_id, "old": replaces_key_id, "now": now},
    )
    await conn.execute(
        text("DELETE FROM channel_key_envelopes WHERE channel_id = :channel"), {"channel": channel_id},
    )
    for device_id, envelope in clean.items():
        await conn.execute(
            text("""INSERT INTO channel_key_envelopes
                    (channel_id, recipient_device_id, sender_device_id, envelope)
                    VALUES (:channel, :recipient, :sender, :envelope)"""),
            {"channel": channel_id, "recipient": device_id, "sender": sender_device_id, "envelope": envelope},
        )
    return {
        "channel_id": str(channel_id), "key_id": str(new_key_id),
        "replaced_key_id": str(replaces_key_id), "recipients": len(clean),
    }


async def affected_channels(conn, device_id):
    """Target channel plus descendants that inherit access; no siblings or restricted children."""
    rows = await _all(conn, """
        WITH RECURSIVE seeds AS (
            SELECT channel_id FROM channel_key_envelopes
            WHERE recipient_device_id = :device OR sender_device_id = :device
            UNION
            SELECT channel_id FROM channel_memberships
            WHERE user_id = (SELECT user_id FROM devices WHERE id = :device)
        ),
        tree AS (
            SELECT id FROM channels WHERE id IN (SELECT channel_id FROM seeds)
            UNION ALL
            SELECT c.id FROM channels c JOIN tree t ON c.parent_id = t.id
            WHERE c.inherits_access
        )
        SELECT DISTINCT id FROM tree
    """, device=device_id)
    return [row["id"] for row in rows]


async def mark_rotation_required(conn, channel_ids):
    for channel_id in channel_ids:
        await conn.execute(
            text("UPDATE channel_keys SET rotation_required = true WHERE channel_id = :id"),
            {"id": channel_id},
        )


async def pending_rotations(conn, user_id):
    rows = await _all(conn, """
        SELECT ck.channel_id, c.name FROM channel_keys ck
        JOIN channels c ON c.id = ck.channel_id
        JOIN channel_memberships m ON m.channel_id = ck.channel_id AND m.user_id = :user
        WHERE ck.rotation_required
    """, user=user_id)
    return [{"channel_id": str(row["channel_id"]), "name": row["name"]} for row in rows]


async def fetch_channel_key(conn, user_id, device_id, channel_id):
    role = await _channel_access(conn, user_id, channel_id)
    key = await _one(conn, "SELECT * FROM channel_keys WHERE channel_id = :id", id=channel_id)
    if not key:
        raise identity.Denied(404)
    envelope = await _one(
        conn, """SELECT envelope, sender_device_id FROM channel_key_envelopes
                 WHERE channel_id = :channel AND recipient_device_id = :recipient""",
        channel=channel_id, recipient=device_id,
    )
    if not envelope:
        raise identity.Denied(404)
    devices = (await list_devices(conn, user_id))["devices"]
    return {
        "channel_id": str(channel_id),
        "key_id": str(key["key_id"]),
        "envelope": _b64(envelope["envelope"]),
        "sender_device_id": str(envelope["sender_device_id"]),
        "devices": devices,
        "role": str(role),
    }
