"""One-time channel invitations for people outside the account.

An invitation only grants a role on the exact target subchannel. It never
grants ancestors, siblings, ownership, or privileges from the declared email.
The code is hashed at rest and consumed together with the membership insert in
the same transaction.
"""

from datetime import datetime, timedelta, UTC
from hashlib import sha256
import re
from secrets import token_urlsafe
from uuid import uuid4

from sqlalchemy import text

from server import authorization as policy
from server import workspace
from server.identity import Denied, _label, _summary, verify_proof

CODE_PATTERN = r"relay_inv_[A-Za-z0-9_-]{43}"
KEY_PATTERN = r"^[A-Za-z0-9_-]{43}$"
PROOF_PURPOSE = "invite_redeem"
DEFAULT_TTL = 900
MIN_TTL = 60
MAX_TTL = 3600
MAX_ATTEMPTS = 5
INVITABLE_ROLES = ("reader", "collaborator", "admin")


def _digest(code: str) -> bytes:
    if not isinstance(code, str) or not re.fullmatch(CODE_PATTERN, code):
        raise Denied()
    return sha256(code.encode("ascii")).digest()


async def _run(conn, query, **params):
    await conn.execute(text(query), params)


async def _one(conn, query, **params):
    return (await conn.execute(text(query), params)).mappings().one_or_none()


async def issue(conn, user_id, channel_id, invited_role, expires_in=None):
    target, actor_role = await workspace._scope(conn, user_id, channel_id)
    kind = policy.ChannelKind(target["kind"])
    if kind is not policy.ChannelKind.WORK:
        raise Denied(422)
    if invited_role not in INVITABLE_ROLES:
        raise Denied(422)
    try:
        role = policy.Role(invited_role)
    except ValueError:
        raise Denied(422) from None
    if not policy.can_invite(actor_role, kind, role):
        raise Denied(403)
    try:
        ttl = DEFAULT_TTL if expires_in is None else int(expires_in)
    except (TypeError, ValueError):
        raise Denied(422) from None
    ttl = max(MIN_TTL, min(MAX_TTL, ttl))
    now = datetime.now(UTC)
    expires = now + timedelta(seconds=ttl)
    await _run(
        conn, """UPDATE channel_invites SET revoked_at = :now
                 WHERE issuer_user_id = :user AND channel_id = :channel
                 AND revoked_at IS NULL AND consumed_at IS NULL""",
        now=now, user=user_id, channel=channel_id,
    )
    code = "relay_inv_" + token_urlsafe(32)
    invite_id = uuid4()
    await _run(
        conn, """INSERT INTO channel_invites
                 (id, channel_id, digest, invited_role, issuer_user_id, expires_at, max_attempts)
                 VALUES (:id, :channel, :digest, :role, :user, :expires, :attempts)""",
        id=invite_id, channel=channel_id, digest=_digest(code), role=invited_role,
        user=user_id, expires=expires, attempts=MAX_ATTEMPTS,
    )
    return {"code": code, "expires_at": expires, "channel_id": channel_id, "role": invited_role}


async def status(conn, user_id, channel_id):
    await workspace._scope(conn, user_id, channel_id)
    row = await _one(
        conn, """SELECT count(*) AS active, max(expires_at) AS last_expires_at
                 FROM channel_invites
                 WHERE channel_id = :channel AND issuer_user_id = :user
                 AND revoked_at IS NULL AND consumed_at IS NULL AND expires_at > :now""",
        channel=channel_id, user=user_id, now=datetime.now(UTC),
    )
    return {"active": row["active"], "last_expires_at": row["last_expires_at"]}


async def redeem(conn, code, device_id, public_key, proof, audience):
    digest = _digest(code)
    entry = await _one(conn, "SELECT * FROM channel_invites WHERE digest = :digest FOR UPDATE", digest=digest)
    if entry is None:
        raise Denied()
    now = datetime.now(UTC)
    if entry["revoked_at"] or entry["consumed_at"] or entry["expires_at"] <= now:
        raise Denied()
    if entry["attempts"] >= entry["max_attempts"]:
        raise Denied(429)
    if not isinstance(public_key, str) or not re.fullmatch(KEY_PATTERN, public_key):
        raise Denied(422)
    await _run(conn, "UPDATE channel_invites SET attempts = attempts + 1 WHERE id = :id", id=entry["id"])
    claims, _ = verify_proof(public_key, proof, audience, device_id, PROOF_PURPOSE)
    display_name = _label(claims.get("display_name"), 100)
    device_label = _label(claims.get("device_label"), 100)
    declared_email = _label(claims.get("declared_email"), 254, required=False)
    user_id = uuid4()
    await _run(
        conn, """INSERT INTO users (id, display_name, declared_email)
                 VALUES (:id, :name, :email)""",
        id=user_id, name=display_name, email=declared_email,
    )
    await _run(
        conn, """INSERT INTO devices (id, user_id, public_key, label)
                 VALUES (:id, :user, :key, :label)""",
        id=device_id, user=user_id, key=public_key, label=device_label,
    )
    await _run(
        conn, """INSERT INTO channel_memberships (channel_id, user_id, role)
                 VALUES (:channel, :user, :role)""",
        channel=entry["channel_id"], user=user_id, role=entry["invited_role"],
    )
    await _run(conn, "UPDATE channel_invites SET consumed_at = :now WHERE id = :id", now=now, id=entry["id"])
    summary = await _summary(conn, device_id, user_id)
    return {**summary, "channel_id": str(entry["channel_id"]), "role": entry["invited_role"]}


async def revoke(conn, user_id, invite_id):
    entry = await _one(conn, "SELECT * FROM channel_invites WHERE id = :id FOR UPDATE", id=invite_id)
    if entry is None:
        raise Denied(404)
    await workspace._scope(conn, user_id, entry["channel_id"])
    if entry["issuer_user_id"] != user_id:
        raise Denied(403)
    await _run(
        conn, "UPDATE channel_invites SET revoked_at = :now WHERE id = :id AND revoked_at IS NULL",
        now=datetime.now(UTC), id=invite_id,
    )
    return {"revoked": True, "invite_id": str(invite_id)}
