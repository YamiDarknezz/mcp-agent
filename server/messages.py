"""Bounded, encrypted message storage; plaintext never enters this module."""

from sqlalchemy import text
from server import authorization as policy, identity, keys
from server.workspace import _scope


async def _access(conn, user_id, channel_id, permission):
    channel, role = await _scope(conn, user_id, channel_id)
    if not policy.allows(role, policy.ChannelKind(channel["kind"]), permission):
        raise identity.Denied(403)


async def send(conn, user_id, body):
    await _access(conn, user_id, body.channel_id, policy.Permission.POST_MESSAGE)
    nonce = keys._unb64(body.nonce)
    ciphertext = keys._unb64(body.ciphertext, 5500)
    if len(nonce) != 12 or not 16 <= len(ciphertext) <= 4112:
        raise identity.Denied(422)
    # Serialize channel sequence assignment and preserve retry identity.
    await conn.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(CAST(:id AS text), 0))"),
                       {"id": body.channel_id})
    existing = await keys._one(conn, """
        SELECT channel_id, seq, nonce, ciphertext FROM channel_messages
        WHERE device_id=:device AND operation_id=:operation
    """, device=body.device_id, operation=body.operation_id)
    if existing:
        if (existing["channel_id"] != body.channel_id or bytes(existing["nonce"]) != nonce
                or bytes(existing["ciphertext"]) != ciphertext):
            raise identity.Denied(409)
        return {"seq": existing["seq"], "operation_id": str(body.operation_id)}
    row = await keys._one(conn, """
        INSERT INTO channel_messages (channel_id, seq, operation_id, device_id, nonce, ciphertext)
        SELECT :channel, COALESCE(MAX(seq), 0) + 1, :operation, :device, :nonce, :ciphertext
        FROM channel_messages WHERE channel_id=:channel RETURNING seq
    """, channel=body.channel_id, operation=body.operation_id, device=body.device_id,
        nonce=nonce, ciphertext=ciphertext)
    return {"seq": row["seq"], "operation_id": str(body.operation_id)}


async def read(conn, user_id, body):
    await _access(conn, user_id, body.channel_id, policy.Permission.READ_MESSAGES)
    rows = await keys._all(conn, """
        SELECT seq, operation_id, device_id, nonce, ciphertext, created_at
        FROM channel_messages WHERE channel_id=:channel AND seq > :after
        ORDER BY seq LIMIT :limit
    """, channel=body.channel_id, after=body.after, limit=body.limit)
    return {"messages": [
        {"seq": row["seq"], "operation_id": str(row["operation_id"]),
         "device_id": str(row["device_id"]), "nonce": keys._b64(row["nonce"]),
         "ciphertext": keys._b64(row["ciphertext"]), "created_at": row["created_at"]}
        for row in rows
    ]}
