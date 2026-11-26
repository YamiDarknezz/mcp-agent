"""Encrypted task storage with single-winner reservations. No plaintext here."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from server import authorization as policy, identity, keys
from server.workspace import _scope

LEASE_SECONDS = 900


async def _access(conn, user_id, channel_id, permission):
    channel, role = await _scope(conn, user_id, channel_id)
    if not policy.allows(role, policy.ChannelKind(channel["kind"]), permission):
        raise identity.Denied(403)
    return role


async def propose(conn, user_id, body):
    await _access(conn, user_id, body.channel_id, policy.Permission.PROPOSE_TASK)
    nonce = keys._unb64(body.nonce)
    ciphertext = keys._unb64(body.ciphertext, 5500)
    if len(nonce) != 12 or not 16 <= len(ciphertext) <= 4112:
        raise identity.Denied(422)
    existing = await keys._one(conn, """
        SELECT id FROM tasks WHERE device_id=:device AND operation_id=:operation
    """, device=body.device_id, operation=body.operation_id)
    if existing:
        return {"task_id": str(existing["id"]), "operation_id": str(body.operation_id)}
    row = await keys._one(conn, """
        INSERT INTO tasks (id, channel_id, operation_id, device_id, nonce, ciphertext, status)
        VALUES (:id, :channel, :operation, :device, :nonce, :ciphertext, 'open') RETURNING id
    """, id=body.task_id, channel=body.channel_id, operation=body.operation_id,
        device=body.device_id, nonce=nonce, ciphertext=ciphertext)
    await conn.execute(text("SELECT pg_notify('relay_messages', :channel)"),
                       {"channel": str(body.channel_id)})
    return {"task_id": str(row["id"]), "operation_id": str(body.operation_id)}


async def list_tasks(conn, user_id, body):
    await _access(conn, user_id, body.channel_id, policy.Permission.READ_TASKS)
    rows = await keys._all(conn, """
        SELECT id, nonce, ciphertext, status, generation, claimed_by, lease_until, created_at
        FROM tasks WHERE channel_id=:channel AND (:all OR status=:status)
        ORDER BY created_at, id LIMIT :limit
    """, channel=body.channel_id, all=body.status is None, status=body.status, limit=body.limit)
    now = datetime.now(UTC)
    items = []
    for row in rows:
        status = row["status"]
        if status == "claimed" and row["lease_until"] <= now:
            status = "expired"
        items.append({
            "task_id": str(row["id"]), "nonce": keys._b64(row["nonce"]),
            "ciphertext": keys._b64(row["ciphertext"]), "status": status,
            "generation": row["generation"],
            "claimed_by": str(row["claimed_by"]) if row["claimed_by"] else None,
            "created_at": row["created_at"],
        })
    return {"tasks": items}


async def claim(conn, user_id, body):
    await _access(conn, user_id, body.channel_id, policy.Permission.CLAIM_TASK)
    device = await keys._one(conn, """
        SELECT id FROM devices WHERE id=:id AND user_id=:user_id AND revoked_at IS NULL
    """, id=body.device_id, user_id=user_id)
    if device is None:
        raise identity.Denied(404)
    now = datetime.now(UTC)
    lease = now + timedelta(seconds=LEASE_SECONDS)
    # One statement reserves the task; a second claimant sees status='claimed'.
    row = await keys._one(conn, """
        UPDATE tasks SET status='claimed', claimed_by=:device, lease_until=:lease,
            generation=generation+1
        WHERE id=:task AND channel_id=:channel AND status='open'
        RETURNING generation
    """, task=body.task_id, channel=body.channel_id, device=body.device_id, lease=lease)
    if row is None:
        raise identity.Denied(409)
    await conn.execute(text("SELECT pg_notify('relay_messages', :channel)"),
                       {"channel": str(body.channel_id)})
    return {"task_id": str(body.task_id), "generation": row["generation"],
            "lease_until": lease}


async def release(conn, user_id, body):
    await _access(conn, user_id, body.channel_id, policy.Permission.CLAIM_TASK)
    row = await keys._one(conn, """
        UPDATE tasks SET status='open', claimed_by=NULL, lease_until=NULL, generation=generation+1
        WHERE id=:task AND channel_id=:channel AND status='claimed' AND claimed_by=:device
        RETURNING generation
    """, task=body.task_id, channel=body.channel_id, device=body.device_id)
    if row is None:
        raise identity.Denied(409)
    await conn.execute(text("SELECT pg_notify('relay_messages', :channel)"),
                       {"channel": str(body.channel_id)})
    return {"task_id": str(body.task_id), "generation": row["generation"]}


async def complete(conn, user_id, body):
    await _access(conn, user_id, body.channel_id, policy.Permission.CLAIM_TASK)
    # A stale generation must never complete a task that was reclaimed.
    row = await keys._one(conn, """
        UPDATE tasks SET status='done', claimed_by=NULL, lease_until=NULL, generation=generation+1
        WHERE id=:task AND channel_id=:channel AND status='claimed'
          AND claimed_by=:device AND generation=:generation
        RETURNING generation
    """, task=body.task_id, channel=body.channel_id, device=body.device_id,
        generation=body.generation)
    if row is None:
        raise identity.Denied(409)
    await conn.execute(text("SELECT pg_notify('relay_messages', :channel)"),
                       {"channel": str(body.channel_id)})
    return {"task_id": str(body.task_id), "generation": row["generation"]}
