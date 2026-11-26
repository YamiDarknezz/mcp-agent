"""Project and channel operations using an authenticated account, never a claimed role."""

from hashlib import sha256
import re
import unicodedata
from uuid import uuid4

from sqlalchemy import text

from server import authorization as policy
from server.identity import Denied, record_security_event

MAX_DEPTH = 8


def names(name: str, slug: str | None) -> tuple[str, str]:
    if any(unicodedata.category(char) == "Cc" for char in name):
        raise Denied(422)
    name = unicodedata.normalize("NFC", name.strip())
    if not 1 <= len(name) <= 100:
        raise Denied(422)
    if slug is None:
        ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode().lower()
        slug = re.sub(r"[^a-z0-9]+", "-", ascii_name).strip("-")[:64].rstrip("-")
        if not slug:
            slug = "channel-" + sha256(name.encode()).hexdigest()[:12]
    return name, slug


async def _one(conn, query, **params):
    return (await conn.execute(text(query), params)).mappings().one_or_none()


async def _scope(conn, user_id, channel_id):
    """Load only the target lineage and apply the same policy as other mutations."""
    result = await conn.execute(text("""
        WITH RECURSIVE ancestors AS (
            SELECT * FROM channels WHERE id = :channel_id
            UNION ALL
            SELECT c.* FROM channels c JOIN ancestors a ON c.id = a.parent_id
        )
        SELECT a.*, m.role AS direct_role, m.channel_id IS NOT NULL AS has_grant
        FROM ancestors a
        LEFT JOIN channel_memberships m ON m.user_id = :user_id AND m.channel_id = a.id
    """), {"user_id": user_id, "channel_id": channel_id})
    rows = {str(row["id"]): row for row in result.mappings()}
    target = rows.get(str(channel_id))
    if not target:
        raise Denied(404)
    channels = {
        key: policy.Channel(
            project_id=str(row["project_id"]), kind=policy.ChannelKind(row["kind"]),
            parent_id=str(row["parent_id"]) if row["parent_id"] else None,
            inherits_access=row["inherits_access"],
        )
        for key, row in rows.items()
    }
    memberships = {
        key: policy.Role(row["direct_role"]) if row["direct_role"] else None
        for key, row in rows.items() if row["has_grant"]
    }
    role = policy.effective_role(str(channel_id), channels, memberships)
    if role is None:
        raise Denied(404)
    return target, role


def _card(row, role, parent_id=None, project_id=None):
    return {
        "id": row["id"], "name": row["name"], "slug": row["slug"],
        "kind": row["kind"], "role": role, "inherits_access": row["inherits_access"],
        "project_id": project_id, "parent_id": parent_id,
    }


async def create_project(conn, user_id, data):
    name, slug = names(data.name, data.slug)
    root_id = uuid4()
    root = await _one(
        conn, """INSERT INTO channels (id, project_id, kind, depth, name, slug, inherits_access, created_by)
                 VALUES (:id, :id, 'project', 0, :name, :slug, false, :user_id)
                 ON CONFLICT (created_by, slug) WHERE kind = 'project' DO NOTHING RETURNING *""",
        id=root_id, name=name, slug=slug, user_id=user_id,
    )
    if root is None:
        root = await _one(
            conn, "SELECT * FROM channels WHERE created_by = :user_id AND slug = :slug AND kind = 'project'",
            user_id=user_id, slug=slug,
        )
        if root is None or root["name"] != name:
            raise Denied(409)
        try:
            _, role = await _scope(conn, user_id, root["id"])
            main = await _one(
                conn, "SELECT id FROM channels WHERE project_id = :project_id AND kind = 'main'",
                project_id=root["id"],
            )
            if main is None:
                raise Denied(409)
            main_row, main_role = await _scope(conn, user_id, main["id"])
        except Denied:
            raise Denied(409) from None
        return {
            "project": _card(root, role, project_id=root["id"]),
            "main": _card(main_row, main_role, root["id"], root["id"]), "created": False,
        }

    await conn.execute(
        text("INSERT INTO channel_memberships (channel_id, user_id, role) VALUES (:id, :user_id, 'owner')"),
        {"id": root_id, "user_id": user_id},
    )
    main = await _one(
        conn, """INSERT INTO channels
                    (id, project_id, parent_id, kind, parent_kind, parent_depth, depth, name, slug, inherits_access, created_by)
                 VALUES (:id, :root_id, :root_id, 'main', 'project', 0, 1, 'main', 'main', true, :user_id)
                 RETURNING *""",
        id=uuid4(), root_id=root_id, user_id=user_id,
    )
    await conn.execute(
        text("INSERT INTO channel_subscriptions (channel_id, user_id, mode) VALUES (:id, :user_id, 'mentions')"),
        {"id": main["id"], "user_id": user_id},
    )
    await record_security_event(conn, "project_created", root_id)
    return {
        "project": _card(root, policy.Role.OWNER, project_id=root_id),
        "main": _card(main, policy.Role.OWNER, root_id, root_id), "created": True,
    }


async def create_subchannel(conn, user_id, data):
    name, slug = names(data.name, data.slug)
    parent, parent_role = await _scope(conn, user_id, data.parent_id)
    kind = policy.ChannelKind(parent["kind"])
    if not policy.allows(parent_role, kind, policy.Permission.CREATE_SUBCHANNEL):
        raise Denied(403)
    if parent["depth"] >= MAX_DEPTH or (kind is policy.ChannelKind.PROJECT and slug == "main"):
        raise Denied(422)
    inherits = data.access == "inherit"
    row = await _one(
        conn, """INSERT INTO channels
                    (id, project_id, parent_id, kind, parent_kind, parent_depth, depth, name, slug, inherits_access, created_by)
                 VALUES (:id, :project_id, :parent_id, 'work', :parent_kind, :parent_depth, :depth, :name, :slug, :inherits, :user_id)
                 ON CONFLICT (parent_id, slug) WHERE parent_id IS NOT NULL DO NOTHING RETURNING *""",
        id=uuid4(), project_id=parent["project_id"], parent_id=data.parent_id, parent_kind=parent["kind"],
        parent_depth=parent["depth"], depth=parent["depth"] + 1, name=name, slug=slug,
        inherits=inherits, user_id=user_id,
    )
    created = row is not None
    if created:
        role = parent_role
        if not inherits:
            await conn.execute(
                text("INSERT INTO channel_memberships (channel_id, user_id, role) VALUES (:id, :user_id, 'owner')"),
                {"id": row["id"], "user_id": user_id},
            )
            role = policy.Role.OWNER
        await record_security_event(conn, "channel_created", row["id"])
    else:
        row = await _one(
            conn, "SELECT * FROM channels WHERE parent_id = :parent_id AND slug = :slug",
            parent_id=data.parent_id, slug=slug,
        )
        if row is None or row["name"] != name or row["inherits_access"] != inherits:
            raise Denied(409)
        try:
            _, role = await _scope(conn, user_id, row["id"])
        except Denied:
            raise Denied(409) from None
    try:
        await _scope(conn, user_id, parent["project_id"])
    except Denied:
        visible_project = None
    else:
        visible_project = parent["project_id"]
    return {"channel": _card(row, role, parent["id"], visible_project), "created": created}


# The CTE seeds direct grants and follows inheritance until an explicit grant/block or
# a restricted node. The composite parent FK keeps the graph within a single tree.
_VISIBLE = """
    WITH RECURSIVE visible(id, role) AS (
        SELECT m.channel_id, m.role
        FROM channel_memberships m JOIN channels c ON c.id = m.channel_id
        WHERE m.user_id = :user_id AND m.role IS NOT NULL
          AND (m.role <> 'owner' OR c.kind = 'project' OR (c.kind = 'work' AND NOT c.inherits_access))
          AND (:all_projects OR c.project_id = CAST(:project_id AS uuid))
        UNION ALL
        SELECT c.id,
               CASE WHEN cm.role = 'owner' THEN cm.role ELSE v.role END
        FROM visible v JOIN channels c ON c.parent_id = v.id
        LEFT JOIN channel_memberships cm ON cm.channel_id = c.id AND cm.user_id = :user_id
        WHERE c.inherits_access
          AND NOT EXISTS (SELECT 1 FROM channel_memberships m WHERE m.channel_id = c.id AND m.user_id = :user_id)
    )
"""


async def _page(conn, user_id, data, *, roots, project_id=None):
    result = await conn.execute(text(_VISIBLE + """
        SELECT c.id, c.name, c.slug, c.kind, c.inherits_access, v.role,
               parent.id AS visible_parent, c.project_id AS project_id
        FROM visible v JOIN channels c ON c.id = v.id
        LEFT JOIN visible parent ON parent.id = c.parent_id
        WHERE (c.kind = 'project') = :roots
          AND (:first_page OR c.id > CAST(:cursor AS uuid))
        ORDER BY c.id LIMIT :fetch
    """), {
        "user_id": user_id, "roots": roots, "first_page": data.cursor is None, "cursor": data.cursor,
        "fetch": data.limit + 1, "all_projects": project_id is None, "project_id": project_id,
    })
    rows = result.mappings().all()
    shown = rows[:data.limit]
    return {
        "items": [_card(row, row["role"], row["visible_parent"], row["project_id"]) for row in shown],
        "next_cursor": shown[-1]["id"] if len(rows) > data.limit else None,
    }


async def list_projects(conn, user_id, data):
    return await _page(conn, user_id, data, roots=True)


async def list_channels(conn, user_id, data):
    if data.project_id is not None:
        root, _ = await _scope(conn, user_id, data.project_id)
        if root["kind"] != policy.ChannelKind.PROJECT:
            raise Denied(404)
    return await _page(conn, user_id, data, roots=False, project_id=data.project_id)


async def set_subscription(conn, user_id, data):
    channel, role = await _scope(conn, user_id, data.channel_id)
    if not policy.allows(role, policy.ChannelKind(channel["kind"]), policy.Permission.SUBSCRIBE):
        raise Denied(403)
    if data.mode is None:
        await conn.execute(text("""
            DELETE FROM channel_subscriptions WHERE channel_id=:channel AND user_id=:user_id
        """), {"channel": data.channel_id, "user_id": user_id})
    else:
        await conn.execute(text("""
            INSERT INTO channel_subscriptions (channel_id, user_id, mode)
            VALUES (:channel, :user_id, :mode)
            ON CONFLICT (channel_id, user_id) DO UPDATE SET mode=EXCLUDED.mode
        """), {"channel": data.channel_id, "user_id": user_id, "mode": data.mode})
    return {"channel_id": str(data.channel_id), "mode": data.mode}


async def list_subscriptions(conn, user_id, data):
    rows = (await conn.execute(text("""
        SELECT channel_id, mode FROM channel_subscriptions
        WHERE user_id=:user_id AND (:first OR channel_id > CAST(:cursor AS uuid))
        ORDER BY channel_id LIMIT :limit
    """), {"user_id": user_id, "first": data.cursor is None, "cursor": data.cursor,
           "limit": data.limit + 1})).mappings().all()
    scanned = rows[:data.limit]
    items = []
    for row in scanned:
        try:
            channel, role = await _scope(conn, user_id, row["channel_id"])
        except Denied:
            continue
        if policy.allows(role, policy.ChannelKind(channel["kind"]), policy.Permission.SUBSCRIBE):
            items.append({"channel_id": str(row["channel_id"]), "mode": row["mode"]})
    return {
        "items": items,
        "next_cursor": str(scanned[-1]["channel_id"]) if len(rows) > data.limit else None,
    }
