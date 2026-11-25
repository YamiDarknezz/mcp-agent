"""Channel policy. Callers supply state loaded from trusted server storage."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum


class Role(StrEnum):
    READER = "reader"
    COLLABORATOR = "collaborator"
    ADMIN = "admin"
    OWNER = "owner"


class ChannelKind(StrEnum):
    PROJECT = "project"
    MAIN = "main"
    WORK = "work"


class Permission(StrEnum):
    VIEW = "view"
    SUBSCRIBE = "subscribe"
    READ_MESSAGES = "read_messages"
    READ_HISTORY = "read_history"
    READ_TASKS = "read_tasks"
    DOWNLOAD_FILE = "download_file"
    DOWNLOAD_HISTORICAL_FILE = "download_historical_file"
    POST_MESSAGE = "post_message"
    PROPOSE_TASK = "propose_task"
    CLAIM_TASK = "claim_task"
    UPLOAD_FILE = "upload_file"
    CREATE_SUBCHANNEL = "create_subchannel"
    INVITE = "invite"
    MANAGE_MEMBERSHIPS = "manage_memberships"
    SHARE_HISTORY = "share_history"
    SHARE_HISTORICAL_FILES = "share_historical_files"
    ARCHIVE_SCOPE = "archive_scope"


@dataclass(frozen=True, slots=True)
class Channel:
    """A node in a single project's tree. The project's ID is its root ID."""

    project_id: str
    kind: ChannelKind
    parent_id: str | None = None
    inherits_access: bool = True


_READ = frozenset(
    {
        Permission.VIEW,
        Permission.SUBSCRIBE,
        Permission.READ_MESSAGES,
        Permission.READ_HISTORY,
        Permission.READ_TASKS,
        Permission.DOWNLOAD_FILE,
        Permission.DOWNLOAD_HISTORICAL_FILE,
    }
)
_WRITE = frozenset(
    {
        Permission.POST_MESSAGE,
        Permission.PROPOSE_TASK,
        Permission.CLAIM_TASK,
        Permission.UPLOAD_FILE,
    }
)
_ADMIN = frozenset(
    {
        Permission.CREATE_SUBCHANNEL,
        Permission.INVITE,
        Permission.MANAGE_MEMBERSHIPS,
        Permission.SHARE_HISTORY,
        Permission.SHARE_HISTORICAL_FILES,
    }
)
_ROLE_PERMISSIONS = {
    Role.READER: _READ,
    Role.COLLABORATOR: _READ | _WRITE,
    Role.ADMIN: _READ | _WRITE | _ADMIN,
    Role.OWNER: _READ | _WRITE | _ADMIN | {Permission.ARCHIVE_SCOPE},
}
_PROJECT_PERMISSIONS = frozenset(
    {
        Permission.VIEW,
        Permission.CREATE_SUBCHANNEL,
        Permission.INVITE,
        Permission.MANAGE_MEMBERSHIPS,
        Permission.ARCHIVE_SCOPE,
    }
)
_MAIN_FORBIDDEN = frozenset({Permission.ARCHIVE_SCOPE, Permission.CREATE_SUBCHANNEL})
_GRANTABLE = {
    Role.ADMIN: frozenset({Role.READER, Role.COLLABORATOR}),
    Role.OWNER: frozenset({Role.READER, Role.COLLABORATOR, Role.ADMIN}),
}


def _lineage(channel_id: str, channels: Mapping[str, Channel]) -> tuple[str, ...]:
    """Return the path to a valid project root, or an empty path on inconsistency."""
    target = channels.get(channel_id)
    if target is None:
        return ()

    current_id = channel_id
    seen: set[str] = set()
    path: list[str] = []
    while current_id not in seen:
        channel = channels.get(current_id)
        if channel is None or channel.project_id != target.project_id:
            return ()
        seen.add(current_id)
        path.append(current_id)

        if channel.kind is ChannelKind.PROJECT:
            if current_id == target.project_id and channel.parent_id is None:
                return tuple(path)
            return ()

        if current_id == target.project_id or channel.parent_id is None:
            return ()
        parent = channels.get(channel.parent_id)
        if parent is None or parent.kind is ChannelKind.MAIN:
            return ()
        if channel.kind is ChannelKind.MAIN:
            if parent.kind is not ChannelKind.PROJECT or not channel.inherits_access:
                return ()
        elif channel.kind is not ChannelKind.WORK:
            return ()
        current_id = channel.parent_id

    return ()


def effective_role(
    channel_id: str,
    channels: Mapping[str, Channel],
    memberships: Mapping[str, Role | None],
) -> Role | None:
    """Resolve one user's nearest grant. An explicit None blocks inheritance."""
    for scope_id in _lineage(channel_id, channels):
        scope = channels[scope_id]
        if scope_id in memberships:
            role = memberships[scope_id]
            if not isinstance(role, Role):
                return None
            if role is Role.OWNER and scope.kind is not ChannelKind.PROJECT:
                if scope.kind is not ChannelKind.WORK or scope.inherits_access:
                    return None
            return role
        if not scope.inherits_access:
            return None
    return None


def allows(
    role: Role | None,
    kind: ChannelKind,
    permission: Permission,
    *,
    has_historical_file_grant: bool = False,
) -> bool:
    """Check a role and scope. This does not authorize a device or release keys."""
    if not isinstance(role, Role) or not isinstance(permission, Permission):
        return False
    if permission not in _ROLE_PERMISSIONS[role]:
        return False
    if kind is ChannelKind.PROJECT:
        return permission in _PROJECT_PERMISSIONS
    if kind is ChannelKind.MAIN:
        if permission in _MAIN_FORBIDDEN:
            return False
    elif kind is not ChannelKind.WORK:
        return False
    if permission is Permission.DOWNLOAD_HISTORICAL_FILE:
        return has_historical_file_grant
    return True


def can_invite(
    actor_role: Role | None, kind: ChannelKind, invited_role: Role
) -> bool:
    """Check the role limit at the exact target scope, using the actor's effective role."""
    if not isinstance(invited_role, Role):
        return False
    if actor_role is None or not allows(actor_role, kind, Permission.INVITE):
        return False
    return invited_role in _GRANTABLE[actor_role]


def can_change_membership(
    actor_role: Role | None,
    kind: ChannelKind,
    *,
    current_role: Role | None,
    desired_role: Role | None,
) -> bool:
    """Authorize a grant or withdrawal; normal edits never assign/remove ownership.

    The target's current effective role is taken before the change. A withdrawal
    writes a scoped block (None) instead of exposing a parent grant again.
    """
    if actor_role is None or not allows(actor_role, kind, Permission.MANAGE_MEMBERSHIPS):
        return False
    grantable = _GRANTABLE[actor_role]
    return all(
        role is None or (isinstance(role, Role) and role in grantable)
        for role in (current_role, desired_role)
    )
