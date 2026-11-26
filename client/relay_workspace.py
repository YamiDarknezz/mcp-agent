"""Local-to-Relay workspace calls. Only this module sends signed device proofs."""

from typing import Any, TypedDict

if __package__:
    from .relay_identity import DeviceVault, IdentityError, request_json
else:
    from relay_identity import DeviceVault, IdentityError, request_json


class ChannelCard(TypedDict):
    id: str
    name: str
    slug: str
    kind: str
    role: str
    inherits_access: bool
    project_id: str
    parent_id: str | None


class Page(TypedDict):
    items: list[ChannelCard]
    next_cursor: str | None


class WorkspaceResult(TypedDict, total=False):
    error: str


def _signed(origin: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    key = DeviceVault(origin).load()
    if key is None:
        return None
    return {**payload, "device_id": key.device_id, "proof": key.proof(origin, "workspace")}


def _call(origin: str, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    body = _signed(origin, payload)
    if body is None:
        raise IdentityError("Esta laptop no está registrada en Relay.")
    try:
        return request_json(origin, path, body, max_bytes=65536)
    except IdentityError as error:
        if error.status in {401, 403}:
            raise IdentityError("La identidad local no tiene acceso a Relay.", error.status) from None
        raise


def create_project(origin: str, name: str, slug: str | None = None) -> dict[str, Any]:
    payload = {"name": name}
    if slug is not None:
        payload["slug"] = slug
    return _call(origin, "/v1/workspace/projects", payload)


def create_subchannel(
    origin: str, parent_id: str, name: str, slug: str | None = None, access: str = "inherit"
) -> dict[str, Any]:
    payload = {"parent_id": parent_id, "name": name, "access": access}
    if slug is not None:
        payload["slug"] = slug
    return _call(origin, "/v1/workspace/subchannels", payload)


def list_projects(origin: str, limit: int = 50, cursor: str | None = None) -> Page:
    payload: dict[str, Any] = {"limit": limit}
    if cursor:
        payload["cursor"] = cursor
    return _call(origin, "/v1/workspace/list-projects", payload)


def set_subscription(origin: str, channel_id: str, mode: str | None) -> dict[str, Any]:
    return _call(origin, "/v1/workspace/set-subscription", {"channel_id": channel_id, "mode": mode})


def list_subscriptions(origin: str, limit: int = 100, cursor: str | None = None) -> dict[str, Any]:
    return _call(origin, "/v1/workspace/list-subscriptions", {"limit": limit, "cursor": cursor})
