"""Internal channel announcements carried by ordinary encrypted messages.

An announcement only informs: it never grants access, forces a subscription
or starts an agent turn. It uses `main` as transport, so the existing bridge
syncs it even when the announced channel is not yet followed.
"""

if __package__:
    from . import relay_announcement_format as announcement_format
    from . import relay_messages
    from .relay_identity import DeviceVault, IdentityError
    from .relay_workspace import list_projects, _call
else:
    import relay_announcement_format as announcement_format
    import relay_messages
    from relay_identity import DeviceVault, IdentityError
    from relay_workspace import list_projects, _call


def main_channel(origin: str) -> str:
    """Find the `main` subchannel of the first visible project."""
    for project in list_projects(origin, 10)["items"]:
        channels = _call(origin, "/v1/workspace/list-channels",
                         {"project_id": project["id"], "limit": 100})["items"]
        for channel in channels:
            if channel["kind"] == "main":
                return channel["id"]
    raise IdentityError("No hay un canal main visible para anuncios.")


def announce(origin: str, announced_channel_id: str, note: str = "", via: str | None = None) -> dict:
    try:
        content = announcement_format.encode(announced_channel_id, note)
    except (ValueError, TypeError):
        raise IdentityError("Anuncio inválido.") from None
    transport = via or main_channel(origin)
    return relay_messages.send(origin, transport, content)


def list_announcements(origin: str, after: int = 0, limit: int = 10, via: str | None = None) -> dict:
    """Read the local inbox and return only valid, deduplicated announcements."""
    device = DeviceVault(origin).load()
    if device is None:
        raise IdentityError("Esta laptop no está registrada en Relay.")
    transport = via or main_channel(origin)
    inbox = relay_messages.read_inbox(origin, transport, after, limit)
    seen = {}
    for message in inbox["messages"]:
        try:
            parsed = announcement_format.decode(message["content"])
        except ValueError:
            parsed = None
        if not parsed:
            continue
        key = (message["device_id"], parsed["channel_id"])
        current = seen.get(key)
        if current is None or message["seq"] > current["seq"]:
            version = parsed.get("version", 1)
            warning = None
            if version == 1:
                warning = "legacy"
            elif version > announcement_format.CLIENT_VERSION:
                warning = "remote_newer"
            seen[key] = {
                "seq": message["seq"],
                "operation_id": message["operation_id"],
                "device_id": message["device_id"],
                "channel_id": parsed["channel_id"],
                "note": parsed["note"],
                "version": version,
                "warning": warning,
            }
    return {
        "announcements": sorted(seen.values(), key=lambda item: item["seq"]),
        "cursor": inbox["cursor"],
        "client_version": announcement_format.CLIENT_VERSION,
    }
