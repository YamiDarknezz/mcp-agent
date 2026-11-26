"""Client and protocol version markers for cross-laptop compatibility warnings."""

CLIENT_VERSION = "0.2.0"
PROTOCOL_VERSION = 4


def _parts(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split(".") if part.isdigit())


def is_older(remote: str, local: str = CLIENT_VERSION) -> bool:
    """Return True when the remote client reports a lower version than ours."""
    try:
        remote_parts, local_parts = _parts(remote), _parts(local)
    except ValueError:
        return False
    return bool(remote_parts) and remote_parts < local_parts


def warning(remote: str, local: str = CLIENT_VERSION) -> str | None:
    if not is_older(remote, local):
        return None
    return (
        f"El otro extremo usa cliente {remote} y este usa {local}; "
        "actualiza ese cliente para interpretar los formatos nuevos."
    )
