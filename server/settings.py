"""Load deployment settings without echoing secret values."""

import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError

POSTGRES_MAJOR = 18


class ConfigurationError(RuntimeError):
    pass


def _value(name: str) -> str | None:
    value = os.getenv(name) or None
    path = os.getenv(f"{name}_FILE") or None
    if value and path:
        raise ConfigurationError(f"Use either {name} or {name}_FILE.")
    if path:
        try:
            value = Path(path).read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            raise ConfigurationError(f"Could not read {name}_FILE.") from None
    return value


def database_url() -> URL:
    value = _value("DATABASE_URL")
    if not value:
        raise ConfigurationError("DATABASE_URL or DATABASE_URL_FILE is required.")
    try:
        url = make_url(value)
    except (ArgumentError, ValueError):
        raise ConfigurationError("Invalid PostgreSQL URL.") from None
    if url.drivername not in {"postgresql", "postgresql+psycopg"} or not url.database:
        raise ConfigurationError("A PostgreSQL URL with a database name is required.")
    return url.set(drivername="postgresql+psycopg")


def redis_url() -> str | None:
    value = _value("REDIS_URL")
    if value:
        try:
            parts = urlsplit(value)
            if parts.scheme not in {"redis", "rediss"} or not parts.hostname or parts.fragment:
                raise ValueError
            _ = parts.port
        except ValueError:
            raise ConfigurationError("Invalid Redis URL.") from None
    return value or None


def deployment_mode() -> str:
    mode = os.getenv("MCP_ENV", "development")
    if mode not in {"development", "production"}:
        raise ConfigurationError("Invalid MCP_ENV.")
    return mode


def enrollment_code_ttl() -> int:
    try:
        value = int(os.getenv("MCP_ENROLLMENT_TTL_SECONDS", "900"))
    except ValueError:
        raise ConfigurationError("Invalid enrollment code lifetime.") from None
    if not 60 <= value <= 3600:
        raise ConfigurationError("Enrollment code lifetime must be between 60 and 3600 seconds.")
    return value


def runtime_db_role() -> str | None:
    role = os.getenv("MCP_RUNTIME_DB_ROLE") or None
    if role and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", role):
        raise ConfigurationError("Invalid MCP_RUNTIME_DB_ROLE.")
    return role


def public_url() -> str:
    mode = deployment_mode()
    value = os.getenv("MCP_PUBLIC_URL")
    if not value and mode == "development":
        value = "http://127.0.0.1:8765"
    try:
        if not value or not value.isascii() or any(
            ord(char) <= 32 or ord(char) == 127 or char in "\\?#" for char in value
        ):
            raise ValueError
        parts = urlsplit(value)
        if not parts.hostname or parts.username is not None or parts.password is not None:
            raise ValueError
        if parts.path not in {"", "/"} or parts.port == 0:
            raise ValueError
        allowed_http = mode == "development" and parts.hostname in {
            "127.0.0.1", "::1", "localhost",
        }
        if parts.scheme != "https" and not (parts.scheme == "http" and allowed_http):
            raise ValueError
    except ValueError:
        raise ConfigurationError(
            "MCP_PUBLIC_URL must be an HTTPS origin (loopback HTTP for development only)."
        ) from None
    return f"{parts.scheme}://{parts.netloc}"
