"""Relay device enrollment client. Private keys live only in the OS vault."""

import base64
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import jwt


class IdentityError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        self.status = status
        super().__init__(message)


def server_origin(value: str | None) -> str:
    if not value or not value.isascii() or any(
        ord(char) <= 32 or ord(char) == 127 or char in "\\?#" for char in value
    ):
        raise ValueError("Expected a clean HTTPS origin (HTTP for loopback only).")
    parts = urlsplit(value)
    loopback = parts.hostname in {"localhost", "127.0.0.1", "::1"}
    if not (
        parts.hostname and parts.username is None and parts.password is None
        and parts.path in {"", "/"} and parts.port != 0
        and (parts.scheme == "https" or (parts.scheme == "http" and loopback))
    ):
        raise ValueError("Expected a clean HTTPS origin (HTTP for loopback only).")
    return f"{parts.scheme}://{parts.netloc}"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def opener():
    return build_opener(ProxyHandler({}), NoRedirect())


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _native_vault():
    if os.name == "nt":
        from keyring.backends.Windows import WinVaultKeyring
        return WinVaultKeyring()
    if sys.platform == "darwin":
        from keyring.backends.macOS import Keyring
        return Keyring()
    if sys.platform.startswith("linux"):
        from keyring.backends.SecretService import Keyring
        return Keyring()
    raise RuntimeError("No supported credential vault.")


@contextmanager
def enrollment_lock(origin):
    """Avoid overwriting a vault key if two local enrollment commands race."""
    if os.name == "nt":
        root = Path(os.getenv("LOCALAPPDATA") or Path.home()) / "Relay"
    else:
        root = Path(os.getenv("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "relay"
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock_path = root / (sha256(origin.encode("ascii")).hexdigest() + ".lock")
        file = os.fdopen(os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600), "r+b")
    except OSError:
        raise IdentityError("The local enrollment lock could not be opened.") from None
    with file:
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise IdentityError("Another enrollment is already running for this server.") from None
        yield


@dataclass(frozen=True, repr=False)
class LocalKey:
    device_id: str
    private: Ed25519PrivateKey

    def proof(self, origin, purpose, **claims):
        now = int(time.time())
        return jwt.encode(
            {
                **claims, "aud": origin, "sub": self.device_id, "purpose": purpose,
                "iat": now, "exp": now + 45, "jti": str(uuid4()),
            },
            self.private, algorithm="EdDSA", headers={"typ": "relay-device+jwt"},
        )


class DeviceVault:
    def __init__(self, origin, backend=None):
        self.service = "Relay device " + sha256(origin.encode("ascii")).hexdigest()
        try:
            self.backend = backend if backend is not None else _native_vault()
        except Exception:
            raise IdentityError("The operating system credential vault is not available.") from None

    def load(self) -> LocalKey | None:
        try:
            encoded = self.backend.get_password(self.service, "device-v1")
            if encoded is None:
                return None
            record = json.loads(encoded)
            device_id = UUID(record["device_id"])
            if device_id.version != 4:
                raise ValueError
            seed = base64.urlsafe_b64decode(record["private_seed"] + "=")
            return LocalKey(str(device_id), Ed25519PrivateKey.from_private_bytes(seed))
        except Exception:
            raise IdentityError("The local device credential could not be read.") from None

    def load_or_create(self) -> LocalKey:
        existing = self.load()
        if existing:
            return existing
        key = LocalKey(str(uuid4()), Ed25519PrivateKey.generate())
        value = json.dumps({"device_id": key.device_id, "private_seed": _b64(key.private.private_bytes_raw())})
        try:
            self.backend.set_password(self.service, "device-v1", value)
            if self.backend.get_password(self.service, "device-v1") != value:
                raise ValueError
        except Exception:
            raise IdentityError("The local device credential could not be saved; no code was consumed.") from None
        return key


def _request(origin, path, payload):
    req = Request(
        origin + path, data=json.dumps(payload).encode(), method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    try:
        with opener().open(req, timeout=9) as response:
            raw = response.read(8193)
            if response.status != 200 or len(raw) > 8192:
                raise ValueError
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ValueError
            return result
    except HTTPError as error:
        error.close()
        raise IdentityError(f"Relay rejected the identity request (HTTP {error.code}).", error.code) from None
    except (OSError, ValueError, HTTPException):
        raise IdentityError("Relay identity service did not return a valid response.") from None


def identify(origin, key):
    result = _request(origin, "/v1/devices/me", {"device_id": key.device_id, "proof": key.proof(origin, "identify")})
    if result.get("device_id") != key.device_id or type(result.get("is_operator")) is not bool:
        raise IdentityError("Invalid device identity response.")
    return result


def enroll(origin, key, code, label, name=None, email=None):
    if not re.fullmatch(r"relay_(?:boot|pair)_[A-Za-z0-9_-]{43}", code):
        raise IdentityError("Invalid enrollment code format.")
    challenge = _request(
        origin, "/v1/enrollment/challenge",
        {"code": code, "device_id": key.device_id, "public_key": _b64(key.private.public_key().public_bytes_raw())},
    ).get("challenge")
    if not isinstance(challenge, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", challenge):
        raise IdentityError("Invalid enrollment challenge.")
    proof = key.proof(
        origin, "enroll", challenge=challenge, device_label=label, display_name=name, declared_email=email,
    )
    _request(origin, "/v1/enrollment/claim", {"code": code, "device_id": key.device_id, "proof": proof})
    return identify(origin, key)


def issue_pair_code(origin, key):
    result = _request(
        origin, "/v1/devices/pair-code",
        {"device_id": key.device_id, "proof": key.proof(origin, "pair")},
    )
    code = result.get("code")
    if not isinstance(code, str) or not re.fullmatch(r"relay_pair_[A-Za-z0-9_-]{43}", code):
        raise IdentityError("Invalid pairing code response.")
    return code
