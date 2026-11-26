"""Relay MCP tools. Credentials and enrollment codes never enter a tool call."""

import asyncio
from http.client import HTTPException
import json
import os
from typing import Literal, TypedDict
from urllib.error import HTTPError
from urllib.request import Request

from mcp.server.fastmcp import FastMCP

if __package__:
    from .relay_messages import send as api_send_message, read as api_read_messages, retry_pending as api_retry_pending
    from .relay_identity import DeviceVault, IdentityError, identify, opener, server_origin
    from .relay_workspace import (
        create_project as api_create_project,
        create_subchannel as api_create_subchannel,
        list_projects as api_list_projects,
    )
    from .relay_keys import (
        decrypt as api_decrypt,
        encrypt as api_encrypt,
        has_local_key,
        list_devices as api_list_devices,
        public_device_fingerprint,
        load as api_load_key,
        setup as api_setup_encryption,
        share as api_share_key,
    )
else:
    from relay_messages import send as api_send_message, read as api_read_messages, retry_pending as api_retry_pending
    from relay_identity import DeviceVault, IdentityError, identify, opener, server_origin
    from relay_workspace import (
        create_project as api_create_project,
        create_subchannel as api_create_subchannel,
        list_projects as api_list_projects,
    )
    from relay_keys import (
        decrypt as api_decrypt,
        encrypt as api_encrypt,
        has_local_key,
        list_devices as api_list_devices,
        public_device_fingerprint,
        load as api_load_key,
        setup as api_setup_encryption,
        share as api_share_key,
    )


INSTRUCTIONS = (
    "Relay connects this laptop to an agent workspace. Projects are containers "
    "without chat: creating one also creates its mandatory 'main' subchannel for "
    "coordination. Work happens in subchannels; access is inherited by default, "
    "while notifications and subscriptions are not. Experimental messages are encrypted "
    "locally, but key distribution does not yet resist an active server. Use test data only. "
    "Run setup_encryption once per device, then "
    "share_channel_key and load_channel_key for each channel. Ask the human for an "
    "enrollment or pairing code: no Relay tool accepts credentials or codes."
)


class RelayStatus(TypedDict):
    origin: str
    healthy: bool
    ready: bool
    enrollment: Literal["registered", "unregistered", "rejected", "unavailable"]
    is_operator: bool


class ErrorResult(TypedDict):
    error: str


def _probe(origin: str, path: str, expected: str) -> bool:
    req = Request(f"{origin}/{path}", headers={"Accept": "application/json"})
    try:
        with opener().open(req, timeout=3) as response:
            body = response.read(1025)
            if response.status != 200 or len(body) > 1024:
                return False
            payload = json.loads(body)
            return isinstance(payload, dict) and payload.get("status") == expected
    except HTTPError as error:
        error.close()
        return False
    except (OSError, HTTPException, ValueError):
        return False


def _enrollment(origin):
    try:
        key = DeviceVault(origin).load()
        if not key:
            return "unregistered", False
        return "registered", identify(origin, key)["is_operator"]
    except IdentityError as error:
        return ("rejected" if error.status == 401 else "unavailable"), False


def _safe(origin, action):
    try:
        return action()
    except IdentityError as error:
        return {"error": str(error)}


def create_server(origin: str) -> FastMCP:
    origin = server_origin(origin)
    mcp = FastMCP("Relay", instructions=INSTRUCTIONS)

    @mcp.tool()
    async def status() -> RelayStatus:
        """Check Relay health and this laptop's registration. No credentials are returned."""
        healthy, ready, (enrollment, operator) = await asyncio.gather(
            asyncio.to_thread(_probe, origin, "health", "ok"),
            asyncio.to_thread(_probe, origin, "ready", "ready"),
            asyncio.to_thread(_enrollment, origin),
        )
        return {
            "origin": origin, "healthy": healthy, "ready": ready,
            "enrollment": enrollment, "is_operator": operator,
        }

    @mcp.tool()
    async def create_project(name: str, slug: str | None = None) -> dict:
        """Create a project container and its mandatory 'main' coordination subchannel."""
        return await asyncio.to_thread(
            _safe, origin, lambda: api_create_project(origin, name, slug),
        )

    @mcp.tool()
    async def list_projects(limit: int = 50, cursor: str | None = None) -> dict:
        """List the projects this laptop's account can see, newest first, paginated."""
        if not 1 <= limit <= 100:
            return {"error": "limit must be between 1 and 100"}
        return await asyncio.to_thread(
            _safe, origin, lambda: api_list_projects(origin, limit, cursor),
        )

    @mcp.tool()
    async def create_subchannel(
        parent_id: str, name: str, slug: str | None = None, access: str = "inherit"
    ) -> dict:
        """Create a work subchannel under a visible project or subchannel, not under 'main'."""
        if access not in {"inherit", "restricted"}:
            return {"error": "access must be inherit or restricted"}
        return await asyncio.to_thread(
            _safe, origin, lambda: api_create_subchannel(origin, parent_id, name, slug, access),
        )

    @mcp.tool()
    async def setup_encryption() -> dict:
        """Publish this device's signed encryption key. Run once per laptop. No secret is returned."""
        return await asyncio.to_thread(_safe, origin, lambda: api_setup_encryption(origin))

    @mcp.tool()
    async def encryption_status(channel_id: str | None = None) -> dict:
        """List device fingerprints for out-of-band comparison and whether a channel key is local."""
        def action():
            devices = api_list_devices(origin)["devices"]
            return {
                "devices": [
                    {"id": d["id"], "label": d["label"],
                     "fingerprint": public_device_fingerprint(d, origin) if d.get("encryption_key") else None}
                    for d in devices
                ],
                "channel_key_local": (
                    has_local_key(origin, channel_id) if channel_id else None
                ),
                "compare_fingerprints": (
                    "Compare these values with the other laptop by voice or another trusted channel."
                ),
            }
        return await asyncio.to_thread(_safe, origin, action)

    @mcp.tool()
    async def share_channel_key(
        channel_id: str, device_ids: list[str] | None = None, key_id: str | None = None
    ) -> dict:
        """Wrap a channel key for devices. Pass key_id to add recipients without rotating."""
        return await asyncio.to_thread(
            _safe, origin, lambda: api_share_key(origin, channel_id, device_ids, key_id),
        )

    @mcp.tool()
    async def load_channel_key(channel_id: str) -> dict:
        """Verify the pinned sender and signed envelope before loading a channel key."""
        return await asyncio.to_thread(_safe, origin, lambda: api_load_key(origin, channel_id))

    @mcp.tool()
    async def crypto_selftest(channel_id: str, text: str = "prueba cifrada") -> dict:
        """Verify that a message can be encrypted and decrypted locally without leaking plaintext."""
        def action():
            if not has_local_key(origin, channel_id):
                return {"error": "This laptop does not hold the channel key yet."}
            payload = api_encrypt(origin, channel_id, 1, text.encode("utf-8"))
            leaked = text in str(payload)
            recovered = api_decrypt(
                origin, channel_id, 1, payload["nonce"], payload["ciphertext"]
            ).decode("utf-8")
            return {
                "roundtrip": recovered == text,
                "ciphertext_contains_plaintext": leaked,
                "channel_id": channel_id,
            }
        return await asyncio.to_thread(_safe, origin, action)

    @mcp.tool()
    async def send_message(channel_id: str, content: str) -> dict:
        """Queue and send a test message encrypted locally; pending messages can be retried."""
        return await asyncio.to_thread(_safe, origin, lambda: api_send_message(origin, channel_id, content))

    @mcp.tool()
    async def retry_messages() -> dict:
        """Retry encrypted messages retained on this device, preserving their operation IDs."""
        return await asyncio.to_thread(_safe, origin, lambda: api_retry_pending(origin))

    @mcp.tool()
    async def read_messages(channel_id: str, after: int = 0, limit: int = 10) -> dict:
        """Read and locally decrypt a page of channel messages after a sequence."""
        if after < 0 or not 1 <= limit <= 10:
            return {"error": "after must be nonnegative and limit must be between 1 and 10"}
        return await asyncio.to_thread(_safe, origin, lambda: api_read_messages(origin, channel_id, after, limit))

    @mcp.tool()
    async def relay_help() -> dict:
        """Explain how to create projects, channels and shared keys, and what is not implemented yet."""
        return {
            "tools": [
                "status", "create_project", "list_projects", "create_subchannel",
                "setup_encryption", "encryption_status", "share_channel_key",
                "load_channel_key", "crypto_selftest", "send_message", "read_messages", "retry_messages", "relay_help",
            ],
            "project": "The root is a container with no chat. Create it with a name; Relay creates 'main' automatically.",
            "subchannel": "Create under a project ID or a work subchannel ID. Use access='restricted' to cut inherited access.",
            "encryption": "Run setup_encryption once, compare fingerprints with the other laptop, then share_channel_key and load_channel_key per channel.",
            "not_yet": ["live delivery", "automatic retries", "channel invitations", "file sharing", "task handoff"],
            "enrollment": "Ask the human to use relayctl in a private terminal; never paste a code into a tool call.",
        }

    return mcp


if __name__ == "__main__":
    try:
        origin = server_origin(os.getenv("MCP_AGENT_SERVER_URL"))
    except ValueError:
        raise SystemExit(
            "Set MCP_AGENT_SERVER_URL to an HTTPS origin without credentials."
        ) from None
    create_server(origin).run(transport="stdio")
