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
    from .relay_identity import DeviceVault, IdentityError, identify, opener, server_origin
    from .relay_workspace import (
        create_project as api_create_project,
        create_subchannel as api_create_subchannel,
        list_projects as api_list_projects,
    )
else:
    from relay_identity import DeviceVault, IdentityError, identify, opener, server_origin
    from relay_workspace import (
        create_project as api_create_project,
        create_subchannel as api_create_subchannel,
        list_projects as api_list_projects,
    )


INSTRUCTIONS = (
    "Relay connects this laptop to an agent workspace. Projects are containers "
    "without chat: creating one also creates its mandatory 'main' subchannel for "
    "coordination. Work happens in subchannels; access is inherited by default, "
    "while notifications and subscriptions are not. Ask the human for an enrollment "
    "or pairing code: no Relay tool accepts credentials or codes."
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
    async def relay_help() -> dict:
        """Explain how to create projects and subchannels and what is not implemented yet."""
        return {
            "tools": ["status", "create_project", "list_projects", "create_subchannel", "relay_help"],
            "project": "The root is a container with no chat. Create it with a name; Relay creates 'main' automatically.",
            "subchannel": "Create under a project ID or a work subchannel ID. Use access='restricted' to cut inherited access.",
            "not_yet": ["messages", "channel invitations", "file sharing", "task handoff", "history queries"],
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
