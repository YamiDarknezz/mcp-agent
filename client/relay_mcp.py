"""Relay MCP health and enrollment status; no tool accepts or returns credentials."""

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
else:
    from relay_identity import DeviceVault, IdentityError, identify, opener, server_origin


class RelayStatus(TypedDict):
    origin: str
    healthy: bool
    ready: bool
    enrollment: Literal["registered", "unregistered", "rejected", "unavailable"]
    is_operator: bool


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


def create_server(origin: str) -> FastMCP:
    origin = server_origin(origin)
    mcp = FastMCP("Relay")

    @mcp.tool()
    async def status() -> RelayStatus:
        """Check Relay service health and this laptop's registration. No credentials are returned."""
        healthy, ready, (enrollment, operator) = await asyncio.gather(
            asyncio.to_thread(_probe, origin, "health", "ok"),
            asyncio.to_thread(_probe, origin, "ready", "ready"),
            asyncio.to_thread(_enrollment, origin),
        )
        return {
            "origin": origin, "healthy": healthy, "ready": ready,
            "enrollment": enrollment, "is_operator": operator,
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
