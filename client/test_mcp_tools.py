"""Verify the MCP tool catalog that agents discover on first connect."""

import asyncio
import json
from pathlib import Path
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

EXPECTED = {
    "status", "create_project", "list_projects", "create_subchannel", "set_subscription", "list_subscriptions",
    "setup_encryption", "encryption_status", "share_channel_key",
    "load_channel_key", "crypto_selftest", "send_message", "read_messages", "retry_messages", "read_inbox", "my_identity", "list_alerts", "relay_help",
}


async def verify():
    origin = "https://relay.example.invalid"
    server = StdioServerParameters(
        command=sys.executable,
        args=[str(Path(__file__).with_name("relay_mcp.py").resolve())],
        env={"MCP_AGENT_SERVER_URL": origin},
    )
    async with asyncio.timeout(25):
        async with stdio_client(server) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                assert "workspace" in (init.instructions or "").lower()
                tools = (await session.list_tools()).tools
                assert {tool.name for tool in tools} == EXPECTED
                assert all(tool.description for tool in tools)
                result = await session.call_tool("relay_help", {})
                assert not result.isError
                payload = result.structuredContent or json.loads(result.content[0].text)
                assert "invitations" in str(payload["not_yet"])
                # Each tool must call its API function, not recurse into the tool itself.
                created = await session.call_tool("create_project", {"name": "Tesis"})
                assert not created.isError
                outcome = created.structuredContent or json.loads(created.content[0].text)
                assert "error" in outcome and "recursion" not in str(outcome).lower()
                listed = await session.call_tool("list_projects", {})
                assert not listed.isError
                enc = await session.call_tool("encryption_status", {})
                assert not enc.isError
    print("Relay MCP exposes:", ", ".join(sorted(EXPECTED)))


if __name__ == "__main__":
    asyncio.run(verify())
