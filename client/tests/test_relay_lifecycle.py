import asyncio
import unittest
from unittest.mock import patch

from client import relay_mcp


class LifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_mcp_lifespan_starts_and_stops_bridge_without_blocking(self):
        started = asyncio.Event()
        stopped = asyncio.Event()

        async def bridge(_origin, state):
            state.status = "running"
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                state.status = "stopped"
                stopped.set()

        with patch.object(relay_mcp, "run_owned_bridge", side_effect=bridge):
            mcp = relay_mcp.create_server("https://relay.example")
            async with mcp._mcp_server.lifespan(mcp._mcp_server):
                await asyncio.wait_for(started.wait(), 3)
                self.assertFalse(stopped.is_set())
            self.assertTrue(stopped.is_set())


if __name__ == "__main__":
    unittest.main()
