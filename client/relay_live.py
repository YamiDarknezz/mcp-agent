"""Optional long-running local bridge. Never starts or interrupts an agent."""

import argparse
import asyncio
import json
import os

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

if __package__:
    from .relay_identity import DeviceVault, IdentityError, server_origin
    from .relay_inbox import Inbox
    from .relay_messages import retry_pending
    from .relay_workspace import _call
else:
    from relay_identity import DeviceVault, IdentityError, server_origin
    from relay_inbox import Inbox
    from relay_messages import retry_pending
    from relay_workspace import _call


def synchronize(origin, channel_id):
    device = DeviceVault(origin).load()
    if device is None:
        raise IdentityError("Esta laptop no está registrada en Relay.")
    inbox = Inbox(origin, device.device_id)
    while True:
        cursor = inbox.cursor(channel_id)
        page = _call(origin, "/v1/workspace/read-messages",
                     {"channel_id": channel_id, "after": cursor, "limit": 10})["messages"]
        if not page:
            return
        if not inbox.append(channel_id, cursor, page):
            continue
        if len(page) < 10:
            return


async def run(origin, channel_id):
    uri = ("wss://" + origin[8:] if origin.startswith("https://") else "ws://" + origin[7:]) + "/v1/live"
    async for socket in connect(uri, max_size=8192, open_timeout=10, proxy=None):
        try:
            device = DeviceVault(origin).load()
            if device is None:
                raise IdentityError("Esta laptop no está registrada en Relay.")
            await socket.send(json.dumps({
                "device_id": device.device_id, "channel_id": channel_id,
                "proof": device.proof(origin, "workspace"),
            }))
            async for frame in socket:
                event = json.loads(frame)
                if event.get("type") not in {"ready", "changed", "reconcile"}:
                    raise ValueError("Invalid Relay live event.")
                await asyncio.to_thread(synchronize, origin, channel_id)
                await asyncio.to_thread(retry_pending, origin)
        except ConnectionClosed as error:
            if error.rcvd and error.rcvd.code == 1008:
                raise IdentityError("Relay rechazó el dispositivo o su acceso al canal.") from None
        except IdentityError as error:
            if error.status in {401, 403, 404}:
                raise
            await asyncio.sleep(1)


def main():
    parser = argparse.ArgumentParser(description="Experimental Relay live bridge.")
    parser.add_argument("--server", default=os.getenv("MCP_AGENT_SERVER_URL"))
    parser.add_argument("--channel", required=True)
    args = parser.parse_args()
    asyncio.run(run(server_origin(args.server), args.channel))


if __name__ == "__main__":
    main()
