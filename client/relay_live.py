"""Optional long-running local bridge. Never starts or interrupts an agent."""

import argparse
import asyncio
import json
import os

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

SUBSCRIPTION_REFRESH_SECONDS = 10

if __package__:
    from .relay_identity import DeviceVault, IdentityError, server_origin
    from .relay_inbox import Inbox
    from .relay_messages import retry_pending
    from .relay_workspace import _call
    from .relay_workspace import list_subscriptions
else:
    from relay_identity import DeviceVault, IdentityError, server_origin
    from relay_inbox import Inbox
    from relay_messages import retry_pending
    from relay_workspace import _call
    from relay_workspace import list_subscriptions


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


def subscribed_channels(origin):
    channels = {}
    cursor = None
    while True:
        page = list_subscriptions(origin, 100, cursor)
        for item in page["items"]:
            channels[item["channel_id"]] = item["mode"]
        if len(channels) > 100:
            raise IdentityError("El puente admite hasta 100 canales seguidos.")
        next_cursor = page["next_cursor"]
        if not next_cursor:
            return channels
        if next_cursor == cursor:
            raise IdentityError("La paginación de suscripciones no avanzó.")
        cursor = next_cursor


async def run_subscriptions(origin):
    tasks = {}
    try:
        while True:
            try:
                channels = await asyncio.to_thread(subscribed_channels, origin)
            except IdentityError as error:
                if error.status in {401, 403}:
                    raise
                await asyncio.sleep(SUBSCRIPTION_REFRESH_SECONDS)
                continue
            # A muted or mentions-only channel still synchronizes its encrypted
            # inbox. User-facing alerts are a separate, not-yet-built feature.
            for channel, task in list(tasks.items()):
                if channel not in channels or task.done():
                    if not task.done():
                        task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    del tasks[channel]
            for channel in channels:
                if channel not in tasks:
                    tasks[channel] = asyncio.create_task(run(origin, channel))
            await asyncio.sleep(SUBSCRIPTION_REFRESH_SECONDS)
    finally:
        for task in tasks.values():
            task.cancel()
        await asyncio.gather(*tasks.values(), return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description="Experimental Relay live bridge.")
    parser.add_argument("--server", default=os.getenv("MCP_AGENT_SERVER_URL"))
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--channel")
    selection.add_argument("--subscriptions", action="store_true")
    args = parser.parse_args()
    origin = server_origin(args.server)
    asyncio.run(run_subscriptions(origin) if args.subscriptions else run(origin, args.channel))


if __name__ == "__main__":
    main()
