"""Authenticated WebSocket hints; PostgreSQL remains the durable source."""

import asyncio
import contextlib
import json
from collections import defaultdict
from uuid import UUID

import psycopg
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy.exc import SQLAlchemyError

from server import authorization as policy, identity, messages, settings

router = APIRouter()


class NotificationHub:
    def __init__(self):
        self.subscribers = defaultdict(set)
        self.ready = asyncio.Event()

    def subscribe(self, channel):
        queue = asyncio.Queue(maxsize=1)
        self.subscribers[channel].add(queue)
        return queue

    def unsubscribe(self, channel, queue):
        self.subscribers[channel].discard(queue)
        if not self.subscribers[channel]:
            self.subscribers.pop(channel, None)

    def notify(self, channel):
        for queue in tuple(self.subscribers.get(channel, ())):
            if not queue.full():
                queue.put_nowait(None)

    async def run(self):
        # Notifications are hints; reconnection clients reconcile from PostgreSQL.
        dsn = settings.database_url().set(drivername="postgresql").render_as_string(hide_password=False)
        while True:
            try:
                async with await psycopg.AsyncConnection.connect(dsn, autocommit=True) as conn:
                    await conn.execute("LISTEN relay_messages")
                    self.ready.set()
                    async for notification in conn.notifies():
                        self.notify(notification.payload)
            except (OSError, psycopg.Error):
                self.ready.clear()
                await asyncio.sleep(1)


@router.websocket("/v1/live")
async def live_socket(websocket: WebSocket):
    await websocket.accept()
    queue = None
    receive_task = None
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=5)
        if len(raw) > 8192:
            await websocket.close(code=1009)
            return
        body = json.loads(raw)
        device_id = UUID(body["device_id"])
        channel_id = UUID(body["channel_id"])
        proof = body["proof"]
        if device_id.version != 4 or channel_id.version != 4 or not isinstance(proof, str) or len(proof) > 3500:
            raise ValueError
        async with websocket.app.state.engine.begin() as conn:
            summary = await identity.authenticate_workspace(conn, device_id, proof, websocket.app.state.public_url)
            await messages._access(conn, summary["account_id"], channel_id, policy.Permission.READ_MESSAGES)
        channel = str(channel_id)
        hub = websocket.app.state.notification_hub
        await asyncio.wait_for(hub.ready.wait(), timeout=5)
        queue = hub.subscribe(channel)
        # Client must always reconcile after this frame to close the LISTEN/read race.
        await asyncio.wait_for(websocket.send_json({"type": "ready"}), timeout=5)
        receive_task = asyncio.create_task(websocket.receive())
        while True:
            try:
                await asyncio.wait_for(queue.get(), timeout=5)
                hint = True
            except TimeoutError:
                hint = False
            if receive_task.done():
                break
            async with websocket.app.state.engine.begin() as conn:
                device = await identity._device(conn, device_id)
                if str(device["user_id"]) != summary["account_id"]:
                    raise identity.Denied(401)
                await messages._access(conn, summary["account_id"], channel_id, policy.Permission.READ_MESSAGES)
            await asyncio.wait_for(websocket.send_json({"type": "changed" if hint else "reconcile"}), timeout=5)
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, identity.Denied):
        with contextlib.suppress(RuntimeError):
            await websocket.close(code=1008)
    except (WebSocketDisconnect, OSError, SQLAlchemyError, TimeoutError):
        pass
    finally:
        if receive_task:
            receive_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, WebSocketDisconnect):
                await receive_task
        if queue is not None:
            hub.unsubscribe(channel, queue)
