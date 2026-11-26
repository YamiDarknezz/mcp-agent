import asyncio
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from client.relay_inbox import Inbox
from client import relay_live
from client.relay_identity import IdentityError


def event(seq):
    return {"seq": seq, "operation_id": str(uuid4()), "device_id": str(uuid4()),
            "nonce": "nonce", "ciphertext": "ciphertext", "created_at": "2026-01-01T00:00:00Z"}


class InboxTests(unittest.TestCase):
    def test_store_and_cursor_are_atomic_and_duplicate_replay_is_safe(self):
        with tempfile.TemporaryDirectory() as folder:
            inbox = Inbox("https://example.com", "device", Path(folder) / "inbox.sqlite")
            channel = str(uuid4())
            self.assertEqual(inbox.cursor(channel), 0)
            first = [event(1), event(2)]
            self.assertTrue(inbox.append(channel, 0, first))
            self.assertFalse(inbox.append(channel, 0, first))
            self.assertEqual(inbox.cursor(channel), 2)
            with self.assertRaises(ValueError):
                inbox.append(channel, 2, [event(3), event(5)])
            self.assertEqual(inbox.cursor(channel), 2)
            self.assertEqual(len(inbox.page(channel)), 2)
            self.assertTrue(inbox.append(channel, 2, [event(3)]))
            self.assertEqual(inbox.cursor(channel), 3)

    def test_sync_recovers_from_persisted_cursor_after_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "inbox.sqlite"
            channel = str(uuid4())
            rows = [event(i) for i in range(1, 13)]
            requests = []
            def fetch(_origin, _path, payload):
                requests.append(payload["after"])
                return {"messages": [row for row in rows if row["seq"] > payload["after"]][:10]}
            with patch("client.relay_inbox._state_path", return_value=path), \
                 patch.object(relay_live, "DeviceVault") as vault, \
                 patch.object(relay_live, "_call", side_effect=fetch):
                vault.return_value.load.return_value = SimpleNamespace(device_id=str(uuid4()))
                relay_live.synchronize("https://example.com", channel)
                self.assertEqual(requests, [0, 10])
                rows.append(event(13))
                relay_live.synchronize("https://example.com", channel)
                self.assertEqual(requests[-1], 12)
                inbox = Inbox("https://example.com", "ignored", path)
                self.assertEqual(inbox.cursor(channel), 13)
                self.assertEqual(len(inbox.page(channel, after=10)), 3)

    def test_subscriptions_paginate_without_inheriting_unlisted_channels(self):
        first, second = str(uuid4()), str(uuid4())
        pages = [
            {"items": [{"channel_id": first, "mode": "muted"}], "next_cursor": "next"},
            {"items": [{"channel_id": second, "mode": "mentions"}], "next_cursor": None},
        ]
        with patch.object(relay_live, "list_subscriptions", side_effect=pages) as fetch:
            self.assertEqual(relay_live.subscribed_channels("https://example.com"), {
                first: "muted", second: "mentions",
            })
            self.assertEqual(fetch.call_args_list[1].args[2], "next")

    def test_subscription_pagination_must_advance(self):
        page = {"items": [], "next_cursor": "same"}
        with patch.object(relay_live, "list_subscriptions", return_value=page):
            with self.assertRaises(IdentityError):
                relay_live.subscribed_channels("https://example.com")


class SubscriptionBridgeTests(unittest.IsolatedAsyncioTestCase):
    async def test_outbox_retries_even_when_no_channels_are_followed(self):
        called = asyncio.Event()
        loop = asyncio.get_running_loop()

        def retry(_origin):
            loop.call_soon_threadsafe(called.set)
            return {"sent": [], "pending": False}

        with patch.object(relay_live, "subscribed_channels", return_value={}), \
             patch.object(relay_live, "retry_pending", side_effect=retry):
            task = asyncio.create_task(relay_live.run_subscriptions("https://example.com"))
            try:
                await asyncio.wait_for(called.wait(), 3)
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def test_bridge_follows_and_unfollows_without_affecting_other_tasks(self):
        first, second = str(uuid4()), str(uuid4())
        desired = {first: "all"}
        started_first = asyncio.Event()
        stopped_first = asyncio.Event()
        started_second = asyncio.Event()

        async def worker(_origin, channel):
            if channel == first:
                started_first.set()
            else:
                started_second.set()
            try:
                await asyncio.Event().wait()
            finally:
                if channel == first:
                    stopped_first.set()

        with patch.object(relay_live, "subscribed_channels", side_effect=lambda _origin: dict(desired)), \
             patch.object(relay_live, "retry_pending", return_value={"sent": [], "pending": False}), \
             patch.object(relay_live, "run", side_effect=worker), \
             patch.object(relay_live, "SUBSCRIPTION_REFRESH_SECONDS", 0.01):
            supervisor = asyncio.create_task(relay_live.run_subscriptions("https://example.com"))
            try:
                await asyncio.wait_for(started_first.wait(), 3)
                desired.clear()
                desired[second] = "muted"
                await asyncio.wait_for(stopped_first.wait(), 3)
                await asyncio.wait_for(started_second.wait(), 3)
            finally:
                supervisor.cancel()
                await asyncio.gather(supervisor, return_exceptions=True)

    async def test_owned_bridge_releases_lease_on_cancellation(self):
        started = asyncio.Event()
        stopped = asyncio.Event()
        state = relay_live.BridgeState()
        lease = SimpleNamespace(close=unittest.mock.Mock())

        async def supervisor(_origin):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()

        with patch.object(relay_live, "DeviceVault") as vault, \
             patch.object(relay_live.BridgeLease, "acquire", return_value=lease), \
             patch.object(relay_live, "run_subscriptions", side_effect=supervisor):
            vault.return_value.load.return_value = SimpleNamespace(device_id=str(uuid4()))
            task = asyncio.create_task(relay_live.run_owned_bridge("https://example.com", state))
            await asyncio.wait_for(started.wait(), 3)
            self.assertEqual(state.status, "running")
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            self.assertTrue(stopped.is_set())
            lease.close.assert_called_once()
            self.assertEqual(state.status, "stopped")

    async def test_standby_takes_over_when_owner_exits(self):
        state = relay_live.BridgeState()
        started = asyncio.Event()
        lease = SimpleNamespace(close=unittest.mock.Mock())

        async def supervisor(_origin):
            started.set()
            await asyncio.Event().wait()

        with patch.object(relay_live, "DeviceVault") as vault, \
             patch.object(relay_live.BridgeLease, "acquire", side_effect=[None, lease]), \
             patch.object(relay_live, "SUBSCRIPTION_REFRESH_SECONDS", 0.01), \
             patch.object(relay_live, "run_subscriptions", side_effect=supervisor):
            vault.return_value.load.return_value = SimpleNamespace(device_id=str(uuid4()))
            task = asyncio.create_task(relay_live.run_owned_bridge("https://example.com", state))
            try:
                await asyncio.wait_for(started.wait(), 3)
                self.assertEqual(state.status, "running")
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            lease.close.assert_called_once()


class BridgeLeaseTests(unittest.TestCase):
    def test_same_device_exclusive_and_distinct_devices_independent(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(
            "os.environ", {"LOCALAPPDATA": folder, "XDG_STATE_HOME": folder}
        ):
            first = relay_live.BridgeLease.acquire("https://example.com", "device-a")
            self.assertIsNotNone(first)
            try:
                self.assertIsNone(relay_live.BridgeLease.acquire("https://example.com", "device-a"))
                second = relay_live.BridgeLease.acquire("https://example.com", "device-b")
                self.assertIsNotNone(second)
                second.close()
            finally:
                first.close()
            replacement = relay_live.BridgeLease.acquire("https://example.com", "device-a")
            self.assertIsNotNone(replacement)
            replacement.close()


if __name__ == "__main__":
    unittest.main()
