import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from client.relay_inbox import Inbox
from client import relay_live


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


if __name__ == "__main__":
    unittest.main()
