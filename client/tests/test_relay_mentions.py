import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from client import relay_message_format as fmt, relay_messages
from client.relay_identity import IdentityError
from client.relay_inbox import Inbox


class MessageFormatTests(unittest.TestCase):
    def test_mentions_are_in_encrypted_payload_and_legacy_stays_readable(self):
        account = str(uuid4())
        raw = fmt.encode("Hola equipo 👋", [account, account])
        self.assertEqual(fmt.decode(raw), ("Hola equipo 👋", [account]))
        self.assertEqual(fmt.decode(b"old plain body"), ("old plain body", []))
        for mentions in (["bad"], [str(uuid4()).upper()], [3], ["x"] * 33):
            with self.subTest(mentions=mentions), self.assertRaises(ValueError):
                fmt.encode("Hola", mentions)
        with self.assertRaises(ValueError):
            fmt.encode("a" * 4096)
        with self.assertRaises(ValueError):
            fmt.decode(fmt.PREFIX + b'{"content":"x","mentions":[],"extra":1}')


class AlertTests(unittest.TestCase):
    def test_preferences_and_mentions_filter_without_storing_plaintext(self):
        origin = "https://relay.example"
        channel, me, other, own_device = (str(uuid4()) for _ in range(4))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "inbox.sqlite"
            inbox = Inbox(origin, own_device, path)
            rows = [
                {"seq": i, "operation_id": str(uuid4()), "device_id": device,
                 "nonce": "n", "ciphertext": str(i), "created_at": "2026-01-01"}
                for i, device in ((1, other), (2, other), (3, own_device))
            ]
            inbox.append(channel, 0, rows)
            bodies = {"1": fmt.encode("not mentioned", []),
                      "2": fmt.encode("private mention", [me]),
                      "3": fmt.encode("own message", [me])}
            mode = ["mentions"]
            def decrypt(_origin, _channel, _seq, _nonce, ciphertext):
                return bodies[ciphertext]
            def subscriptions(_origin, _limit, _cursor):
                return {"items": [{"channel_id": channel, "mode": mode[0]}], "next_cursor": None}
            with patch.object(relay_messages, "DeviceVault") as vault, \
                 patch("client.relay_inbox._state_path", return_value=path), \
                 patch.object(relay_messages, "identify", return_value={"account_id": me}), \
                 patch.object(relay_messages, "list_subscriptions", side_effect=subscriptions), \
                 patch.object(relay_messages.relay_keys, "decrypt", side_effect=decrypt):
                vault.return_value.load.return_value = SimpleNamespace(device_id=own_device)
                result = relay_messages.alerts(origin, channel)
                self.assertEqual([item["seq"] for item in result["alerts"]], [2])
                self.assertEqual(result["alerts"][0]["reason"], "mention")
                self.assertEqual(result["next_after"], 3)
                self.assertNotIn("private mention", str(result))
                mode[0] = "all"
                self.assertEqual([item["seq"] for item in relay_messages.alerts(origin, channel)["alerts"]], [1, 2])
                mode[0] = "muted"
                result = relay_messages.alerts(origin, channel)
                self.assertEqual(result["alerts"], [])
                self.assertEqual(result["next_after"], 3)
                with patch.object(relay_messages, "list_subscriptions",
                                  return_value={"items": [], "next_cursor": None}):
                    self.assertEqual(relay_messages.alerts(origin, channel)["mode"], "unfollowed")
            self.assertNotIn(b"private mention", path.read_bytes())

    def test_invalid_identity_is_rejected(self):
        with patch.object(relay_messages, "DeviceVault") as vault, \
             patch.object(relay_messages, "identify", return_value={"account_id": "invalid"}):
            vault.return_value.load.return_value = SimpleNamespace(device_id=str(uuid4()))
            with self.assertRaises(IdentityError):
                relay_messages.alerts("https://relay.example", str(uuid4()))


if __name__ == "__main__":
    unittest.main()
