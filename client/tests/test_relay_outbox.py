import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from client import relay_messages, relay_outbox
from client.relay_identity import IdentityError


class OutboxTests(unittest.TestCase):
    def test_lost_ack_is_retried_with_identical_ciphertext_and_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "outbox.sqlite3"
            stored = {}
            calls = []

            def call(_origin, _path, payload):
                calls.append(dict(payload))
                stored.setdefault(payload["operation_id"], dict(payload))
                if len(calls) == 1:
                    raise IdentityError("Conexión interrumpida.")
                return {"operation_id": payload["operation_id"], "seq": payload.get("expected_seq", 1)}

            with patch.object(relay_outbox, "_state_path", return_value=path), \
                 patch.object(relay_messages, "DeviceVault") as vault, \
                 patch.object(relay_messages.relay_keys, "encrypt", return_value={
                     "nonce": "encrypted-nonce", "ciphertext": "encrypted-payload",
                 }), patch.object(relay_messages, "_call", side_effect=call):
                vault.return_value.load.return_value = SimpleNamespace(device_id=str(uuid4()))
                result = relay_messages.send("https://example.com", str(uuid4()), "plain-text-sentinel")
                self.assertEqual(result["status"], "pending")
                self.assertNotIn(b"plain-text-sentinel", path.read_bytes())
                self.assertEqual(len(relay_outbox.Outbox("ignored", "ignored", path).pending()), 1)
                retried = relay_messages.retry_pending("https://example.com")
                self.assertFalse(retried["pending"])
                self.assertEqual(len(stored), 1)
                self.assertEqual(calls[0], calls[1])
                self.assertEqual(relay_outbox.Outbox("ignored", "ignored", path).pending(), [])

    def test_origin_and_device_have_separate_paths(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            "os.environ", {"LOCALAPPDATA": directory, "XDG_STATE_HOME": directory}
        ):
            first = relay_outbox._state_path("https://one.example", "device-a")
            self.assertNotEqual(first, relay_outbox._state_path("https://one.example", "device-b"))
            self.assertNotEqual(first, relay_outbox._state_path("https://two.example", "device-a"))


if __name__ == "__main__":
    unittest.main()
