import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from client import relay_crypto as crypto
from client import relay_message_format
from client import relay_messages
from client.relay_identity import IdentityError
from unittest.mock import ANY


class SequenceTests(unittest.TestCase):
    def test_read_does_not_expose_ciphertext_to_the_model(self):
        channel = str(uuid4())
        message = {
            "seq": 1, "operation_id": str(uuid4()),
            "nonce": "nonce-value", "ciphertext": "ciphertext-value",
        }
        with patch.object(relay_messages, "_call", return_value={"messages": [message]}), \
             patch.object(relay_messages.relay_keys, "decrypt",
                          return_value=relay_message_format.encode("hola", [])):
            result = relay_messages.read("https://relay.example", channel, 0, 10)
        shown = result["messages"][0]
        self.assertEqual(shown["content"], "hola")
        self.assertNotIn("nonce", shown)
        self.assertNotIn("ciphertext", shown)

    def test_ciphertext_is_bound_to_server_sequence(self):
        key = crypto.new_channel_key()
        channel = str(uuid4())
        plaintext = b"mensaje ligado al seq"
        nonce, ciphertext = crypto.encrypt_message(key, channel, 7, plaintext)
        self.assertEqual(crypto.decrypt_message(key, channel, 7, nonce, ciphertext), plaintext)
        with self.assertRaises(ValueError):
            crypto.decrypt_message(key, channel, 8, nonce, ciphertext)

    def test_read_prefers_server_seq_and_falls_back_to_legacy(self):
        key = crypto.new_channel_key()
        channel, operation = str(uuid4()), str(uuid4())
        body = b"cuerpo"
        nonce, ciphertext = crypto.encrypt_message(key, channel, 3, body)
        legacy = relay_messages._aad_sequence(operation)
        legacy_nonce, legacy_ciphertext = crypto.encrypt_message(key, channel, legacy, body)
        with patch.object(relay_messages.relay_keys, "decrypt",
                          side_effect=lambda _o, _c, seq, n, ct: crypto.decrypt_message(key, channel, seq, n, ct)):
            item = {"seq": 3, "operation_id": operation, "nonce": nonce, "ciphertext": ciphertext}
            self.assertEqual(relay_messages._decrypt_item("o", channel, item), body)
        with patch.object(relay_messages.relay_keys, "decrypt",
                          side_effect=lambda _o, _c, seq, n, ct: crypto.decrypt_message(key, channel, seq, n, ct)):
            item = {"seq": 9, "operation_id": operation, "nonce": legacy_nonce, "ciphertext": legacy_ciphertext}
            self.assertEqual(relay_messages._decrypt_item("o", channel, item), body)
        with patch.object(relay_messages.relay_keys, "decrypt", side_effect=ValueError):
            item = {"seq": 9, "operation_id": operation, "nonce": "n", "ciphertext": "c"}
            with self.assertRaises(IdentityError):
                relay_messages._decrypt_item("o", channel, item)

    def test_send_sends_expected_seq_and_rejects_wrong_assignment(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            channel = str(uuid4())
            device_id = str(uuid4())
            with patch.dict("os.environ", {"LOCALAPPDATA": folder, "XDG_STATE_HOME": folder}), \
                 patch.object(relay_messages, "DeviceVault") as vault, \
                 patch.object(relay_messages, "relay_keys") as keys, \
                 patch.object(relay_messages, "_call") as call:
                vault.return_value.load.return_value = SimpleNamespace(device_id=device_id)
                keys.encrypt.return_value = {"nonce": "n", "ciphertext": "c"}
                def respond(_origin, _path, payload):
                    return {"operation_id": payload["operation_id"], "seq": 4}
                call.side_effect = respond
                result = relay_messages.send("https://relay.example", channel, "hola")
            self.assertEqual(result["status"], "rejected")
            payload = call.call_args.args[2]
            self.assertEqual(payload["expected_seq"], 1)

    def test_send_accepts_matching_seq(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.dict("os.environ", {"LOCALAPPDATA": folder, "XDG_STATE_HOME": folder}), \
             patch.object(relay_messages, "DeviceVault") as vault, \
             patch.object(relay_messages, "relay_keys") as keys, \
             patch.object(relay_messages, "_call") as call:
            vault.return_value.load.return_value = SimpleNamespace(device_id=str(uuid4()))
            keys.encrypt.return_value = {"nonce": "n", "ciphertext": "c"}
            def respond(_origin, _path, payload):
                return {"operation_id": payload["operation_id"], "seq": 1}
            call.side_effect = respond
            result = relay_messages.send("https://relay.example", str(uuid4()), "hola")
        self.assertEqual(result["status"], "sent")
        self.assertEqual(result["seq"], 1)


if __name__ == "__main__":
    unittest.main()
