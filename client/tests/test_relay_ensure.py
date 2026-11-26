import unittest
from unittest.mock import patch

from client import relay_keys
from client.relay_identity import IdentityError


class EnsureChannelKeyTests(unittest.TestCase):
    def test_existing_local_key_is_reused_without_rotation(self):
        loaded = {"channel_id": "ch", "key_id": "key-1", "fingerprint": "fp", "role": "owner"}
        with patch.object(relay_keys, "has_local_key", return_value=True), \
             patch.object(relay_keys, "load", return_value=loaded) as load, \
             patch.object(relay_keys, "share") as share:
            result = relay_keys.ensure("https://relay.example", "ch")
        self.assertEqual(result, {"status": "already_local", **loaded})
        load.assert_called_once_with("https://relay.example", "ch")
        share.assert_not_called()

    def test_missing_key_is_shared_then_loaded(self):
        shared = {"recipients": ["device-1", "device-2"], "key_id": "key-1"}
        loaded = {"channel_id": "ch", "key_id": "key-1", "fingerprint": "fp", "role": "owner"}
        with patch.object(relay_keys, "has_local_key", return_value=False), \
             patch.object(relay_keys, "share", return_value=shared) as share, \
             patch.object(relay_keys, "load", return_value=loaded) as load:
            result = relay_keys.ensure("https://relay.example", "ch")
        self.assertEqual(result, {
            "status": "created", "recipients": ["device-1", "device-2"], **loaded,
        })
        share.assert_called_once_with("https://relay.example", "ch")
        load.assert_called_once_with("https://relay.example", "ch")

    def test_unverifiable_local_key_never_rotates(self):
        with patch.object(relay_keys, "has_local_key", return_value=True), \
             patch.object(relay_keys, "load", side_effect=IdentityError("not verified")), \
             patch.object(relay_keys, "share") as share:
            result = relay_keys.ensure("https://relay.example", "ch")
        self.assertEqual(result, {
            "status": "already_local", "channel_id": "ch", "key_id": None,
        })
        share.assert_not_called()


if __name__ == "__main__":
    unittest.main()
