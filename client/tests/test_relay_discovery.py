import unittest
from types import SimpleNamespace
from unittest.mock import patch

from client import relay_workspace
from client.relay_identity import IdentityError, DeviceVault


class ChannelDiscoveryTests(unittest.TestCase):
    def test_list_channels_sends_only_filters_and_returns_page(self):
        seen = []

        def fake_call(_origin, path, payload, **_kwargs):
            seen.append((path, payload))
            return {"items": [{"id": "ch", "name": "main"}], "next_cursor": None}

        with patch.object(relay_workspace, "_call", side_effect=fake_call):
            result = relay_workspace.list_channels(
                "https://relay.example", "project-1", limit=12, cursor="cursor-1"
            )
        self.assertEqual(
            seen,
            [("/v1/workspace/list-channels",
              {"limit": 12, "project_id": "project-1", "cursor": "cursor-1"})],
        )
        self.assertEqual(result["items"][0]["id"], "ch")

    def test_directory_returns_mentionable_ids_without_key_material(self):
        key = SimpleNamespace(device_id="device-1")
        devices = {
            "devices": [{
                "id": "device-1", "label": "GO15", "fingerprint": "fp1",
                "authentication_key": "secret-auth", "encryption_key": "secret-encryption",
            }]
        }

        def fake_call(_origin, path, payload, **_kwargs):
            self.assertEqual(path, "/v1/devices/list")
            self.assertEqual(payload, {})
            return devices

        with patch.object(DeviceVault, "load", return_value=key), \
             patch.object(relay_workspace, "identify", return_value={"account_id": "account-1"}), \
             patch.object(relay_workspace, "_call", side_effect=fake_call):
            result = relay_workspace.directory("https://relay.example")
        self.assertEqual(result["account_id"], "account-1")
        self.assertEqual(result["devices"], [{"id": "device-1", "label": "GO15", "encryption_fingerprint": "fp1"}])
        self.assertNotIn("secret-auth", str(result))
        self.assertNotIn("secret-encryption", str(result))

    def test_directory_requires_registration(self):
        with patch.object(DeviceVault, "load", return_value=None):
            with self.assertRaises(IdentityError):
                relay_workspace.directory("https://relay.example")


if __name__ == "__main__":
    unittest.main()
