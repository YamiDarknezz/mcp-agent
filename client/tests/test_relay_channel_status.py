from types import SimpleNamespace
from unittest.mock import patch
import unittest
from uuid import uuid4

from client import relay_mcp
from client.relay_identity import IdentityError


class ChannelStatusTests(unittest.TestCase):
    def test_reports_per_channel_state_without_secrets(self):
        origin = "https://relay.example"
        with_key, followed = str(uuid4()), str(uuid4())
        state = relay_mcp.BridgeState(status="running", connected_channels={with_key})
        subscriptions = [{"channel_id": followed, "mode": "mentions"}]

        def keys(_origin):
            class Store:
                def load(self, channel):
                    return b"secret" if channel == with_key else None
            return Store()

        inbox = SimpleNamespace(cursor=lambda channel: 7 if channel == with_key else 0,
                                channel_ids=lambda: [with_key])
        with patch.object(relay_mcp, "DeviceVault") as vault, \
             patch.object(relay_mcp, "api_list_subscriptions", return_value={"items": subscriptions}), \
             patch.object(relay_mcp, "ChannelKeyStore", side_effect=keys), \
             patch.object(relay_mcp, "Inbox", return_value=inbox):
            vault.return_value.load.return_value = SimpleNamespace(device_id=str(uuid4()))
            result = relay_mcp._channel_details(origin, state)
        by_id = {item["channel_id"]: item for item in result["channels"]}
        self.assertTrue(by_id[with_key]["channel_key_local"])
        self.assertEqual(by_id[with_key]["last_seq"], 7)
        self.assertTrue(by_id[with_key]["bridge_connected"])
        self.assertIsNone(by_id[with_key]["subscription"])
        self.assertFalse(by_id[followed]["channel_key_local"])
        self.assertEqual(by_id[followed]["subscription"], "mentions")
        self.assertEqual(by_id[followed]["last_seq"], 0)
        self.assertFalse(by_id[followed]["bridge_connected"])
        self.assertNotIn("secret", str(result))

    def test_still_reports_local_state_when_server_is_unavailable(self):
        origin = "https://relay.example"
        state = relay_mcp.BridgeState(status="retrying")
        channel = str(uuid4())
        inbox = SimpleNamespace(cursor=lambda _channel: 3, channel_ids=lambda: [channel])
        with patch.object(relay_mcp, "DeviceVault") as vault, \
             patch.object(relay_mcp, "api_list_subscriptions", side_effect=IdentityError("sin servidor")), \
             patch.object(relay_mcp, "ChannelKeyStore") as store, \
             patch.object(relay_mcp, "Inbox", return_value=inbox):
            vault.return_value.load.return_value = SimpleNamespace(device_id=str(uuid4()))
            store.return_value.load.return_value = None
            result = relay_mcp._channel_details(origin, state)
        self.assertEqual(result["channels"][0]["last_seq"], 3)
        self.assertIsNone(result["channels"][0]["subscription"])
        self.assertIn("server_error", result)


if __name__ == "__main__":
    unittest.main()
