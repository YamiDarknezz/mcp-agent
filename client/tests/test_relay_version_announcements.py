import unittest
from unittest.mock import patch
from uuid import uuid4

from client import relay_announcement_format as fmt
from client import relay_announcements as announcements
from client.relay_identity import DeviceVault


class VersionedAnnouncementTests(unittest.TestCase):
    def test_v2_roundtrip_and_v1_stays_readable(self):
        channel = str(uuid4())
        v2 = fmt.encode_with_version(channel, "Conectate", "0.1.0")
        parsed = fmt.decode(v2)
        self.assertEqual(parsed, {
            "channel_id": channel, "note": "Conectate", "client_version": "0.1.0",
        })
        v1 = fmt.encode(channel, "nota")
        self.assertEqual(fmt.decode(v1), {"channel_id": channel, "note": "nota"})

    def test_warning_and_legacy_flag_reach_the_agent(self):
        channel, sender = str(uuid4()), str(uuid4())
        inbox = {"cursor": 2, "messages": [
            {"seq": 1, "operation_id": str(uuid4()), "device_id": sender,
             "content": fmt.encode(channel, "sin version")},
            {"seq": 2, "operation_id": str(uuid4()), "device_id": sender,
             "content": fmt.encode_with_version(channel, "con version", "0.1.0")},
        ]}
        with patch.object(DeviceVault, "load", return_value=object()), \
             patch.object(announcements, "main_channel", return_value="main"), \
             patch.object(announcements.relay_messages, "read_inbox", return_value=inbox):
            result = announcements.list_announcements("https://relay.example")
        latest = result["announcements"][0]
        self.assertTrue(latest["legacy"] is False)
        self.assertEqual(latest["client_version"], "0.1.0")
        self.assertIn("0.1.0", result["version_warning"])


if __name__ == "__main__":
    unittest.main()
