import unittest
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from client import relay_announcement_format as fmt
from client import relay_announcements as announcements
from client.relay_identity import IdentityError


class AnnouncementFormatTests(unittest.TestCase):
    def test_encode_decode_is_canonical_and_validates_input(self):
        channel = str(uuid4())
        encoded = fmt.encode(channel, "Conectate por favor")
        self.assertEqual(fmt.decode(encoded), {
            "channel_id": channel, "note": "Conectate por favor", "version": 2,
        })
        self.assertTrue(encoded.startswith(fmt.PREFIX_V2))
        self.assertIsNone(fmt.decode("mensaje normal"))
        with self.assertRaises(ValueError):
            fmt.encode("")
        with self.assertRaises(ValueError):
            fmt.encode(channel, note=5)
        with self.assertRaises(ValueError):
            fmt.decode(fmt.PREFIX + "!!!")
        with self.assertRaises(ValueError):
            tampered = fmt.encode(channel, "nota")
            fmt.decode(tampered[:-2] + "AA")

    def test_v1_legacy_is_still_readable(self):
        channel = str(uuid4())
        legacy = fmt.encode(channel, "anuncio viejo", version=1)
        self.assertTrue(legacy.startswith(fmt.PREFIX))
        self.assertEqual(fmt.decode(legacy), {"channel_id": channel, "note": "anuncio viejo"})
        with self.assertRaises(ValueError):
            fmt.encode(channel, version=3)


class AnnouncementTests(unittest.TestCase):
    def test_announce_uses_encrypted_main_transport(self):
        announced, transport = str(uuid4()), str(uuid4())
        with patch.object(announcements, "main_channel", return_value=transport), \
             patch.object(announcements.relay_messages, "send", return_value={"status": "sent"}) as send:
            result = announcements.announce("https://relay.example", announced, "Abrir canal")
        self.assertEqual(result["status"], "sent")
        args = send.call_args.args
        self.assertEqual(args[1], transport)
        self.assertEqual(fmt.decode(args[2]), {
            "channel_id": announced, "note": "Abrir canal", "version": 2,
        })

    def test_list_deduplicates_and_ignores_ordinary_messages(self):
        first, second = str(uuid4()), str(uuid4())
        sender = str(uuid4())
        inbox = {"cursor": 4, "messages": [
            {"seq": 1, "operation_id": str(uuid4()), "device_id": sender,
             "content": fmt.encode(first, "primero")},
            {"seq": 2, "operation_id": str(uuid4()), "device_id": sender,
             "content": fmt.encode(first, "actualizado")},
            {"seq": 3, "operation_id": str(uuid4()), "device_id": sender,
             "content": "mensaje normal"},
            {"seq": 4, "operation_id": str(uuid4()), "device_id": sender,
             "content": fmt.encode(second, "otro")},
        ]}
        with patch.object(announcements, "main_channel", return_value=str(uuid4())), \
             patch.object(announcements, "DeviceVault") as vault, \
             patch.object(announcements.relay_messages, "read_inbox", return_value=inbox):
            vault.return_value.load.return_value = SimpleNamespace(device_id=str(uuid4()))
            result = announcements.list_announcements("https://relay.example")
        self.assertEqual([item["seq"] for item in result["announcements"]], [2, 4])
        self.assertEqual(result["announcements"][0]["note"], "actualizado")
        self.assertEqual(result["cursor"], 4)
        self.assertEqual(result["client_version"], 2)

    def test_legacy_announcement_is_flagged(self):
        channel = str(uuid4())
        sender = str(uuid4())
        inbox = {"cursor": 1, "messages": [
            {"seq": 1, "operation_id": str(uuid4()), "device_id": sender,
             "content": fmt.encode(channel, "viejo", version=1)},
        ]}
        with patch.object(announcements, "main_channel", return_value=str(uuid4())), \
             patch.object(announcements, "DeviceVault") as vault, \
             patch.object(announcements.relay_messages, "read_inbox", return_value=inbox):
            vault.return_value.load.return_value = SimpleNamespace(device_id=str(uuid4()))
            result = announcements.list_announcements("https://relay.example")
        self.assertEqual(len(result["announcements"]), 1)
        self.assertEqual(result["announcements"][0]["warning"], "legacy")
        self.assertEqual(result["announcements"][0]["version"], 1)
        self.assertEqual(result["client_version"], 2)

    def test_announcements_do_not_grant_access_or_follow_channel(self):
        from client import relay_workspace
        with patch.object(announcements, "main_channel", return_value=str(uuid4())), \
             patch.object(announcements, "DeviceVault") as vault, \
             patch.object(announcements.relay_messages, "read_inbox",
                          return_value={"cursor": 0, "messages": []}), \
             patch.object(relay_workspace, "set_subscription") as subscription:
            vault.return_value.load.return_value = SimpleNamespace(device_id=str(uuid4()))
            announcements.list_announcements("https://relay.example")
        subscription.assert_not_called()

    def test_main_channel_requires_visible_main(self):
        with patch.object(announcements, "list_projects", return_value={"items": []}):
            with self.assertRaises(IdentityError):
                announcements.main_channel("https://relay.example")


if __name__ == "__main__":
    unittest.main()
