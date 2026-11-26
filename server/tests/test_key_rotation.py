import unittest
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from server import authorization as policy
from server import keys
from server.identity import Denied


class FakeResult:
    def __init__(self, row):
        self.row = row

    def mappings(self):
        return self

    def one_or_none(self):
        return self.row


class FakeConn:
    def __init__(self, current_key):
        self.current_key = current_key
        self.statements = []

    async def execute(self, query, params=None):
        sql = str(query)
        self.statements.append((sql, params or {}))
        if "SELECT key_id FROM channel_keys" in sql:
            return FakeResult({"key_id": self.current_key})
        return FakeResult(None)


class KeyRotationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.old = uuid4()
        self.new = uuid4()
        self.channel = uuid4()
        self.sender = uuid4()
        self.recipient = uuid4()
        self.envelopes = {str(self.recipient): "e" * 100}

    async def test_rotation_retires_old_key_and_rewraps(self):
        conn = FakeConn(self.old)
        with patch.object(keys, "_channel_access", new=AsyncMock(return_value=policy.Role.OWNER)), \
             patch.object(keys, "_validated_envelopes", new=AsyncMock(return_value={self.recipient: b"e" * 100})):
            result = await keys.rotate_channel_key(
                conn, uuid4(), self.sender, self.channel, self.new, self.old, self.envelopes,
            )
        self.assertEqual(result["replaced_key_id"], str(self.old))
        self.assertEqual(result["key_id"], str(self.new))
        self.assertEqual(result["recipients"], 1)
        sql = " ".join(statement for statement, _ in conn.statements)
        self.assertIn("UPDATE channel_keys", sql)
        self.assertIn("channel_key_history", sql)
        self.assertIn("DELETE FROM channel_key_envelopes", sql)

    async def test_wrong_previous_key_is_rejected_without_writes(self):
        conn = FakeConn(self.old)
        with patch.object(keys, "_channel_access", new=AsyncMock(return_value=policy.Role.OWNER)):
            with self.assertRaises(Denied) as raised:
                await keys.rotate_channel_key(
                    conn, uuid4(), self.sender, self.channel, self.new, uuid4(), self.envelopes,
                )
        self.assertEqual(raised.exception.status, 409)
        writes = [sql for sql, _ in conn.statements if not sql.startswith("SELECT key_id")]
        self.assertEqual(writes, [])

    async def test_mark_rotation_required_updates_each_channel(self):
        conn = FakeConn(self.old)
        channels = [uuid4(), uuid4()]
        await keys.mark_rotation_required(conn, channels)
        updates = [params for sql, params in conn.statements if "rotation_required = true" in sql]
        self.assertEqual([params["id"] for params in updates], channels)

    async def test_pending_rotations_lists_flagged_channels(self):
        channel = uuid4()
        with patch.object(keys, "_all", new=AsyncMock(return_value=[
            {"channel_id": channel, "name": "hijo"},
        ])):
            result = await keys.pending_rotations(FakeConn(self.old), uuid4())
        self.assertEqual(result, [{"channel_id": str(channel), "name": "hijo"}])

    async def test_non_admin_cannot_rotate(self):
        conn = FakeConn(self.old)
        with patch.object(keys, "_channel_access", new=AsyncMock(return_value=policy.Role.READER)):
            with self.assertRaises(Denied) as raised:
                await keys.rotate_channel_key(
                    conn, uuid4(), self.sender, self.channel, self.new, self.old, self.envelopes,
                )
        self.assertEqual(raised.exception.status, 403)


if __name__ == "__main__":
    unittest.main()
