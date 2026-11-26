import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from server import keys, messages
from server.identity import Denied


class FakeResult:
    def __init__(self, row):
        self.row = row

    def mappings(self):
        return self

    def one_or_none(self):
        return self.row


class FakeConn:
    def __init__(self, existing=None, current=3):
        self.existing = existing
        self.current = current
        self.inserts = []

    async def execute(self, query, params=None):
        sql = str(query)
        if "pg_advisory_xact_lock" in sql:
            return FakeResult(None)
        if "SELECT channel_id, seq, nonce, ciphertext" in sql:
            return FakeResult(self.existing)
        if "COALESCE(MAX(seq)" in sql:
            return FakeResult({"next_seq": self.current})
        if "INSERT INTO channel_messages" in sql:
            self.inserts.append(params)
            return FakeResult({"seq": self.current})
        if "pg_notify" in sql:
            return FakeResult(None)
        raise AssertionError(sql)


def body(expected_seq=None, nonce=None, ciphertext=None):
    return SimpleNamespace(
        channel_id=uuid4(), operation_id=uuid4(), device_id=uuid4(),
        nonce=nonce or keys._b64(b"n" * 12),
        ciphertext=ciphertext or keys._b64(b"c" * 16),
        expected_seq=expected_seq,
    )


class SequenceIntegrityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.access = patch.object(messages, "_access", new=AsyncMock())
        self.access.start()
        self.addAsyncCleanup(self.access.stop)

    async def test_matching_expected_seq_is_written(self):
        conn = FakeConn(current=3)
        payload = body(expected_seq=3)
        result = await messages.send(conn, uuid4(), payload)
        self.assertEqual(result["seq"], 3)
        self.assertEqual(len(conn.inserts), 1)
        self.assertEqual(conn.inserts[0]["seq"], 3)

    async def test_mismatched_expected_seq_rejects_without_writing(self):
        conn = FakeConn(current=3)
        with self.assertRaises(Denied) as raised:
            await messages.send(conn, uuid4(), body(expected_seq=2))
        self.assertEqual(raised.exception.status, 409)
        self.assertEqual(conn.inserts, [])

    async def test_retry_with_existing_operation_keeps_its_seq(self):
        nonce, ciphertext = keys._b64(b"n" * 12), keys._b64(b"c" * 16)
        payload = body(expected_seq=20, nonce=nonce, ciphertext=ciphertext)
        existing = {
            "channel_id": payload.channel_id, "seq": 7,
            "nonce": keys._unb64(nonce), "ciphertext": keys._unb64(ciphertext),
        }
        conn = FakeConn(existing=existing, current=20)
        result = await messages.send(conn, uuid4(), payload)
        self.assertEqual(result["seq"], 7)
        self.assertEqual(conn.inserts, [])

    async def test_retry_with_changed_ciphertext_is_rejected(self):
        payload = body(ciphertext=keys._b64(b"x" * 16))
        existing = {
            "channel_id": payload.channel_id, "seq": 7,
            "nonce": keys._unb64(keys._b64(b"n" * 12)),
            "ciphertext": keys._unb64(keys._b64(b"c" * 16)),
        }
        conn = FakeConn(existing=existing)
        with self.assertRaises(Denied) as raised:
            await messages.send(conn, uuid4(), payload)
        self.assertEqual(raised.exception.status, 409)
        self.assertEqual(conn.inserts, [])


if __name__ == "__main__":
    unittest.main()
