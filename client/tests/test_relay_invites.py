import unittest
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from client import relay_invites
from client.relay_identity import IdentityError


CODE = "relay_inv_" + "A" * 43


def fake_key():
    private = Ed25519PrivateKey.generate()
    return SimpleNamespace(
        device_id=str(uuid4()),
        private=SimpleNamespace(
            public_key=lambda: SimpleNamespace(public_bytes_raw=lambda: private.public_key().public_bytes_raw())
        ),
        proof=lambda origin, purpose, **claims: "signed-proof",
    )


class InviteClientTests(unittest.TestCase):
    def test_issue_returns_code_only_to_caller(self):
        channel = str(uuid4())
        with patch.object(relay_invites, "_proof", return_value={
            "code": CODE, "expires_at": "2026-11-26T17:00:00Z",
        }) as proof:
            result = relay_invites.issue("https://relay.example", channel, "collaborator", 300)
        self.assertEqual(result["code"], CODE)
        self.assertEqual(proof.call_args.args[1], "/v1/invites/issue")
        self.assertEqual(proof.call_args.args[2]["role"], "collaborator")
        self.assertEqual(proof.call_args.args[2]["expires_in"], 300)

    def test_issue_rejects_bad_role_and_ttl_before_calling_server(self):
        with patch.object(relay_invites, "_proof") as proof:
            with self.assertRaises(IdentityError):
                relay_invites.issue("https://relay.example", str(uuid4()), "owner")
            with self.assertRaises(IdentityError):
                relay_invites.issue("https://relay.example", str(uuid4()), expires_in=1)
        proof.assert_not_called()

    def test_status_never_accepts_a_code_from_server(self):
        with patch.object(relay_invites, "_proof", return_value={
            "active": 0, "last_expires_at": None, "code": "leaked",
        }):
            with self.assertRaises(IdentityError):
                relay_invites.status("https://relay.example", str(uuid4()))

    def test_redeem_uses_new_device_proof_with_invited_identity(self):
        channel = str(uuid4())
        key = fake_key()
        with patch.object(relay_invites.DeviceVault, "load_or_create", return_value=key), \
             patch.object(relay_invites, "request_json", return_value={
                 "channel_id": channel, "role": "reader",
             }) as request:
            result = relay_invites.redeem(
                "https://relay.example", CODE, "Erick", "VIVOBOOK-S16", "erick@example.com"
            )
        self.assertEqual(result["channel_id"], channel)
        body = request.call_args.args[2]
        self.assertEqual(body["device_id"], key.device_id)
        self.assertEqual(len(body["public_key"]), 43)
        self.assertEqual(body["proof"], "signed-proof")
        self.assertEqual(body["code"], CODE)

    def test_redeem_validates_inputs_before_network(self):
        with patch.object(relay_invites, "request_json") as request:
            for bad in ("", "not-a-code", "relay_inv_SHORT", CODE + "!"):
                with self.subTest(code=bad), self.assertRaises(IdentityError):
                    relay_invites.redeem("https://relay.example", bad, "Erick", "Laptop")
            with self.assertRaises(IdentityError):
                relay_invites.redeem("https://relay.example", CODE, "", "Laptop")
        request.assert_not_called()

    def test_redeem_propagates_server_rejection(self):
        with patch.object(relay_invites.DeviceVault, "load_or_create", return_value=fake_key()), \
             patch.object(relay_invites, "request_json", side_effect=IdentityError("invitación expirada", 410)):
            with self.assertRaises(IdentityError) as raised:
                relay_invites.redeem("https://relay.example", CODE, "Erick", "Laptop")
        self.assertEqual(raised.exception.status, 410)


if __name__ == "__main__":
    unittest.main()
