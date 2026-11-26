import unittest
from unittest.mock import patch
from uuid import uuid4

from client import relay_invites
from client.relay_identity import IdentityError


CODE = "relay_inv_" + "A" * 43


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

    def test_redeem_signs_invite_redeem_claims_and_public_key(self):
        channel = str(uuid4())
        with patch.object(relay_invites, "DeviceVault") as vault, \
             patch.object(relay_invites, "request_json", return_value={
                 "channel_id": channel, "role": "reader",
             }) as request:
            vault.return_value.load.return_value = __import__(
                "client.relay_identity", fromlist=["LocalKey"]
            ).LocalKey(str(uuid4()), __import__(
                "cryptography.hazmat.primitives.asymmetric.ed25519", fromlist=["Ed25519PrivateKey"]
            ).Ed25519PrivateKey.generate())
            result = relay_invites.redeem(
                "https://relay.example", CODE, "Ana Invitada", "Laptop de Ana", "ana@example.com"
            )
        self.assertEqual(result["channel_id"], channel)
        payload = request.call_args.args[2]
        self.assertEqual(payload["code"], CODE)
        self.assertEqual(len(payload["public_key"]), 43)
        proof = payload["proof"]
        self.assertIsInstance(proof, str)
        import jwt
        claims = jwt.decode(proof, options={"verify_signature": False}, audience="https://relay.example")
        self.assertEqual(claims["purpose"], "invite_redeem")
        self.assertEqual(claims["display_name"], "Ana Invitada")
        self.assertEqual(claims["device_label"], "Laptop de Ana")
        self.assertEqual(claims["declared_email"], "ana@example.com")

    def test_redeem_validates_code_and_labels_before_calling_server(self):
        with patch.object(relay_invites, "request_json") as request:
            for bad in ("", "not-a-code", "relay_inv_SHORT", CODE + "!"):
                with self.subTest(bad=bad), self.assertRaises(IdentityError):
                    relay_invites.redeem("https://relay.example", bad, "Ana", "Laptop")
            with self.assertRaises(IdentityError):
                relay_invites.redeem("https://relay.example", CODE, "", "Laptop")
        request.assert_not_called()

    def test_redeem_propagates_server_rejection(self):
        with patch.object(relay_invites, "DeviceVault") as vault, \
             patch.object(relay_invites, "request_json",
                          side_effect=IdentityError("invitación expirada", 410)):
            vault.return_value.load.return_value = __import__(
                "client.relay_identity", fromlist=["LocalKey"]
            ).LocalKey(str(uuid4()), __import__(
                "cryptography.hazmat.primitives.asymmetric.ed25519", fromlist=["Ed25519PrivateKey"]
            ).Ed25519PrivateKey.generate())
            with self.assertRaises(IdentityError) as raised:
                relay_invites.redeem("https://relay.example", "relay_inv_" + "C" * 43, "Ana", "Laptop")
        self.assertEqual(raised.exception.status, 410)


if __name__ == "__main__":
    unittest.main()
