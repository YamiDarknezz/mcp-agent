import unittest
from unittest.mock import patch
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from client import relay_crypto as crypto
from client import relay_keys
from client.relay_identity import DeviceVault, IdentityError, LocalKey
from client.relay_keys import ChannelKeyStore, TrustedDeviceStore
from client.tests.test_relay_mcp import MemoryVault


class TrustTests(unittest.TestCase):
    def test_pin_requires_exact_fingerprint_and_refuses_substitution(self):
        backend = MemoryVault()
        store = TrustedDeviceStore("https://relay.example", backend)
        auth, encryption = b"a" * 32, b"b" * 32
        fingerprint = crypto.device_fingerprint(auth, encryption)
        with self.assertRaises(IdentityError):
            store.verify("device", auth, encryption)
        with self.assertRaises(IdentityError):
            store.pin("device", auth, encryption, "0" * 64)
        store.pin("device", auth, encryption, fingerprint)
        store.verify("device", auth, encryption)
        for changed_auth, changed_encryption in ((b"c" * 32, encryption), (auth, b"d" * 32)):
            with self.assertRaises(IdentityError):
                store.verify("device", changed_auth, changed_encryption)
            with self.assertRaises(IdentityError):
                store.pin("device", changed_auth, changed_encryption,
                          crypto.device_fingerprint(changed_auth, changed_encryption))
        store.verify("device", auth, encryption)

    def test_two_devices_exchange_only_after_pin_and_reject_forged_sender(self):
        origin = "https://relay.example"
        alice = LocalKey(str(uuid4()), Ed25519PrivateKey.generate())
        bob = LocalKey(str(uuid4()), Ed25519PrivateKey.generate())
        channel = str(uuid4())
        vaults = {alice.device_id: MemoryVault(), bob.device_id: MemoryVault()}
        current = [alice]
        def device(key):
            encryption = crypto.public_bytes(key.encryption_public())
            return {
                "id": key.device_id, "authentication_key": crypto.b64(key.private.public_key().public_bytes_raw()),
                "encryption_key": crypto.b64(encryption),
                "encryption_signature": crypto.b64(key.encryption_signature()),
                "fingerprint": crypto.fingerprint(encryption),
            }
        devices = [device(alice), device(bob)]
        data = {}
        def request(_origin, path, payload, **_kwargs):
            if path == "/v1/devices/list":
                return {"devices": devices}
            if path == "/v1/keys/publish":
                data.update(payload)
                return {"channel_id": channel, "key_id": payload["key_id"]}
            if path == "/v1/keys/fetch":
                return {"devices": devices, "channel_id": channel, "key_id": data["key_id"],
                        "sender_device_id": alice.device_id,
                        "envelope": data["envelopes"][bob.device_id], "role": "owner"}
            raise AssertionError(path)
        with patch("client.relay_identity._native_vault", side_effect=lambda: vaults[current[0].device_id]), \
             patch.object(DeviceVault, "load", lambda _self: current[0]), \
             patch.object(relay_keys, "request_json", side_effect=request):
            with self.assertRaises(IdentityError):
                relay_keys.share(origin, channel, [bob.device_id])
            for actor, peer, descriptor in ((alice, bob, devices[1]), (bob, alice, devices[0])):
                current[0] = actor
                relay_keys.trust_device(origin, peer.device_id,
                                        relay_keys.public_device_fingerprint(descriptor, origin))
            current[0] = alice
            relay_keys.share(origin, channel, [bob.device_id])
            current[0] = bob
            relay_keys.load(origin, channel)
            bob_key = ChannelKeyStore(origin).load(channel)
            current[0] = alice
            self.assertEqual(ChannelKeyStore(origin).load(channel), bob_key)
            # A valid signature under an attacker key is rejected against the pinned sender.
            current[0] = bob
            forged = LocalKey(alice.device_id, Ed25519PrivateKey.generate())
            devices[0] = device(forged)
            with self.assertRaises(IdentityError):
                relay_keys.load(origin, channel)


if __name__ == "__main__":
    unittest.main()
