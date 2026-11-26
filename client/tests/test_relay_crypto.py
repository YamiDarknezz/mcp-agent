import os
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from client import relay_crypto as crypto


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.alice_seed = os.urandom(32)
        self.bob_seed = os.urandom(32)
        self.alice_ed = Ed25519PrivateKey.from_private_bytes(self.alice_seed)
        self.bob_ed = Ed25519PrivateKey.from_private_bytes(self.bob_seed)
        self.alice_x = crypto.derive_encryption_key(self.alice_seed)
        self.bob_x = crypto.derive_encryption_key(self.bob_seed)
        self.channel = "11111111-1111-4111-8111-111111111111"
        self.alice_id = "22222222-2222-4222-8222-222222222222"
        self.bob_id = "33333333-3333-4333-8333-333333333333"
        self.key = crypto.new_channel_key()

    def test_key_derivation_is_deterministic_and_domain_separated(self):
        self.assertEqual(
            crypto.private_bytes(crypto.derive_encryption_key(self.alice_seed)),
            crypto.private_bytes(self.alice_x),
        )
        self.assertNotEqual(
            crypto.private_bytes(self.alice_x), crypto.private_bytes(self.bob_x)
        )
        self.assertNotEqual(
            crypto.private_bytes(self.alice_x), self.alice_seed
        )

    def test_encryption_key_signature_binds_device_and_catches_substitution(self):
        xpub = self.alice_x.public_key()
        signature = crypto.sign_encryption_key(self.alice_ed, xpub)
        self.assertTrue(crypto.verify_encryption_key(self.alice_ed.public_key(), xpub, signature))
        self.assertFalse(crypto.verify_encryption_key(self.bob_ed.public_key(), xpub, signature))
        forged = crypto.sign_encryption_key(self.bob_ed, self.bob_x.public_key())
        self.assertFalse(crypto.verify_encryption_key(self.alice_ed.public_key(), xpub, forged))

    def test_wrap_and_unwrap_only_work_for_the_intended_device_and_channel(self):
        envelope = crypto.wrap_channel_key(
            self.alice_x, self.bob_x.public_key(), self.key,
            self.channel, self.alice_id, self.bob_id,
        )
        self.assertEqual(
            crypto.unwrap_channel_key(self.bob_x, envelope, self.channel, self.alice_id, self.bob_id),
            self.key,
        )
        self.assertNotIn(crypto.b64(self.key), envelope)
        with self.assertRaises(ValueError):
            crypto.unwrap_channel_key(self.alice_x, envelope, self.channel, self.alice_id, self.bob_id)
        with self.assertRaises(ValueError):
            crypto.unwrap_channel_key(self.bob_x, envelope, self.channel, self.alice_id, self.alice_id)
        with self.assertRaises(ValueError):
            crypto.unwrap_channel_key(self.bob_x, envelope, self.bob_id, self.alice_id, self.bob_id)

    def test_modified_envelope_is_rejected(self):
        envelope = crypto.wrap_channel_key(
            self.alice_x, self.bob_x.public_key(), self.key,
            self.channel, self.alice_id, self.bob_id,
        )
        raw = bytearray(crypto.unb64(envelope))
        raw[-1] ^= 1
        with self.assertRaises(ValueError):
            crypto.unwrap_channel_key(
                self.bob_x, crypto.b64(bytes(raw)), self.channel, self.alice_id, self.bob_id
            )

    def test_message_aad_binds_channel_and_sequence(self):
        secret = b"contrasena-solo-para-el-equipo"
        nonce, ciphertext = crypto.encrypt_message(self.key, self.channel, 7, secret)
        self.assertNotIn(secret, crypto.unb64(ciphertext))
        self.assertEqual(
            crypto.decrypt_message(self.key, self.channel, 7, nonce, ciphertext), secret
        )
        for channel, seq in ((self.channel, 8), (self.bob_id, 7)):
            with self.subTest(channel=channel, seq=seq), self.assertRaises(ValueError):
                crypto.decrypt_message(self.key, channel, seq, nonce, ciphertext)
        with self.assertRaises(ValueError):
            crypto.decrypt_message(crypto.new_channel_key(), self.channel, 7, nonce, ciphertext)

    def test_fingerprint_is_short_stable_and_public(self):
        xpub = crypto.public_bytes(self.alice_x.public_key())
        first = crypto.fingerprint(xpub)
        self.assertEqual(first, crypto.fingerprint(xpub))
        self.assertEqual(len(first), 24)
        self.assertNotEqual(first, crypto.fingerprint(crypto.public_bytes(self.bob_x.public_key())))


if __name__ == "__main__":
    unittest.main()
