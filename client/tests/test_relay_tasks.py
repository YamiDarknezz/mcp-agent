import os
import unittest

from client import relay_crypto as crypto, relay_task_format as fmt


class TaskFormatTests(unittest.TestCase):
    def test_encode_decode_roundtrip_and_rejects_tampering(self):
        body = fmt.encode("Preparar informe", "Resumen y graficos", ["https://example.com/doc"])
        self.assertEqual(
            fmt.decode(body),
            ("Preparar informe", "Resumen y graficos", ["https://example.com/doc"]),
        )
        with self.assertRaises(ValueError):
            fmt.decode(b"legacy plain text")
        with self.assertRaises(ValueError):
            fmt.decode(body + b"tampered")
        with self.assertRaises(ValueError):
            fmt.encode("")
        with self.assertRaises(ValueError):
            fmt.encode("x", links=[3])
        with self.assertRaises(ValueError):
            fmt.encode("x" * 5000)

    def test_task_aad_binds_channel_and_task_and_hides_plaintext(self):
        key = crypto.new_channel_key()
        channel, task = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
        secret = b"clave-de-tarea-solo-local"
        nonce, ciphertext = crypto.encrypt_task(key, channel, task, secret)
        self.assertNotIn(secret, crypto.unb64(ciphertext))
        self.assertEqual(crypto.decrypt_task(key, channel, task, nonce, ciphertext), secret)
        for wrong_channel, wrong_task in ((channel, "33333333-3333-4333-8333-333333333333"),
                                          ("44444444-4444-4444-8444-444444444444", task)):
            with self.subTest(channel=wrong_channel, task=wrong_task), self.assertRaises(ValueError):
                crypto.decrypt_task(key, wrong_channel, wrong_task, nonce, ciphertext)


if __name__ == "__main__":
    unittest.main()
