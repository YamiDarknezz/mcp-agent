"""End-to-end encryption smoke against a fresh disposable PostgreSQL database.

Proves the server never sees plaintext or channel keys, and that two distinct
devices can agree on a key without sharing a private key.
"""

import asyncio
import base64
import json
import os
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from client import relay_crypto as crypto
from server import identity, settings

_HTTP = "http://127.0.0.1:8000"


class Device:
    def __init__(self):
        self.id = uuid4()
        self.ed = Ed25519PrivateKey.generate()
        seed = self.ed.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        self.x = crypto.derive_encryption_key(seed)

    def auth_pub(self):
        return crypto.b64(self.ed.public_key().public_bytes_raw())

    def xpub(self):
        return crypto.b64(crypto.public_bytes(self.x.public_key()))

    def signature(self):
        return crypto.b64(crypto.sign_encryption_key(self.ed, self.x.public_key()))

    def proof(self, purpose, **claims):
        now = int(time.time())
        return {
            "device_id": str(self.id),
            "proof": __import__("jwt").encode(
                {
                    "aud": settings.public_url(), "sub": str(self.id), "purpose": purpose,
                    "iat": now, "exp": now + 45, "jti": str(uuid4()), **claims,
                },
                self.ed, algorithm="EdDSA", headers={"typ": "relay-device+jwt"},
            ),
        }


def post(path, body):
    req = Request(
        _HTTP + path, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        response = urlopen(req, timeout=12)
    except HTTPError as error:
        response = error
    with response:
        payload = json.load(response)
        if response.status != 200:
            assert payload == {"status": "rejected"}, (path, response.status, payload)
        return response.status, payload


async def console(action, *args):
    engine = identity.new_engine()
    try:
        async with engine.begin() as conn:
            return await action(conn, *args)
    finally:
        await engine.dispose()


async def verify_disposable(conn):
    state = (await conn.execute(text("SELECT operator_user_id FROM installation WHERE id=1"))).scalar_one()
    if state is not None:
        raise RuntimeError("Refusing to run encryption smoke on an activated instance.")
    count = (await conn.execute(text("SELECT count(*) FROM channel_keys"))).scalar_one()
    if count:
        raise RuntimeError("Refusing to run on an instance that already has channel keys.")


def main():
    if os.getenv("RELAY_ACTIVATION_TEST_DB") != settings.database_url().database:
        raise RuntimeError("Explicit disposable database opt-in is required.")
    asyncio.run(console(verify_disposable))

    alice, bob = Device(), Device()
    code = asyncio.run(console(identity.issue_bootstrap, 900))["code"]
    status, challenge = post("/v1/enrollment/challenge", {
        "code": code, "device_id": str(alice.id), "public_key": alice.auth_pub(),
    })
    assert status == 200
    status, _ = post("/v1/enrollment/claim", {
        "code": code, **alice.proof("enroll", challenge=challenge["challenge"],
                                   device_label="Alice", display_name="Alice"),
    })
    assert status == 200

    status, pair = post("/v1/devices/pair-code", alice.proof("pair"))
    assert status == 200
    status, challenge = post("/v1/enrollment/challenge", {
        "code": pair["code"], "device_id": str(bob.id), "public_key": bob.auth_pub(),
    })
    assert status == 200
    status, _ = post("/v1/enrollment/claim", {
        "code": pair["code"], **bob.proof("enroll", challenge=challenge["challenge"], device_label="Bob"),
    })
    assert status == 200

    # A forged signature must not be accepted by the server.
    status, _ = post("/v1/devices/encryption-key", {
        **alice.proof("workspace"), "public_key": bob.xpub(), "signature": alice.signature(),
    })
    assert status == 401
    for device in (alice, bob):
        status, result = post("/v1/devices/encryption-key", {
            **device.proof("workspace"), "public_key": device.xpub(), "signature": device.signature(),
        })
        assert status == 200
        assert result["fingerprint"] == crypto.fingerprint(crypto.public_bytes(device.x.public_key()))

    status, listed = post("/v1/devices/list", alice.proof("workspace"))
    assert status == 200
    found = {d["id"]: d for d in listed["devices"]}
    assert {str(alice.id), str(bob.id)} <= set(found)
    assert all(d["fingerprint"] for d in found.values())

    status, project = post("/v1/workspace/projects", {**alice.proof("workspace"), "name": "Tesis"})
    assert status == 200
    channel_id = project["project"]["id"]
    channel_key = crypto.new_channel_key()

    def envelope_for(device):
        return crypto.wrap_channel_key(
            alice.x, device.x.public_key(), channel_key, channel_id,
            str(alice.id), str(device.id),
        )

    status, published = post("/v1/keys/publish", {
        **alice.proof("workspace"), "channel_id": channel_id, "key_id": str(uuid4()),
        "envelopes": {str(alice.id): envelope_for(alice), str(bob.id): envelope_for(bob)},
    })
    assert status == 200 and published["recipients"] == 2
    status, _ = post("/v1/keys/publish", {
        **bob.proof("workspace"), "channel_id": channel_id, "key_id": str(uuid4()),
        "envelopes": {str(bob.id): envelope_for(bob)},
    })
    assert status == 409

    status, fetched = post("/v1/keys/fetch", {**bob.proof("workspace"), "channel_id": channel_id})
    assert status == 200
    unwrapped = crypto.unwrap_channel_key(
        bob.x, fetched["envelope"], channel_id, str(alice.id), str(bob.id)
    )
    assert unwrapped == channel_key
    assert crypto.fingerprint(channel_key) not in json.dumps(fetched)

    plaintext = b"clave-solo-del-equipo"
    nonce, ciphertext = crypto.encrypt_message(channel_key, channel_id, 3, plaintext)
    assert plaintext not in base64.urlsafe_b64decode(ciphertext + "=" * (-len(ciphertext) % 4))
    assert crypto.decrypt_message(unwrapped, channel_id, 3, nonce, ciphertext) == plaintext

    async def inspect(conn):
        stored = (await conn.execute(text("SELECT key_id FROM channel_keys WHERE channel_id=:id"), {"id": channel_id})).scalar_one()
        assert str(stored) != crypto.b64(channel_key)
        envelopes = (await conn.execute(text("SELECT envelope FROM channel_key_envelopes WHERE channel_id=:id"), {"id": channel_id})).scalars().all()
        assert all(channel_key not in bytes(e) for e in envelopes)
        assert all(plaintext not in bytes(e) for e in envelopes)
    asyncio.run(console(inspect))

    print("Verified signed device keys, opaque envelopes and E2E message confidentiality.")


if __name__ == "__main__":
    main()
