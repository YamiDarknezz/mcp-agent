"""End-to-end encryption smoke against a fresh disposable PostgreSQL database.

Proves the server never sees plaintext or channel keys, and that two distinct
devices can agree on a key without sharing a private key.
"""

import asyncio
import base64
import json
import os
import time
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import UUID, uuid4

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
    root_id = project["project"]["id"]
    channel_id = project["main"]["id"]
    channel_key = crypto.new_channel_key()
    active_key_id = str(uuid4())

    def envelope_for(device):
        envelope = crypto.wrap_channel_key(
            alice.x, device.x.public_key(), channel_key, channel_id,
            str(alice.id), str(device.id),
        )
        return crypto.sign_envelope(alice.ed, envelope, channel_id, active_key_id,
                                    str(alice.id), str(device.id))

    status, _ = post("/v1/keys/publish", {
        **alice.proof("workspace"), "channel_id": root_id, "key_id": str(uuid4()),
        "envelopes": {str(alice.id): envelope_for(alice)},
    })
    assert status == 404
    status, _ = post("/v1/keys/publish", {
        **alice.proof("workspace"), "channel_id": channel_id, "key_id": str(uuid4()),
        "envelopes": {str(uuid4()): envelope_for(alice)},
    })
    assert status == 404

    # Create isolated fixtures directly: real invitations are not implemented yet.
    outsider, reader, revoked = Device(), Device(), Device()
    outsider_user, reader_user, revoked_user = uuid4(), uuid4(), uuid4()

    async def add_fixtures(conn):
        for device, user_id in ((outsider, outsider_user), (reader, reader_user), (revoked, revoked_user)):
            await conn.execute(text("INSERT INTO users (id, display_name) VALUES (:id, 'Fixture')"), {"id": user_id})
            await conn.execute(text("""
                INSERT INTO devices (id, user_id, label, public_key, encryption_public_key,
                                     encryption_signature, encryption_updated_at, revoked_at)
                VALUES (:id, :user_id, 'Fixture', :auth, :enc, :sig, now(),
                        CASE WHEN :revoked THEN now() ELSE NULL END)
            """), {
                "id": device.id, "user_id": user_id, "auth": device.ed.public_key().public_bytes_raw(),
                "enc": crypto.public_bytes(device.x.public_key()),
                "sig": crypto.sign_encryption_key(device.ed, device.x.public_key()),
                "revoked": device is revoked,
            })
        await conn.execute(text("""
            INSERT INTO channel_memberships (channel_id, user_id, role)
            VALUES (:channel, :user_id, 'reader')
        """), {"channel": channel_id, "user_id": reader_user})
    asyncio.run(console(add_fixtures))

    status, subscribed = post("/v1/workspace/list-subscriptions", alice.proof("workspace"))
    assert status == 200 and subscribed["items"] == [{"channel_id": channel_id, "mode": "mentions"}]
    status, work = post("/v1/workspace/subchannels", {
        **alice.proof("workspace"), "parent_id": root_id, "name": "Development",
    })
    assert status == 200
    work_id = work["channel"]["id"]
    status, subscribed = post("/v1/workspace/list-subscriptions", bob.proof("workspace"))
    assert status == 200 and subscribed["items"] == [{"channel_id": channel_id, "mode": "mentions"}]
    status, _ = post("/v1/workspace/set-subscription", {
        **alice.proof("workspace"), "channel_id": root_id, "mode": "all",
    })
    assert status == 403
    status, _ = post("/v1/workspace/set-subscription", {
        **outsider.proof("workspace"), "channel_id": work_id, "mode": "all",
    })
    assert status == 404
    for mode in ("all", "muted", "mentions"):
        status, changed = post("/v1/workspace/set-subscription", {
            **alice.proof("workspace"), "channel_id": work_id, "mode": mode,
        })
        assert status == 200 and changed["mode"] == mode
    status, first_page = post("/v1/workspace/list-subscriptions", {
        **alice.proof("workspace"), "limit": 1,
    })
    assert status == 200 and len(first_page["items"]) == 1 and first_page["next_cursor"]
    status, second_page = post("/v1/workspace/list-subscriptions", {
        **alice.proof("workspace"), "limit": 1, "cursor": first_page["next_cursor"],
    })
    assert status == 200 and len(second_page["items"]) == 1
    assert {first_page["items"][0]["channel_id"], second_page["items"][0]["channel_id"]} == {channel_id, work_id}
    status, _ = post("/v1/workspace/set-subscription", {
        **alice.proof("workspace"), "channel_id": work_id, "mode": None,
    })
    assert status == 200
    status, subscribed = post("/v1/workspace/list-subscriptions", alice.proof("workspace"))
    assert status == 200 and subscribed["items"] == [{"channel_id": channel_id, "mode": "mentions"}]

    for target in (outsider, revoked):
        status, _ = post("/v1/keys/publish", {
            **alice.proof("workspace"), "channel_id": channel_id, "key_id": str(uuid4()),
            "envelopes": {str(target.id): envelope_for(target)},
        })
        assert status == 404
    status, _ = post("/v1/keys/publish", {
        **alice.proof("workspace"), "channel_id": channel_id, "key_id": str(uuid4()),
        "envelopes": {str(alice.id): envelope_for(alice), str(outsider.id): envelope_for(outsider)},
    })
    assert status == 404
    status, _ = post("/v1/keys/publish", {
        **alice.proof("workspace"), "channel_id": channel_id, "key_id": str(uuid4()),
        "envelopes": {str(alice.id): "!" * 120},
    })
    assert status == 422
    status, _ = post("/v1/keys/publish", {
        **reader.proof("workspace"), "channel_id": channel_id, "key_id": str(uuid4()),
        "envelopes": {str(reader.id): envelope_for(reader)},
    })
    assert status == 403

    status, published = post("/v1/keys/publish", {
        **alice.proof("workspace"), "channel_id": channel_id, "key_id": active_key_id,
        "envelopes": {str(alice.id): envelope_for(alice), str(bob.id): envelope_for(bob)},
    })
    assert status == 200 and published["recipients"] == 2
    # A different key must never replace an existing channel key.
    status, _ = post("/v1/keys/publish", {
        **alice.proof("workspace"), "channel_id": channel_id, "key_id": str(uuid4()),
        "envelopes": {str(bob.id): envelope_for(bob)},
    })
    assert status == 409
    # Adding a recipient later must reuse the same key without changing it.
    status, extended = post("/v1/keys/publish", {
        **alice.proof("workspace"), "channel_id": channel_id, "key_id": published["key_id"],
        "envelopes": {str(bob.id): envelope_for(bob)},
    })
    assert status == 200 and extended["key_id"] == published["key_id"] and extended["recipients"] == 2

    status, fetched = post("/v1/keys/fetch", {**bob.proof("workspace"), "channel_id": channel_id})
    assert status == 200
    verified = crypto.verify_envelope(
        alice.ed.public_key(), fetched["envelope"], channel_id, fetched["key_id"],
        str(alice.id), str(bob.id),
    )
    unwrapped = crypto.unwrap_channel_key(
        bob.x, verified, channel_id, str(alice.id), str(bob.id)
    )
    assert unwrapped == channel_key
    assert crypto.fingerprint(channel_key) not in json.dumps(fetched)

    plaintext = b"clave-solo-del-equipo"
    nonce, ciphertext = crypto.encrypt_message(channel_key, channel_id, 3, plaintext)
    assert plaintext not in base64.urlsafe_b64decode(ciphertext + "=" * (-len(ciphertext) % 4))
    assert crypto.decrypt_message(unwrapped, channel_id, 3, nonce, ciphertext) == plaintext

    operation_id = uuid4()
    aad_sequence = operation_id.int & ((1 << 64) - 1)
    nonce, ciphertext = crypto.encrypt_message(channel_key, channel_id, aad_sequence, plaintext)
    payload = {"channel_id": channel_id, "operation_id": str(operation_id),
               "nonce": nonce, "ciphertext": ciphertext}
    status, sent = post("/v1/workspace/send-message", {**alice.proof("workspace"), **payload})
    assert status == 200 and sent["seq"] == 1
    status, retry = post("/v1/workspace/send-message", {**alice.proof("workspace"), **payload})
    assert status == 200 and retry == sent
    status, _ = post("/v1/workspace/send-message", {
        **alice.proof("workspace"), **payload, "ciphertext": crypto.b64(b"x" * 24),
    })
    assert status == 409
    status, page = post("/v1/workspace/read-messages", {
        **bob.proof("workspace"), "channel_id": channel_id,
    })
    assert status == 200 and len(page["messages"]) == 1
    item = page["messages"][0]
    assert crypto.decrypt_message(unwrapped, channel_id, aad_sequence, item["nonce"], item["ciphertext"]) == plaintext
    status, page = post("/v1/workspace/read-messages", {
        **bob.proof("workspace"), "channel_id": channel_id, "after": 1,
    })
    assert status == 200 and page["messages"] == []
    status, _ = post("/v1/workspace/read-messages", {
        **outsider.proof("workspace"), "channel_id": channel_id,
    })
    assert status == 404
    status, _ = post("/v1/workspace/send-message", {
        **reader.proof("workspace"), **payload, "operation_id": str(uuid4()),
    })
    assert status == 403

    # --- Tasks: encrypted content, generation-based reservations, stale completion. ---
    task_id = str(uuid4())
    task_op = str(uuid4())
    task_raw = b"{\"summary\":\"Preparar informe\",\"objective\":\"\", \"links\":[]}"
    task_nonce, task_ciphertext = crypto.encrypt_task(channel_key, channel_id, task_id, task_raw)
    status, proposed = post("/v1/tasks/propose", {
        **alice.proof("workspace"), "channel_id": channel_id, "task_id": task_id,
        "operation_id": task_op, "nonce": task_nonce, "ciphertext": task_ciphertext,
    })
    assert status == 200 and proposed["task_id"] == task_id
    status, retry_propose = post("/v1/tasks/propose", {
        **alice.proof("workspace"), "channel_id": channel_id, "task_id": task_id,
        "operation_id": task_op, "nonce": task_nonce, "ciphertext": task_ciphertext,
    })
    assert status == 200 and retry_propose == proposed
    status, task_page = post("/v1/tasks/list", {**bob.proof("workspace"), "channel_id": channel_id})
    assert status == 200 and len(task_page["tasks"]) == 1
    listed = task_page["tasks"][0]
    assert crypto.decrypt_task(channel_key, channel_id, task_id, listed["nonce"], listed["ciphertext"]) == task_raw
    assert listed["status"] == "open" and listed["generation"] == 0

    status, _ = post("/v1/tasks/propose", {
        **outsider.proof("workspace"), "channel_id": channel_id, "task_id": str(uuid4()),
        "operation_id": str(uuid4()), "nonce": task_nonce, "ciphertext": task_ciphertext,
    })
    assert status == 404
    status, _ = post("/v1/tasks/list", {**reader.proof("workspace"), "channel_id": channel_id})
    assert status == 200  # reader may read tasks
    status, _ = post("/v1/tasks/claim", {
        **reader.proof("workspace"), "channel_id": channel_id, "task_id": task_id,
    })
    assert status == 403

    status, claim_bob = post("/v1/tasks/claim", {
        **bob.proof("workspace"), "channel_id": channel_id, "task_id": task_id,
    })
    assert status == 200 and claim_bob["generation"] == 1
    status, _ = post("/v1/tasks/claim", {
        **alice.proof("workspace"), "channel_id": channel_id, "task_id": task_id,
    })
    assert status == 409  # one winner
    # Stale completion must fail after the lease is released and generation advances.
    status, _ = post("/v1/tasks/release", {
        **bob.proof("workspace"), "channel_id": channel_id, "task_id": task_id,
    })
    assert status == 200
    status, claim_alice = post("/v1/tasks/claim", {
        **alice.proof("workspace"), "channel_id": channel_id, "task_id": task_id,
    })
    assert status == 200 and claim_alice["generation"] == 3
    status, _ = post("/v1/tasks/complete", {
        **bob.proof("workspace"), "channel_id": channel_id, "task_id": task_id, "generation": 1,
    })
    assert status == 409
    status, done = post("/v1/tasks/complete", {
        **alice.proof("workspace"), "channel_id": channel_id, "task_id": task_id,
        "generation": claim_alice["generation"],
    })
    assert status == 200 and done["generation"] == 4
    status, final_page = post("/v1/tasks/list", {
        **alice.proof("workspace"), "channel_id": channel_id, "status": "done",
    })
    assert status == 200 and any(t["task_id"] == task_id for t in final_page["tasks"])

    async def inspect(conn):
        stored = (await conn.execute(text("SELECT key_id FROM channel_keys WHERE channel_id=:id"), {"id": channel_id})).scalar_one()
        assert str(stored) != crypto.b64(channel_key)
        envelopes = (await conn.execute(text("SELECT envelope FROM channel_key_envelopes WHERE channel_id=:id"), {"id": channel_id})).scalars().all()
        assert all(channel_key not in bytes(e) for e in envelopes)
        assert all(plaintext not in bytes(e) for e in envelopes)
        stored_message = (await conn.execute(text(
            "SELECT ciphertext FROM channel_messages WHERE channel_id=:id"
        ), {"id": channel_id})).scalar_one()
        assert plaintext not in bytes(stored_message)
        stored_task = (await conn.execute(text(
            "SELECT ciphertext FROM tasks WHERE id=:id"
        ), {"id": UUID(task_id)})).scalar_one()
        assert b"Preparar informe" not in bytes(stored_task)
    asyncio.run(console(inspect))

    async def live_smoke():
        async with connect("ws://127.0.0.1:8000/v1/live", proxy=None, open_timeout=5) as socket:
            await socket.send(json.dumps({**bob.proof("workspace"), "channel_id": channel_id}))
            assert json.loads(await socket.recv()) == {"type": "ready"}
            op = uuid4()
            live_nonce, live_ciphertext = crypto.encrypt_message(
                channel_key, channel_id, op.int & ((1 << 64) - 1), b"live-test",
            )
            live_status, _ = await asyncio.to_thread(post, "/v1/workspace/send-message", {
                **alice.proof("workspace"), "channel_id": channel_id, "operation_id": str(op),
                "nonce": live_nonce, "ciphertext": live_ciphertext,
            })
            assert live_status == 200
            event = json.loads(await asyncio.wait_for(socket.recv(), timeout=8))
            assert event["type"] == "changed"
            await console(identity.revoke_device, bob.id)
            try:
                while True:
                    await asyncio.wait_for(socket.recv(), timeout=8)
            except ConnectionClosed as error:
                assert error.rcvd and error.rcvd.code == 1008
    asyncio.run(live_smoke())

    print("Verified key access, messages, tasks, WebSocket notifications and revocation.")


if __name__ == "__main__":
    main()
