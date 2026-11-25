"""Real PostgreSQL and HTTP smoke, only against a fresh disposable database."""

import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
import json
import os
import time
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import jwt
from sqlalchemy import text

from server import identity, settings

_HTTP = "http://127.0.0.1:8000"


class TestKey:
    def __init__(self):
        self.id = uuid4()
        self.key = Ed25519PrivateKey.generate()

    def pub(self):
        return base64.urlsafe_b64encode(self.key.public_key().public_bytes_raw()).decode().rstrip("=")

    def proof(self, purpose, **claims):
        now = int(time.time())
        return {
            "device_id": str(self.id),
            "proof": jwt.encode(
                {
                    "aud": settings.public_url(), "sub": str(self.id), "purpose": purpose,
                    "iat": now, "exp": now + 45, "jti": str(uuid4()), **claims,
                },
                self.key, algorithm="EdDSA", headers={"typ": "relay-device+jwt"},
            ),
        }


def post(path, body):
    request = Request(
        _HTTP + path, data=json.dumps(body).encode(), method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        response = urlopen(request, timeout=8)
    except HTTPError as error:
        response = error
    with response:
        assert response.headers["Cache-Control"] == "no-store"
        payload = json.load(response)
        if response.status != 200:
            assert payload == {"status": "rejected"}
        return response.status, payload


async def console(action, *args):
    engine = identity.new_engine()
    try:
        async with engine.begin() as connection:
            return await action(connection, *args)
    finally:
        await engine.dispose()


async def verify_disposable(connection):
    state = (await connection.execute(text("SELECT operator_user_id FROM installation WHERE id=1"))).scalar_one()
    if state is not None:
        raise RuntimeError("Refusing to run activation smoke on an activated instance.")


def challenge(code, key):
    return post(
        "/v1/enrollment/challenge",
        {"code": code, "device_id": str(key.id), "public_key": key.pub()},
    )


def run():
    if os.getenv("RELAY_ACTIVATION_TEST_DB") != settings.database_url().database:
        raise RuntimeError("Explicit disposable database opt-in is required.")
    asyncio.run(console(verify_disposable))

    first = TestKey()
    class Past(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) - timedelta(hours=1)

    with patch.object(identity, "datetime", Past):
        expired = asyncio.run(console(identity.issue_bootstrap, 900))["code"]
    assert challenge(expired, first)[0] == 401
    old = asyncio.run(console(identity.issue_bootstrap, 900))["code"]
    code = asyncio.run(console(identity.issue_bootstrap, 900))["code"]
    assert challenge(old, first)[0] == 401
    assert post("/v1/enrollment/claim", {"code": code, "extra": "secret-sentinel"})[0] == 422
    assert post("/v1/enrollment/challenge", {"code": "x" * 9000})[0] == 413
    status, proposed = challenge(code, first)
    assert status == 200
    wrong = TestKey()
    wrong.id = first.id
    forged = wrong.proof("enroll", challenge=proposed["challenge"], device_label="Wrong", display_name="Wrong")
    assert post("/v1/enrollment/claim", {"code": code, **forged})[0] == 401
    signed = first.proof("enroll", challenge=proposed["challenge"], device_label="First", display_name="Operator")
    with ThreadPoolExecutor(max_workers=2) as jobs:
        results = list(jobs.map(lambda _: post("/v1/enrollment/claim", {"code": code, **signed}), range(2)))
    assert sorted(result[0] for result in results) == [200, 401]
    owner = next(payload for status, payload in results if status == 200)
    assert owner["is_operator"] is True
    try:
        asyncio.run(console(identity.issue_bootstrap, 900))
    except identity.Denied as error:
        assert error.status == 409
    else:
        raise AssertionError("An activated instance issued another bootstrap.")

    signed = first.proof("identify")
    assert post("/v1/devices/pair-code", signed)[0] == 401
    assert post("/v1/devices/me", first.proof("identify", aud="https://other.example.org"))[0] == 401
    now = int(time.time())
    assert post("/v1/devices/me", first.proof("identify", iat=now-120, exp=now-90))[0] == 401
    assert post("/v1/devices/me", signed) == (200, owner)
    assert post("/v1/devices/me", signed)[0] == 401
    status, issued = post("/v1/devices/pair-code", first.proof("pair"))
    assert status == 200
    second = TestKey()
    status, proposed = challenge(issued["code"], second)
    assert status == 200
    payload = {
        "code": issued["code"],
        **second.proof("enroll", challenge=proposed["challenge"], device_label="Second"),
    }
    status, paired = post("/v1/enrollment/claim", payload)
    assert status == 200 and paired["account_id"] == owner["account_id"]
    assert paired["device_id"] != owner["device_id"]
    assert post("/v1/enrollment/claim", payload)[0] == 401
    status, stale = post("/v1/devices/pair-code", second.proof("pair"))
    assert status == 200
    asyncio.run(console(identity.revoke_device, second.id))
    assert post("/v1/devices/me", second.proof("identify"))[0] == 401
    assert challenge(stale["code"], TestKey())[0] == 401
    assert post("/v1/devices/me", first.proof("identify"))[0] == 200
    print("Verified one-time activation, replay, pairing and revocation in PostgreSQL and HTTP.")


if __name__ == "__main__":
    run()
