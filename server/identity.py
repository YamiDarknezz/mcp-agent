"""One-time enrollment and Ed25519 device proofs. No raw codes are stored."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256
import re
import secrets
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import jwt
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

from server import settings

CODE_PATTERN = r"relay_(?:boot|pair)_[A-Za-z0-9_-]{43}"
PROOF_TYPE = "relay-device+jwt"
PROOF_LIFETIME = 60
PROOF_LEEWAY = 5
CHALLENGE_LIFETIME = 120


class Denied(Exception):
    def __init__(self, status: int = 401):
        self.status = status
        super().__init__("Identity operation denied.")


def new_engine():
    return create_async_engine(
        settings.database_url(),
        connect_args={"connect_timeout": 3, "options": "-c statement_timeout=5000 -c lock_timeout=3000"},
        hide_parameters=True,
        pool_pre_ping=True,
        pool_size=4,
        max_overflow=0,
        pool_timeout=3,
    )


async def _run(conn: AsyncConnection, query: str, **params):
    return await conn.execute(text(query), params)


async def _row(conn: AsyncConnection, query: str, **params):
    return (await _run(conn, query, **params)).mappings().one_or_none()


async def _audit(conn, action, subject=None):
    await record_security_event(conn, action, subject)


async def record_security_event(conn, action, subject=None):
    await _run(
        conn, "INSERT INTO security_events (id, action, subject_id) VALUES (:id, :action, :subject)",
        id=uuid4(), action=action, subject=subject,
    )


def _digest(code):
    if not isinstance(code, str) or not re.fullmatch(CODE_PATTERN, code):
        raise Denied()
    return sha256(code.encode("ascii")).digest()


async def _installation(conn):
    installation = await _row(conn, "SELECT * FROM installation WHERE id = 1 FOR UPDATE")
    if not installation:
        raise Denied(503)
    return installation


async def _device(conn, device_id):
    device = await _row(conn, "SELECT * FROM devices WHERE id = :id FOR UPDATE", id=device_id)
    if not device or device["revoked_at"] is not None:
        raise Denied()
    return device


async def _issue(conn, purpose, ttl, issuer=None):
    now = datetime.now(UTC)
    if purpose == "bootstrap":
        if (await _installation(conn))["operator_user_id"] is not None:
            raise Denied(409)
        scope = "purpose = 'bootstrap'"
        token = f"relay_boot_{secrets.token_urlsafe(32)}"
    else:
        scope = "issuer_device_id = :issuer"
        token = f"relay_pair_{secrets.token_urlsafe(32)}"
    await _run(
        conn, f"""UPDATE enrollment_codes SET revoked_at = :now
                 WHERE {scope} AND revoked_at IS NULL AND consumed_at IS NULL""",
        now=now, issuer=issuer,
    )
    expires = now + timedelta(seconds=ttl)
    code_id = uuid4()
    await _run(
        conn, """INSERT INTO enrollment_codes
                 (id, digest, purpose, issuer_device_id, created_at, expires_at)
                 VALUES (:id, :digest, :purpose, :issuer, :now, :expires)""",
        id=code_id, digest=_digest(token), purpose=purpose, issuer=issuer, now=now, expires=expires,
    )
    await _audit(conn, f"{purpose}_issued", code_id)
    return {"code": token, "expires_at": expires}


async def issue_bootstrap(conn, ttl):
    return await _issue(conn, "bootstrap", ttl)


async def _active_code(conn, code):
    digest = _digest(code)
    pointer = await _row(
        conn, "SELECT purpose, issuer_device_id FROM enrollment_codes WHERE digest = :digest", digest=digest,
    )
    if not pointer:
        raise Denied()
    # Always lock installation/issuer before the code row, including during rotation.
    issuer = None
    if pointer["purpose"] == "bootstrap":
        if (await _installation(conn))["operator_user_id"] is not None:
            raise Denied()
    else:
        issuer = await _device(conn, pointer["issuer_device_id"])
    entry = await _row(
        conn, "SELECT * FROM enrollment_codes WHERE digest = :digest FOR UPDATE", digest=digest,
    )
    if not entry or entry["revoked_at"] or entry["consumed_at"] or entry["expires_at"] <= datetime.now(UTC):
        raise Denied()
    return entry, issuer


async def start_enrollment(conn, code, device_id, public_key):
    entry, _ = await _active_code(conn, code)
    challenge = secrets.token_urlsafe(32)
    expires = min(entry["expires_at"], datetime.now(UTC) + timedelta(seconds=CHALLENGE_LIFETIME))
    await _run(
        conn, """UPDATE enrollment_codes SET challenge=:challenge, challenge_expires_at=:expires,
                    candidate_device_id=:device_id, candidate_key=:key WHERE id=:id""",
        challenge=challenge, expires=expires, device_id=device_id, key=public_key, id=entry["id"],
    )
    return {"challenge": challenge}


def verify_proof(public_key, proof, audience, device_id, purpose):
    try:
        if jwt.get_unverified_header(proof).get("typ") != PROOF_TYPE:
            raise Denied()
        claims = jwt.decode(
            proof, Ed25519PublicKey.from_public_bytes(public_key), algorithms=["EdDSA"],
            audience=audience, leeway=PROOF_LEEWAY,
            options={"require": ["aud", "sub", "iat", "exp", "jti", "purpose"], "strict_aud": True},
        )
        if not isinstance(claims["jti"], str):
            raise Denied()
        jti = UUID(claims["jti"])
        if not (
            claims["sub"] == str(device_id) and claims["purpose"] == purpose
            and type(claims["iat"]) is int and type(claims["exp"]) is int
            and 0 < claims["exp"] - claims["iat"] <= PROOF_LIFETIME
            and jti.version == 4 and str(jti) == claims["jti"]
        ):
            raise Denied()
        return claims, jti
    except (jwt.PyJWTError, TypeError, ValueError, OverflowError, RecursionError):
        raise Denied() from None


def _label(value, limit, required=True):
    if value is None and not required:
        return None
    if not isinstance(value, str) or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise Denied(422)
    value = value.strip()
    if not 1 <= len(value) <= limit:
        raise Denied(422)
    return value


async def claim_enrollment(conn, code, device_id, proof, audience):
    entry, issuer = await _active_code(conn, code)
    now = datetime.now(UTC)
    if (
        entry["candidate_device_id"] != device_id
        or not entry["challenge_expires_at"]
        or entry["challenge_expires_at"] <= now
    ):
        raise Denied()
    claims, _ = verify_proof(entry["candidate_key"], proof, audience, device_id, "enroll")
    challenge = claims.get("challenge")
    if (
        not isinstance(challenge, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{43}", challenge)
        or not secrets.compare_digest(challenge, entry["challenge"])
    ):
        raise Denied()
    label = _label(claims.get("device_label"), 100)
    is_first = issuer is None
    if is_first:
        user_id = uuid4()
        await _run(
            conn, "INSERT INTO users (id, display_name, declared_email) VALUES (:id, :name, :email)",
            id=user_id, name=_label(claims.get("display_name"), 100),
            email=_label(claims.get("declared_email"), 254, required=False),
        )
        await _run(
            conn, "UPDATE installation SET operator_user_id=:user_id, activated_at=:now WHERE id=1",
            user_id=user_id, now=now,
        )
    else:
        user_id = issuer["user_id"]
    await _run(
        conn, """INSERT INTO devices (id, user_id, public_key, label)
                 VALUES (:id, :user_id, :public_key, :label)""",
        id=device_id, user_id=user_id, public_key=entry["candidate_key"], label=label,
    )
    await _run(
        conn, """UPDATE enrollment_codes SET consumed_at=:now, challenge=NULL,
                   challenge_expires_at=NULL, candidate_device_id=NULL, candidate_key=NULL WHERE id=:id""",
        now=now, id=entry["id"],
    )
    await _audit(conn, "bootstrap_claimed" if is_first else "device_paired", device_id)
    return await _summary(conn, device_id, user_id)


async def _summary(conn, device_id, user_id):
    installation = await _row(conn, "SELECT operator_user_id FROM installation WHERE id = 1")
    return {
        "device_id": str(device_id),
        "account_id": str(user_id),
        "is_operator": installation["operator_user_id"] == user_id,
    }


async def _authenticate(conn, device_id, proof, audience, purpose):
    device = await _device(conn, device_id)
    claims, proof_id = verify_proof(device["public_key"], proof, audience, device_id, purpose)
    await _run(
        conn, """DELETE FROM device_proofs WHERE device_id=:id AND expires_at <= clock_timestamp()""",
        id=device_id,
    )
    accepted = await _row(
        conn, """INSERT INTO device_proofs (device_id, proof_id, expires_at)
                 VALUES (:device_id, :proof_id, :expires)
                 ON CONFLICT DO NOTHING RETURNING proof_id""",
        device_id=device_id, proof_id=proof_id, expires=datetime.fromtimestamp(claims["exp"] + PROOF_LEEWAY, UTC),
    )
    if not accepted:
        raise Denied()
    return device


async def identify(conn, device_id, proof, audience):
    device = await _authenticate(conn, device_id, proof, audience, "identify")
    return await _summary(conn, device_id, device["user_id"])


async def authenticate_workspace(conn, device_id, proof, audience):
    """Authorize a workspace operation with a proof scoped to that purpose."""
    device = await _authenticate(conn, device_id, proof, audience, "workspace")
    return await _summary(conn, device_id, device["user_id"])


async def issue_pair_code(conn, device_id, proof, audience, ttl):
    await _authenticate(conn, device_id, proof, audience, "pair")
    return await _issue(conn, "pair", ttl, issuer=device_id)


async def revoke_device(conn, device_id):
    await _device(conn, device_id)
    now = datetime.now(UTC)
    await _run(conn, "UPDATE devices SET revoked_at=:now WHERE id=:id", now=now, id=device_id)
    await _run(
        conn, """UPDATE enrollment_codes SET revoked_at=:now
                 WHERE issuer_device_id=:id AND revoked_at IS NULL AND consumed_at IS NULL""",
        now=now, id=device_id,
    )
    await _audit(conn, "device_revoked", device_id)
