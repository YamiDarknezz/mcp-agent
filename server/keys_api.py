"""HTTP boundary for end-to-end key distribution. No plaintext crosses it."""

import asyncio
from typing import Annotated

from fastapi import APIRouter, Request
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, ConfigDict, Field, UUID4
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.responses import JSONResponse

from server import identity, keys

router = APIRouter()
_HEADERS = {"Cache-Control": "no-store"}
_PROOF = Annotated[str, Field(min_length=40, max_length=3500)]
_PUBLIC = Annotated[str, Field(min_length=1, max_length=128)]
_SIGNATURE = Annotated[str, Field(min_length=1, max_length=128)]
_ENVELOPE = Annotated[str, Field(min_length=80, max_length=4096)]


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Authorized(_Request):
    device_id: UUID4
    proof: _PROOF


class DeviceKeyRequest(Authorized):
    public_key: _PUBLIC
    signature: _SIGNATURE


class PublishRequest(Authorized):
    channel_id: UUID4
    key_id: UUID4
    envelopes: dict[str, _ENVELOPE] = Field(min_length=1, max_length=64)


class FetchRequest(Authorized):
    channel_id: UUID4


def error(status: int) -> JSONResponse:
    return JSONResponse({"status": "rejected"}, status_code=status, headers=_HEADERS)


async def _run(request: Request, body, action):
    try:
        async with asyncio.timeout(12):
            async with request.app.state.engine.begin() as conn:
                summary = await identity.authenticate_workspace(
                    conn, body.device_id, body.proof, request.app.state.public_url,
                )
                result = await action(conn, summary["account_id"], body)
    except identity.Denied as denied:
        return error(denied.status)
    except (ValueError, TypeError):
        return error(422)
    except IntegrityError:
        return error(409)
    except (OSError, SQLAlchemyError, TimeoutError):
        return error(503)
    return JSONResponse(jsonable_encoder(result), headers=_HEADERS)


async def _device_key(conn, _user_id, body):
    return await keys.publish_device_key(conn, body.device_id, body.public_key, body.signature)


async def _list_devices(conn, user_id, _body):
    return await keys.list_devices(conn, user_id)


async def _publish(conn, user_id, body):
    return await keys.publish_channel_key(
        conn, user_id, body.device_id, body.channel_id, body.key_id, body.envelopes,
    )


async def _fetch(conn, user_id, body):
    return await keys.fetch_channel_key(conn, user_id, body.device_id, body.channel_id)


@router.post("/v1/devices/encryption-key")
async def device_key(body: DeviceKeyRequest, request: Request):
    return await _run(request, body, _device_key)


@router.post("/v1/devices/list")
async def devices(body: Authorized, request: Request):
    return await _run(request, body, _list_devices)


@router.post("/v1/keys/publish")
async def publish(body: PublishRequest, request: Request):
    return await _run(request, body, _publish)


@router.post("/v1/keys/fetch")
async def fetch(body: FetchRequest, request: Request):
    return await _run(request, body, _fetch)
