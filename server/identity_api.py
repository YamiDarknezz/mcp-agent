"""Enrollment HTTP boundary. Invalid requests never echo input values."""

import asyncio
import base64
from typing import Annotated

from fastapi import APIRouter, Request
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, ConfigDict, Field, UUID4
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.responses import JSONResponse

from server import identity

router = APIRouter()
_HEADERS = {"Cache-Control": "no-store"}
_CODE = Annotated[str, Field(pattern=f"^{identity.CODE_PATTERN}$", max_length=54)]
_PROOF = Annotated[str, Field(min_length=40, max_length=3500)]


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ChallengeRequest(_Request):
    code: _CODE
    device_id: UUID4
    public_key: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$", min_length=43, max_length=43)


class DeviceRequest(_Request):
    device_id: UUID4
    proof: _PROOF


class ClaimRequest(DeviceRequest):
    code: _CODE


def error(status: int) -> JSONResponse:
    return JSONResponse({"status": "rejected"}, status_code=status, headers=_HEADERS)


class IdentityBodyLimit:
    """Cap auth payloads before FastAPI parses them, including chunked requests."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http" or scope["method"] != "POST"
            or not scope["path"].startswith(("/v1/enrollment/", "/v1/devices/"))
        ):
            await self.app(scope, receive, send)
            return

        body = bytearray()
        try:
            async with asyncio.timeout(5):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    chunk = message.get("body", b"")
                    if len(body) + len(chunk) > 8192:
                        await error(413)(scope, receive, send)
                        return
                    body.extend(chunk)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            await error(408)(scope, receive, send)
            return

        sent = False

        async def buffered():
            nonlocal sent
            if sent:
                return await receive()
            sent = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, buffered, send)


async def _transaction(request: Request, action, *args):
    try:
        async with asyncio.timeout(7):
            async with request.app.state.engine.begin() as conn:
                result = await action(conn, *args)
    except identity.Denied as denied:
        return error(denied.status)
    except IntegrityError:
        return error(409)
    except (OSError, SQLAlchemyError, TimeoutError):
        return error(503)
    return JSONResponse(jsonable_encoder(result), headers=_HEADERS)


@router.post("/v1/enrollment/challenge")
async def challenge(body: ChallengeRequest, request: Request):
    raw_key = base64.urlsafe_b64decode(body.public_key + "=")
    if base64.urlsafe_b64encode(raw_key).decode().rstrip("=") != body.public_key:
        return error(422)
    return await _transaction(request, identity.start_enrollment, body.code, body.device_id, raw_key)


@router.post("/v1/enrollment/claim")
async def claim(body: ClaimRequest, request: Request):
    return await _transaction(
        request, identity.claim_enrollment, body.code, body.device_id, body.proof, request.app.state.public_url,
    )


@router.post("/v1/devices/me")
async def me(body: DeviceRequest, request: Request):
    return await _transaction(request, identity.identify, body.device_id, body.proof, request.app.state.public_url)


@router.post("/v1/devices/pair-code")
async def pair(body: DeviceRequest, request: Request):
    return await _transaction(
        request, identity.issue_pair_code, body.device_id, body.proof, request.app.state.public_url,
        request.app.state.enrollment_ttl,
    )
