"""HTTP boundary for one-time channel invitations. Codes never reach the model."""

import asyncio
from typing import Annotated

from fastapi import APIRouter, Request
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, ConfigDict, Field, UUID4
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.responses import JSONResponse

from server import identity, invitations

router = APIRouter()
_HEADERS = {"Cache-Control": "no-store"}
_CODE = Annotated[str, Field(pattern=f"^{invitations.CODE_PATTERN}$", max_length=54)]
_PROOF = Annotated[str, Field(min_length=40, max_length=3500)]
_KEY = Annotated[str, Field(pattern=invitations.KEY_PATTERN, min_length=43, max_length=43)]


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Authorized(_Request):
    device_id: UUID4
    proof: _PROOF


class IssueRequest(Authorized):
    channel_id: UUID4
    role: str
    expires_in: int | None = Field(default=None, ge=invitations.MIN_TTL, le=invitations.MAX_TTL)


class StatusRequest(Authorized):
    channel_id: UUID4


class RevokeRequest(Authorized):
    invite_id: UUID4


class RedeemRequest(_Request):
    code: _CODE
    device_id: UUID4
    public_key: _KEY
    proof: _PROOF


def error(status: int) -> JSONResponse:
    return JSONResponse({"status": "rejected"}, status_code=status, headers=_HEADERS)


async def _authorized(request: Request, body, action):
    try:
        async with asyncio.timeout(8):
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


@router.post("/v1/invites/issue")
async def issue(body: IssueRequest, request: Request):
    return await _authorized(
        request, body,
        lambda conn, user, payload: invitations.issue(
            conn, user, payload.channel_id, payload.role, payload.expires_in,
        ),
    )


@router.post("/v1/invites/status")
async def status(body: StatusRequest, request: Request):
    return await _authorized(
        request, body,
        lambda conn, user, payload: invitations.status(conn, user, payload.channel_id),
    )


@router.post("/v1/invites/revoke")
async def revoke(body: RevokeRequest, request: Request):
    return await _authorized(
        request, body,
        lambda conn, user, payload: invitations.revoke(conn, user, payload.invite_id),
    )


@router.post("/v1/invites/redeem")
async def redeem(body: RedeemRequest, request: Request):
    try:
        async with asyncio.timeout(8):
            async with request.app.state.engine.begin() as conn:
                result = await invitations.redeem(
                    conn, body.code, body.device_id, body.public_key,
                    body.proof, request.app.state.public_url,
                )
    except identity.Denied as denied:
        return error(denied.status)
    except (ValueError, TypeError):
        return error(422)
    except IntegrityError:
        return error(409)
    except (OSError, SQLAlchemyError, TimeoutError):
        return error(503)
    return JSONResponse(jsonable_encoder(result), headers=_HEADERS)
