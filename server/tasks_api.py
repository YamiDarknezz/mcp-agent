"""HTTP boundary for encrypted tasks. No plaintext crosses it."""

import asyncio
from typing import Annotated, Literal

from fastapi import APIRouter, Request
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, ConfigDict, Field, UUID4
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.responses import JSONResponse

from server import identity, tasks

router = APIRouter()
_HEADERS = {"Cache-Control": "no-store"}
_PROOF = Annotated[str, Field(min_length=40, max_length=3500)]


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Authorized(_Request):
    device_id: UUID4
    proof: _PROOF


class ProposeRequest(Authorized):
    channel_id: UUID4
    task_id: UUID4
    operation_id: UUID4
    nonce: str = Field(min_length=16, max_length=32)
    ciphertext: str = Field(min_length=22, max_length=5500)


class ChannelRequest(Authorized):
    channel_id: UUID4


class ListRequest(Authorized):
    channel_id: UUID4
    status: Literal["open", "claimed", "done", "cancelled"] | None = None
    limit: int = Field(default=30, ge=1, le=100)


class TaskDeviceRequest(ChannelRequest):
    task_id: UUID4


class CompleteRequest(TaskDeviceRequest):
    generation: int = Field(ge=1)


def error(status: int) -> JSONResponse:
    return JSONResponse({"status": "rejected"}, status_code=status, headers=_HEADERS)


async def _run(request: Request, body, action):
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


async def _propose(conn, user_id, body):
    return await tasks.propose(conn, user_id, body)


async def _list(conn, user_id, body):
    return await tasks.list_tasks(conn, user_id, body)


async def _claim(conn, user_id, body):
    return await tasks.claim(conn, user_id, body)


async def _release(conn, user_id, body):
    return await tasks.release(conn, user_id, body)


async def _complete(conn, user_id, body):
    return await tasks.complete(conn, user_id, body)


@router.post("/v1/tasks/propose")
async def propose(body: ProposeRequest, request: Request):
    return await _run(request, body, _propose)


@router.post("/v1/tasks/list")
async def list_tasks(body: ListRequest, request: Request):
    return await _run(request, body, _list)


@router.post("/v1/tasks/claim")
async def claim(body: TaskDeviceRequest, request: Request):
    return await _run(request, body, _claim)


@router.post("/v1/tasks/release")
async def release(body: TaskDeviceRequest, request: Request):
    return await _run(request, body, _release)


@router.post("/v1/tasks/complete")
async def complete(body: CompleteRequest, request: Request):
    return await _run(request, body, _complete)
