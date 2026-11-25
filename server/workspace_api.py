"""HTTP boundary for projects and channels. Every operation is device-authenticated."""

import asyncio
from typing import Annotated

from fastapi import APIRouter, Request
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, ConfigDict, Field, UUID4
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.responses import JSONResponse

from server import identity, workspace

router = APIRouter()
_HEADERS = {"Cache-Control": "no-store"}
_NAME = Annotated[str, Field(min_length=1, max_length=100)]
_SLUG = Annotated[str, Field(pattern=r"^[a-z0-9]+(-[a-z0-9]+)*$", max_length=64)]
_PROOF = Annotated[str, Field(min_length=40, max_length=3500)]
_LIMIT = Annotated[int, Field(ge=1, le=100)]


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Authorized(_Request):
    device_id: UUID4
    proof: _PROOF


class ProjectRequest(Authorized):
    name: _NAME
    slug: _SLUG | None = None


class SubchannelRequest(Authorized):
    parent_id: UUID4
    name: _NAME
    slug: _SLUG | None = None
    access: str = Field(default="inherit", pattern="^(inherit|restricted)$")


class ListRequest(Authorized):
    project_id: UUID4 | None = None
    limit: _LIMIT = 50
    cursor: UUID4 | None = None


def error(status: int) -> JSONResponse:
    return JSONResponse({"status": "rejected"}, status_code=status, headers=_HEADERS)


class WorkspaceBodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST" or not scope["path"].startswith("/v1/workspace/"):
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


async def _run(request: Request, body, action):
    try:
        async with asyncio.timeout(8):
            async with request.app.state.engine.begin() as conn:
                # Authenticate and mutate in one transaction, then return after commit.
                summary = await identity.authenticate_workspace(
                    conn, body.device_id, body.proof, request.app.state.public_url,
                )
                result = await action(conn, summary["account_id"], body)
    except identity.Denied as denied:
        return error(denied.status)
    except IntegrityError:
        return error(409)
    except (OSError, SQLAlchemyError, TimeoutError):
        return error(503)
    return JSONResponse(jsonable_encoder(result), headers=_HEADERS)


@router.post("/v1/workspace/projects")
async def projects(body: ProjectRequest, request: Request):
    return await _run(request, body, workspace.create_project)


@router.post("/v1/workspace/subchannels")
async def subchannels(body: SubchannelRequest, request: Request):
    return await _run(request, body, workspace.create_subchannel)


@router.post("/v1/workspace/list-projects")
async def list_projects(body: ListRequest, request: Request):
    return await _run(request, body, workspace.list_projects)


@router.post("/v1/workspace/list-channels")
async def list_channels(body: ListRequest, request: Request):
    return await _run(request, body, workspace.list_channels)
