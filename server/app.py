"""Infrastructure-only ASGI app. Collaboration endpoints are not enabled."""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import create_async_engine

from server import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.public_url = settings.public_url()
    settings.redis_url()  # Validate optional deployment config; no Redis adapter yet.
    engine = create_async_engine(
        settings.database_url(),
        connect_args={"connect_timeout": 3},
        hide_parameters=True,
        pool_pre_ping=True,
        pool_size=4,
        max_overflow=0,
        pool_timeout=3,
    )
    app.state.engine = engine
    try:
        yield
    finally:
        await engine.dispose()


app = FastAPI(
    title="MCP Agent",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/ready")
async def ready(request: Request):
    try:
        async with asyncio.timeout(3):
            async with request.app.state.engine.connect() as connection:
                version = await connection.scalar(text("SHOW server_version_num"))
                if int(version) // 10000 != settings.POSTGRES_MAJOR:
                    return JSONResponse({"status": "not_ready"}, status_code=503)
                revision = await connection.scalar(text("SELECT version_num FROM alembic_version LIMIT 1"))
                if not revision:
                    return JSONResponse({"status": "not_ready"}, status_code=503)
    except (OSError, SQLAlchemyError, TimeoutError):
        return JSONResponse({"status": "not_ready"}, status_code=503)
    return {"status": "ready"}
