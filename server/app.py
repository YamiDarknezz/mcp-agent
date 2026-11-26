"""Relay API: health checks and device enrollment, not collaboration."""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from server import identity, identity_api, keys_api, live, settings, tasks_api, workspace_api


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.public_url = settings.public_url()
    app.state.enrollment_ttl = settings.enrollment_code_ttl()
    settings.redis_url()  # Validate optional deployment config; no Redis adapter yet.
    engine = identity.new_engine()
    app.state.engine = engine
    app.state.notification_hub = live.NotificationHub()
    listener = asyncio.create_task(app.state.notification_hub.run())
    try:
        yield
    finally:
        listener.cancel()
        await asyncio.gather(listener, return_exceptions=True)
        await engine.dispose()


app = FastAPI(
    title="MCP Agent",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.include_router(identity_api.router)
app.include_router(workspace_api.router)
app.include_router(keys_api.router)
app.include_router(live.router)
app.include_router(tasks_api.router)


class BodyLimit:
    def __init__(self, app):
        self.inner = identity_api.IdentityBodyLimit(app)
        self.workspace = workspace_api.WorkspaceBodyLimit(self.inner)

    async def __call__(self, scope, receive, send):
        await self.workspace(scope, receive, send)


app.add_middleware(BodyLimit)


@app.exception_handler(RequestValidationError)
async def invalid_request(_request: Request, _error: RequestValidationError):
    return identity_api.error(422)


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
                instance = await connection.scalar(text("""
                    SELECT id FROM installation WHERE id = 1
                    AND has_table_privilege('users', 'INSERT')
                    AND has_table_privilege('devices', 'INSERT')
                    AND has_column_privilege('devices', 'revoked_at', 'UPDATE')
                    AND has_column_privilege('installation', 'activated_at', 'UPDATE')
                    AND has_table_privilege('enrollment_codes', 'INSERT')
                    AND has_column_privilege('enrollment_codes', 'consumed_at', 'UPDATE')
                    AND has_table_privilege('device_proofs', 'INSERT')
                    AND has_table_privilege('device_proofs', 'DELETE')
                    AND has_table_privilege('security_events', 'INSERT')
                """))
                if not instance:
                    return JSONResponse({"status": "not_ready"}, status_code=503)
                tables = await connection.scalar(text("""
                    SELECT count(*) = 7 FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = ANY(ARRAY[
                        'users','devices','channels','channel_memberships','channel_subscriptions',
                        'channel_keys','channel_key_envelopes'
                    ])
                """))
                if not tables:
                    return JSONResponse({"status": "not_ready"}, status_code=503)
    except (OSError, SQLAlchemyError, TimeoutError):
        return JSONResponse({"status": "not_ready"}, status_code=503)
    return {"status": "ready"}
