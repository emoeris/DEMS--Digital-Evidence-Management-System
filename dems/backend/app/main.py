"""FastAPI application factory.

Run (development):   uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000
Run (local HTTPS):   add  --ssl-certfile certs/localhost.pem --ssl-keyfile certs/localhost-key.pem
"""
from __future__ import annotations

import asyncio
import logging
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import audit, auth, cases, custody, evidence
from app.core.config import Settings, get_settings
from app.core.crypto import KeyServiceNotInitialized, initialize_key_service, key_service
from app.db.session import dispose_engine, init_db
from app.services.errors import ServiceError

logger = logging.getLogger("dems")
_UPLOAD_PATH = "/evidence/upload"
_MULTIPART_OVERHEAD = 2 * 1024 * 1024  # form fields and boundaries on top of the file itself


def ensure_vault(path: Path) -> Path:
    """Create the vault (0700) or refuse to run if an existing one is accessible to other users."""
    path = Path(path)
    created = not path.exists()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        if created:
            os.chmod(path, 0o700)
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            raise RuntimeError(f"Vault directory {path} has insecure permissions ({oct(mode)}); run: chmod 700 {path}")
    return path.resolve()


def _json(status: int, code: str, detail: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"detail": detail, "code": code}, status_code=status, headers=headers)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    production = settings.environment == "production"

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        ensure_vault(settings.vault_path)
        # Derive the KEK (Argon2id) from the passphrase into memory only; blocking, so off the loop.
        await asyncio.to_thread(initialize_key_service, settings)
        await init_db()  # creates missing tables; use Alembic migrations for production schema changes
        try:
            yield
        finally:
            key_service.close()
            await dispose_engine()

    app = FastAPI(
        title="Secure Digital Evidence Management System",
        version="1.0.0",
        lifespan=lifespan,
        docs_url=None if production else "/docs",
        redoc_url=None,
        openapi_url=None if production else "/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["Content-Disposition", "X-Content-SHA256", "X-Request-ID"],
        max_age=600,
    )

    @app.middleware("http")
    async def guard_and_harden(request: Request, call_next):
        request_id = uuid.uuid4().hex
        request.state.request_id = request_id
        if request.method == "POST" and request.url.path == _UPLOAD_PATH:
            # Multipart bodies are parsed before dependencies run, so refuse oversized or anonymous uploads here.
            if not request.headers.get("authorization"):
                return _json(401, "not_authenticated", "Authentication required.", {"WWW-Authenticate": "Bearer"})
            length = request.headers.get("content-length")
            if length is None or not length.isdigit():
                return _json(411, "length_required", "A Content-Length header is required for uploads.")
            if int(length) > settings.upload_max_bytes + _MULTIPART_OVERHEAD:
                return _json(413, "file_too_large", f"Upload exceeds the {settings.upload_max_bytes}-byte limit.")
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        response.headers.setdefault("Cache-Control", "no-store")
        if production:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    @app.exception_handler(ServiceError)
    async def service_error_handler(_: Request, exc: ServiceError) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None
        return _json(exc.status_code, exc.code, exc.message, headers)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Never echo submitted values back (they may be passwords): location, message and type only.
        errors = [{"loc": list(e.get("loc", ())), "msg": e.get("msg", ""), "type": e.get("type", "")} for e in exc.errors()]
        return JSONResponse({"detail": "Request validation failed.", "code": "validation_error", "errors": errors}, status_code=422)

    @app.exception_handler(KeyServiceNotInitialized)
    async def locked_handler(_: Request, __: KeyServiceNotInitialized) -> JSONResponse:
        return _json(503, "keys_locked", "The evidence key service is locked.")

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
        rid = getattr(request.state, "request_id", "-")
        logger.error("unhandled %s request_id=%s", type(exc).__name__, rid)  # type only: messages may hold sensitive data
        return _json(500, "internal_error", f"Internal server error (request {rid}).")

    @app.get("/health", tags=["system"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    for module in (auth, cases, evidence, custody, audit):
        app.include_router(module.router)
    return app
