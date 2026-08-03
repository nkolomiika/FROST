from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app import models  # noqa: F401
from app.config import get_settings
from app.database import Base, SessionLocal, engine
from app.exceptions import ConflictError, ForbiddenError, NotFoundError, PCFError, UnauthorizedError, ValidationError
from app.routers import (
    agent_tokens,
    assets,
    audit_logs,
    auth,
    comments,
    farm,
    files,
    images,
    import_,
    jira,
    notifications,
    projects,
    project_credentials,
    project_notes,
    reports,
    scanner,
    users,
    vulnerabilities,
    v2_agent,
    websocket,
)
from app.services import UserService
from app.storage.minio_client import MinioStorage

settings = get_settings()

app = FastAPI(title="PCF API", version="1.0.0", openapi_url="/api/v1/openapi.json")
agent_api_v2 = FastAPI(
    title="PCF Agent API",
    version="2.0.0",
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With", "Origin", "Accept"],
)


def _register_routes() -> None:
    prefix = "/api/v1"
    app.include_router(auth.router, prefix=prefix)
    app.include_router(agent_tokens.router, prefix=prefix)
    app.include_router(users.router, prefix=prefix)
    app.include_router(projects.router, prefix=prefix)
    app.include_router(project_notes.router, prefix=prefix)
    app.include_router(project_credentials.router, prefix=prefix)
    app.include_router(assets.router, prefix=prefix)
    app.include_router(farm.router, prefix=prefix)
    app.include_router(scanner.router, prefix=prefix)
    app.include_router(vulnerabilities.router, prefix=prefix)
    app.include_router(files.router, prefix=prefix)
    app.include_router(images.router, prefix=prefix)
    app.include_router(comments.router, prefix=prefix)
    app.include_router(notifications.router, prefix=prefix)
    app.include_router(import_.router, prefix=prefix)
    app.include_router(jira.router, prefix=prefix)
    app.include_router(reports.router, prefix=prefix)
    app.include_router(audit_logs.router, prefix=prefix)
    agent_api_v2.include_router(v2_agent.router)
    app.mount("/v2", agent_api_v2)
    app.include_router(websocket.router)


def _register_error_handlers() -> None:
    def _format_request_validation(exc: RequestValidationError) -> str:
        messages: list[str] = []
        for item in exc.errors():
            raw_loc = [str(part) for part in item.get("loc", [])]
            loc = ".".join(part for part in raw_loc if part not in {"body", "query", "path"})
            error_type = item.get("type", "")
            if error_type == "missing":
                message = "Поле обязательно"
            elif error_type == "string_too_short":
                min_length = item.get("ctx", {}).get("min_length")
                message = "Поле не может быть пустым" if min_length == 1 else f"Минимальная длина: {min_length}"
            elif error_type == "string_too_long":
                max_length = item.get("ctx", {}).get("max_length")
                message = f"Максимальная длина: {max_length}"
            elif error_type == "greater_than_equal":
                value = item.get("ctx", {}).get("ge")
                message = f"Значение должно быть не меньше {value}"
            elif error_type == "less_than_equal":
                value = item.get("ctx", {}).get("le")
                message = f"Значение должно быть не больше {value}"
            else:
                message = item.get("msg", "Некорректные входные данные")
            messages.append(f"{loc}: {message}" if loc else message)
        return "; ".join(messages) or "Некорректные входные данные"

    @app.exception_handler(RequestValidationError)
    async def request_validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": _format_request_validation(exc)})

    @app.exception_handler(NotFoundError)
    async def not_found_handler(_: Request, exc: NotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(UnauthorizedError)
    async def unauthorized_handler(_: Request, exc: UnauthorizedError) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": str(exc)})

    @app.exception_handler(ForbiddenError)
    async def forbidden_handler(_: Request, exc: ForbiddenError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(ConflictError)
    async def conflict_handler(_: Request, exc: ConflictError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(ValidationError)
    async def validation_handler(_: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(PCFError)
    async def app_error_handler(_: Request, exc: PCFError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.on_event("startup")
async def startup() -> None:
    """Инициализирует БД, MinIO и стартового администратора."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        if conn.dialect.name == "postgresql":
            await conn.execute(text("ALTER TYPE project_status ADD VALUE IF NOT EXISTS 'handover_to_development'"))
            await conn.execute(text("ALTER TYPE project_status ADD VALUE IF NOT EXISTS 'vulnerability_recheck'"))
            # Критичность 'UNKNOWN' убрана: по умолчанию находка создаётся как INFO.
            # Старые находки со снятым уровнем переводим в INFO (severity::text — на
            # свежей БД метки 'UNKNOWN' в типе уже нет, каст к тексту не падает), и
            # переставляем DEFAULT колонки. Дубль-метка 'UNKNOWN'/'unknown' остаётся в
            # типе безвредным висяком (снять её из enum — только пересозданием типа,
            # это делает alembic-ревизия; здесь довольно того, что ею никто не пишет).
            await conn.execute(
                text("UPDATE vulnerabilities SET severity = 'INFO' WHERE severity::text IN ('UNKNOWN', 'unknown')")
            )
            await conn.execute(text("ALTER TABLE vulnerabilities ALTER COLUMN severity SET DEFAULT 'INFO'"))
            await conn.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS folder VARCHAR(255) NOT NULL DEFAULT ''"))
            await conn.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS timeline_frozen_at TIMESTAMP WITH TIME ZONE"))
            await conn.execute(text("ALTER TABLE projects ALTER COLUMN folder SET DEFAULT ''"))
            await conn.execute(text("UPDATE projects SET folder = '' WHERE folder = 'Без папки'"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(255)"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS tags JSON"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_minio_bucket VARCHAR(63)"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_minio_key TEXT"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_content_type VARCHAR(127)"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_uploaded_at TIMESTAMP WITH TIME ZONE"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP WITH TIME ZONE"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT false"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_confirmed_at TIMESTAMP WITH TIME ZONE"))
            await conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_locked BOOLEAN NOT NULL DEFAULT false"))
            await conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS workflow_steps JSON"))
            await conn.execute(
                text(
                    """
                    UPDATE vulnerabilities
                    SET workflow_steps = (
                        SELECT json_agg(step - 'title')
                        FROM jsonb_array_elements(workflow_steps::jsonb) AS step
                    )
                    WHERE workflow_steps IS NOT NULL
                      AND jsonb_typeof(workflow_steps::jsonb) = 'array'
                    """
                )
            )
            await conn.execute(text("ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS query_params JSON"))
            await conn.execute(text("ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS request_body TEXT"))
            await conn.execute(text("ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS request_content_type VARCHAR(127)"))
            await conn.execute(text("ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS request_headers JSON"))
            await conn.execute(text("ALTER TABLE ports ADD COLUMN IF NOT EXISTS http_status INTEGER"))
            # Рекон-ферма: происхождение хоста, обратный резолв и признак Cloudflare.
            await conn.execute(text("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS origin VARCHAR(16) NOT NULL DEFAULT 'host'"))
            await conn.execute(text("ALTER TABLE host_ip_addresses ADD COLUMN IF NOT EXISTS hostnames JSON"))
            await conn.execute(text("ALTER TABLE host_ip_addresses ADD COLUMN IF NOT EXISTS is_cloudflare BOOLEAN NOT NULL DEFAULT false"))
            # is_cloudflare стал трёхзначным (NULL = ещё неизвестно / пробится): снимаем NOT NULL и default.
            await conn.execute(text("ALTER TABLE host_ip_addresses ALTER COLUMN is_cloudflare DROP NOT NULL"))
            await conn.execute(text("ALTER TABLE host_ip_addresses ALTER COLUMN is_cloudflare DROP DEFAULT"))
            await conn.execute(text("ALTER TABLE host_farm_jobs ADD COLUMN IF NOT EXISTS kind VARCHAR(16) NOT NULL DEFAULT 'hosts'"))
            await conn.execute(text("ALTER TABLE host_farm_jobs ADD COLUMN IF NOT EXISTS raw TEXT"))
            await conn.execute(text("ALTER TABLE host_farm_jobs ADD COLUMN IF NOT EXISTS attempts INTEGER NOT NULL DEFAULT 0"))
            await conn.execute(text("ALTER TABLE host_farm_jobs ADD COLUMN IF NOT EXISTS published_at TIMESTAMP WITH TIME ZONE"))
            await conn.execute(text("ALTER TABLE host_farm_jobs ADD COLUMN IF NOT EXISTS last_error TEXT"))
            await conn.execute(text("ALTER TABLE host_farm_jobs ADD COLUMN IF NOT EXISTS skipped_targets JSON"))
            await conn.execute(text("UPDATE users SET tags = '[]'::json WHERE tags IS NULL"))
            await conn.execute(text("UPDATE endpoints SET query_params = '[]'::json WHERE query_params IS NULL"))
            await conn.execute(text("UPDATE endpoints SET request_headers = '[]'::json WHERE request_headers IS NULL"))
            await conn.execute(text("UPDATE host_ip_addresses SET hostnames = '[]'::json WHERE hostnames IS NULL"))
        elif conn.dialect.name == "sqlite":
            async def add_missing(table: str, columns: dict[str, str]) -> None:
                """SQLite не умеет ADD COLUMN IF NOT EXISTS — проверяем через PRAGMA."""
                present = {row[1] for row in (await conn.execute(text(f"PRAGMA table_info({table})"))).fetchall()}
                for name, ddl in columns.items():
                    if name not in present:
                        await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {ddl}"))

            await add_missing(
                "projects",
                {
                    "folder": "folder VARCHAR(255) NOT NULL DEFAULT ''",
                    "timeline_frozen_at": "timeline_frozen_at TIMESTAMP",
                },
            )
            await add_missing("users", {"is_locked": "is_locked BOOLEAN NOT NULL DEFAULT 0"})
            await add_missing("hosts", {"origin": "origin VARCHAR(16) NOT NULL DEFAULT 'host'"})
            await add_missing(
                "host_ip_addresses",
                {
                    "hostnames": "hostnames JSON",
                    "is_cloudflare": "is_cloudflare BOOLEAN NOT NULL DEFAULT 0",
                },
            )
            await add_missing(
                "host_farm_jobs",
                {
                    "kind": "kind VARCHAR(16) NOT NULL DEFAULT 'hosts'",
                    "raw": "raw TEXT",
                    "attempts": "attempts INTEGER NOT NULL DEFAULT 0",
                    "published_at": "published_at TIMESTAMP",
                    "last_error": "last_error TEXT",
                    "skipped_targets": "skipped_targets JSON",
                },
            )
    MinioStorage().ensure_bucket()
    async with SessionLocal() as db:
        service = UserService(db)
        await service.bootstrap_admin()


@app.get("/health")
async def health() -> dict:
    """Healthcheck эндпоинт для проверки доступности сервиса."""
    return {"status": "ok"}


_register_routes()
_register_error_handlers()
