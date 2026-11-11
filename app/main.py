from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api import alerts as alerts_router
from app.api import audit as audit_router
from app.api import auth as auth_router
from app.api import documents as documents_router
from app.api import shares as shares_router
from app.api import users as users_router
from app.api.auth import limiter
from app.api.health import router as health_router
from app.core.config import get_settings
from app.core.database import engine
from app.core.logging import configure_logging


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    yield
    await engine.dispose()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Classified Document Access Control",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if settings.env == "dev" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.env == "dev" else None,
    )
    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.include_router(health_router)
    app.include_router(auth_router.router)
    app.include_router(users_router.router)
    app.include_router(documents_router.router)
    app.include_router(shares_router.router)
    app.include_router(audit_router.router)
    app.include_router(alerts_router.router)
    return app


app = create_app()
