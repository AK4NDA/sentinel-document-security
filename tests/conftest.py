import base64
import os
from pathlib import Path

import pytest
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

os.environ.setdefault("ENV", "dev")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("MASTER_KEY", base64.b64encode(b"\x00" * 32).decode("ascii"))
os.environ.setdefault("UPLOAD_DIR", str(Path("data/test-uploads")))
os.environ.setdefault("LOG_LEVEL", "INFO")
os.environ.setdefault("RATE_LIMIT_ENABLED", "false")

# Set by the client fixture so helpers like auth_client can reach the test DB.
SESSION_FACTORY = None


@pytest.fixture
async def client(session_factory):
    global SESSION_FACTORY
    SESSION_FACTORY = session_factory

    from httpx import ASGITransport, AsyncClient

    from app.core.database import get_db
    from app.main import app

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as http:
        yield http
    app.dependency_overrides.clear()
    SESSION_FACTORY = None


@pytest.fixture
async def session_factory():
    """Fresh in memory database with all tables, shared FK enforcement."""
    from app.models import Base

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _fk(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    await engine.dispose()
