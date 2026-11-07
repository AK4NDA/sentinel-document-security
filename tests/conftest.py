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
