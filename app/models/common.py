import uuid
from datetime import UTC, datetime

from sqlalchemy import BigInteger, DateTime, Integer, Uuid
from sqlalchemy.orm import MappedColumn, mapped_column
from sqlalchemy.types import TypeEngine


def utcnow() -> datetime:
    return datetime.now(UTC)


def uuid_pk() -> MappedColumn[uuid.UUID]:
    return mapped_column(Uuid, primary_key=True, default=uuid.uuid4)


def created_at() -> MappedColumn[datetime]:
    return mapped_column(DateTime(timezone=True), default=utcnow)


def updated_at() -> MappedColumn[datetime]:
    return mapped_column(DateTime(timezone=True), default=utcnow)


def audit_seq() -> MappedColumn[int]:
    """Autoincrement PK that is BIGINT on Postgres and INTEGER on SQLite.

    Plain BIGINT does not auto increment on SQLite (only INTEGER PRIMARY KEY
    aliases rowid), so the dialect variant keeps both databases working.
    """
    variant: TypeEngine[int] = BigInteger().with_variant(Integer, "sqlite")
    return mapped_column(variant, primary_key=True, autoincrement=True)
