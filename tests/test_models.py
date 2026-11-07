import os
import shutil
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import delete, event, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.models import (
    Alert,
    AuditLog,
    Base,
    ClassificationLevel,
    Document,
    DocumentShare,
    DocumentVersion,
    User,
    UserRole,
)
from app.models import (
    Session as UserSession,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
async def sessionmaker():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", poolclass=StaticPool)

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    yield maker
    await engine.dispose()


async def make_user(session: AsyncSession, username: str = "alice", **overrides) -> User:
    user = User(
        username=username,
        email=f"{username}@example.com",
        password_hash="argon2-hash",
        **overrides,
    )
    session.add(user)
    await session.flush()
    return user


async def make_document(
    session: AsyncSession,
    owner: User,
    classification: ClassificationLevel = ClassificationLevel.SECRET,
) -> Document:
    doc = Document(title="Test doc", owner_id=owner.id)
    session.add(doc)
    await session.flush()
    version = DocumentVersion(
        document_id=doc.id,
        version_number=1,
        classification=classification,
        content_sha256="a" * 64,
        blob_path="ab/cd.blob",
        size_bytes=10,
        mime_type="text/plain",
        created_by=owner.id,
    )
    session.add(version)
    await session.flush()
    doc.current_version_id = version.id
    await session.flush()
    return doc


async def test_uuid_primary_keys_and_defaults(sessionmaker):
    async with sessionmaker() as session:
        user = await make_user(session)
        await session.commit()
        assert isinstance(user.id, uuid.UUID)
        assert user.role.value == "user"
        assert user.clearance == ClassificationLevel.UNCLASSIFIED
        assert user.is_active is True
        assert user.failed_login_attempts == 0


async def test_unique_username_and_email(sessionmaker):
    async with sessionmaker() as session:
        await make_user(session, "alice")
        await session.commit()
        with pytest.raises(IntegrityError):
            async with session.begin_nested():
                session.add(User(username="alice", email="other@example.com", password_hash="x"))
                await session.flush()
        with pytest.raises(IntegrityError):
            async with session.begin_nested():
                session.add(User(username="bob", email="alice@example.com", password_hash="x"))
                await session.flush()


async def test_unique_session_token_hash(sessionmaker):
    async with sessionmaker() as session:
        user = await make_user(session)
        now = datetime.now(UTC)
        session.add(
            UserSession(
                user_id=user.id,
                token_hash="f" * 64,
                created_at=now,
                last_seen_at=now,
                expires_at=now,
            )
        )
        await session.commit()
        with pytest.raises(IntegrityError):
            async with session.begin_nested():
                session.add(
                    UserSession(
                        user_id=user.id,
                        token_hash="f" * 64,
                        created_at=now,
                        last_seen_at=now,
                        expires_at=now,
                    )
                )
                await session.flush()


async def test_unique_version_number_per_document(sessionmaker):
    async with sessionmaker() as session:
        owner = await make_user(session)
        doc = await make_document(session, owner)
        await session.commit()
        with pytest.raises(IntegrityError):
            async with session.begin_nested():
                session.add(
                    DocumentVersion(
                        document_id=doc.id,
                        version_number=1,
                        classification=ClassificationLevel.CONFIDENTIAL,
                        content_sha256="b" * 64,
                        blob_path="ab/ef.blob",
                        size_bytes=5,
                        mime_type="text/plain",
                        created_by=owner.id,
                    )
                )
                await session.flush()


async def test_unique_share_per_document_user(sessionmaker):
    async with sessionmaker() as session:
        owner = await make_user(session, "owner")
        grantee = await make_user(session, "grantee")
        doc = await make_document(session, owner)
        session.add(DocumentShare(document_id=doc.id, user_id=grantee.id, granted_by=owner.id))
        await session.commit()
        with pytest.raises(IntegrityError):
            async with session.begin_nested():
                session.add(
                    DocumentShare(document_id=doc.id, user_id=grantee.id, granted_by=owner.id)
                )
                await session.flush()


async def test_classification_check_constraint(sessionmaker):
    async with sessionmaker() as session:
        owner = await make_user(session)
        doc = Document(title="Bad", owner_id=owner.id)
        session.add(doc)
        await session.flush()
        for bad_value in (0, 6):
            with pytest.raises(IntegrityError):
                async with session.begin_nested():
                    session.add(
                        DocumentVersion(
                            document_id=doc.id,
                            version_number=bad_value,
                            classification=bad_value,
                            content_sha256="c" * 64,
                            blob_path="ab/x.blob",
                            size_bytes=1,
                            mime_type="text/plain",
                            created_by=owner.id,
                        )
                    )
                    await session.flush()
        with pytest.raises(IntegrityError):
            async with session.begin_nested():
                session.add(
                    User(
                        username="nope",
                        email="nope@example.com",
                        password_hash="x",
                        clearance=6,
                    )
                )
                await session.flush()


async def test_role_stored_as_lowercase_value(sessionmaker):
    async with sessionmaker() as session:
        user = User(
            username="dave",
            email="dave@example.com",
            password_hash="x",
            role=UserRole.ADMIN,
        )
        session.add(user)
        await session.commit()
        stored = (
            await session.execute(text("SELECT role FROM users WHERE username = 'dave'"))
        ).scalar_one()
        assert stored == "admin"
        assert user.role == UserRole.ADMIN


async def test_classification_rank_comparison_in_sql(sessionmaker):
    async with sessionmaker() as session:
        secret_user = await make_user(session, "secret", clearance=ClassificationLevel.SECRET)
        conf_user = await make_user(session, "conf", clearance=ClassificationLevel.CONFIDENTIAL)
        await session.commit()
        result = await session.execute(
            select(User.username).where(User.clearance >= ClassificationLevel.SECRET)
        )
        assert result.scalars().all() == [secret_user.username]
        assert conf_user.clearance < ClassificationLevel.SECRET


async def test_document_delete_cascades_versions_and_shares(sessionmaker):
    async with sessionmaker() as session:
        owner = await make_user(session, "owner")
        grantee = await make_user(session, "grantee")
        doc = await make_document(session, owner)
        session.add(DocumentShare(document_id=doc.id, user_id=grantee.id, granted_by=owner.id))
        await session.commit()
        doc_id = doc.id
        await session.execute(delete(Document).where(Document.id == doc_id))
        await session.commit()
        versions = await session.execute(
            select(DocumentVersion).where(DocumentVersion.document_id == doc_id)
        )
        shares = await session.execute(
            select(DocumentShare).where(DocumentShare.document_id == doc_id)
        )
        assert versions.scalars().all() == []
        assert shares.scalars().all() == []


async def test_orm_delete_document_cascades_versions_and_shares(sessionmaker):
    async with sessionmaker() as session:
        owner = await make_user(session, "owner")
        grantee = await make_user(session, "grantee")
        doc = await make_document(session, owner)
        session.add(DocumentShare(document_id=doc.id, user_id=grantee.id, granted_by=owner.id))
        await session.commit()
        doc_id = doc.id
        await session.delete(doc)
        await session.commit()
        versions = await session.execute(
            select(DocumentVersion).where(DocumentVersion.document_id == doc_id)
        )
        shares = await session.execute(
            select(DocumentShare).where(DocumentShare.document_id == doc_id)
        )
        assert versions.scalars().all() == []
        assert shares.scalars().all() == []


async def test_audit_log_and_alerts_survive_document_delete(sessionmaker):
    async with sessionmaker() as session:
        owner = await make_user(session)
        doc = await make_document(session, owner)
        await session.commit()
        doc_id = doc.id
        session.add(
            AuditLog(
                occurred_at=datetime.now(UTC),
                actor_id=owner.id,
                action="document.delete",
                outcome="allowed",
                target_type="document",
                target_id=str(doc_id),
                hash="d" * 64,
            )
        )
        session.add(
            Alert(
                alert_type="access.denied",
                severity="warning",
                document_id=doc_id,
                actor_id=owner.id,
            )
        )
        await session.commit()
        await session.execute(delete(Document).where(Document.id == doc_id))
        await session.commit()
        audit = await session.execute(select(AuditLog))
        alerts = await session.execute(select(Alert))
        assert len(audit.scalars().all()) == 1
        assert len(alerts.scalars().all()) == 1


async def test_audit_seq_auto_increments(sessionmaker):
    async with sessionmaker() as session:
        for i in range(3):
            session.add(
                AuditLog(
                    occurred_at=datetime.now(UTC),
                    action="test.event",
                    outcome="allowed",
                    hash=f"{i:064x}",
                )
            )
        await session.commit()
        result = await session.execute(select(AuditLog.seq).order_by(AuditLog.seq))
        assert result.scalars().all() == [1, 2, 3]


async def test_audit_outcome_check_constraint(sessionmaker):
    async with sessionmaker() as session:
        with pytest.raises(IntegrityError):
            async with session.begin_nested():
                session.add(
                    AuditLog(
                        occurred_at=datetime.now(UTC),
                        action="test.event",
                        outcome="maybe",
                        hash="e" * 64,
                    )
                )
                await session.flush()


async def test_user_delete_cascades_sessions_but_restrict_blocks_authors(sessionmaker):
    async with sessionmaker() as session:
        plain = await make_user(session, "plain")
        now = datetime.now(UTC)
        session.add(
            UserSession(
                user_id=plain.id,
                token_hash="1" * 64,
                created_at=now,
                last_seen_at=now,
                expires_at=now,
            )
        )
        await session.commit()
        await session.execute(delete(User).where(User.id == plain.id))
        await session.commit()
        sessions = await session.execute(select(UserSession).where(UserSession.user_id == plain.id))
        assert sessions.scalars().all() == []

    async with sessionmaker() as session:
        author = await make_user(session, "author")
        await make_document(session, author)
        await session.commit()
        with pytest.raises(IntegrityError):
            async with session.begin_nested():
                await session.execute(delete(User).where(User.id == author.id))
                await session.flush()


def test_migration_upgrade_downgrade_round_trip(tmp_path):
    db_path = tmp_path / "migration_test.db"
    env = dict(os.environ)
    env["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path.as_posix()}"
    env["MASTER_KEY"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    env["ENV"] = "dev"

    uv = shutil.which("uv")
    assert uv is not None, "uv is required to run alembic in the project env"
    for args in (
        ["alembic", "upgrade", "head"],
        ["alembic", "downgrade", "-1"],
        ["alembic", "upgrade", "head"],
    ):
        result = subprocess.run(
            [uv, "run", *args],
            cwd=PROJECT_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"{' '.join(args)} failed:\n{result.stderr}"

    import sqlite3

    con = sqlite3.connect(db_path)
    tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    expected = {
        "users",
        "sessions",
        "documents",
        "document_versions",
        "document_shares",
        "audit_log",
        "alerts",
    }
    assert expected <= tables
    con.close()
