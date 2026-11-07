"""API acceptance tests for the core classified document loop (spec 0003)."""

import hashlib
import itertools
import uuid
from datetime import UTC, datetime

import pyotp
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.config import get_settings
from app.main import app
from app.models import (
    AuditLog,
    ClassificationLevel,
    Document,
    DocumentVersion,
    User,
    UserRole,
)
from app.security import totp as totp_security
from app.security.passwords import hash_password
from app.services import audit

PASSWORD = "correct horse battery"
UPLOADS = {"file": ("note.txt", b"hello classified world", "text/plain")}


async def make_user(
    session_factory,
    username: str,
    *,
    role: UserRole = UserRole.USER,
    clearance: ClassificationLevel = ClassificationLevel.UNCLASSIFIED,
    password: str = PASSWORD,
    is_active: bool = True,
    enrolled: bool = True,
) -> User:
    async with session_factory() as session:
        secret = totp_security.generate_secret() if enrolled else None
        user = User(
            username=username,
            email=f"{username}@example.com",
            password_hash=hash_password(password),
            role=role,
            clearance=clearance,
            is_active=is_active,
            totp_secret_encrypted=totp_security.seal_secret(secret) if secret else None,
            totp_enabled_at=datetime.now(UTC) if enrolled else None,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


async def enroll_user(session_factory, username: str) -> None:
    """Mark an existing user as MFA enrolled with a known secret."""
    async with session_factory() as session:
        user = (await session.execute(select(User).where(User.username == username))).scalar_one()
        user.totp_secret_encrypted = totp_security.seal_secret(totp_security.generate_secret())
        user.totp_enabled_at = datetime.now(UTC)
        await session.commit()


async def totp_code(session_factory, username: str) -> str:
    async with session_factory() as session:
        user = (await session.execute(select(User).where(User.username == username))).scalar_one()
        secret = totp_security.open_secret(user.totp_secret_encrypted)
    return pyotp.TOTP(secret).now()


async def login(client: AsyncClient, username: str, password: str = PASSWORD):
    return await client.post("/v1/auth/login", json={"username": username, "password": password})


async def auth_client(client: AsyncClient, username: str, **kwargs) -> AsyncClient:
    import conftest

    response = await login(client, username, **kwargs)
    assert response.status_code == 200, response.text
    body = response.json()
    if body.get("mfa_required"):
        verify = await client.post(
            "/v1/auth/mfa/verify",
            json={
                "pending_token": body["pending_token"],
                "code": await totp_code(conftest.SESSION_FACTORY, username),
            },
        )
        assert verify.status_code == 200, verify.text
    return client


async def audit_rows(session_factory) -> list[AuditLog]:
    async with session_factory() as session:
        result = await session.execute(select(AuditLog).order_by(AuditLog.seq))
        return list(result.scalars().all())


async def denied_rows(session_factory, action: str | None = None) -> list[AuditLog]:
    async with session_factory() as session:
        stmt = select(AuditLog).where(AuditLog.outcome == "denied")
        if action:
            stmt = stmt.where(AuditLog.action == action)
        result = await session.execute(stmt.order_by(AuditLog.seq))
        return list(result.scalars().all())


# AC-2, AC-3: login, session, cookie, bearer, me


async def test_login_success_sets_cookie_and_returns_profile(client, session_factory):
    await make_user(session_factory, "officer1", enrolled=False)

    response = await login(client, "officer1")

    assert response.status_code == 200
    body = response.json()
    assert body["username"] == "officer1"
    assert body["role"] == "user"
    assert "session=" in response.headers["set-cookie"]
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "SameSite=lax" in response.headers["set-cookie"]
    assert "Path=/" in response.headers["set-cookie"]

    async with session_factory() as session:
        from app.models import Session as UserSession

        rows = (await session.execute(select(UserSession))).scalars().all()
        assert len(rows) == 1
        assert len(rows[0].token_hash) == 64


async def test_login_bad_password_401_and_audited_denied(client, session_factory):
    await make_user(session_factory, "officer2")

    response = await login(client, "officer2", password="wrong password!")

    assert response.status_code == 401
    rows = await denied_rows(session_factory, "auth.login")
    assert len(rows) == 1
    assert rows[0].details["attempted_username"] == "officer2"
    assert rows[0].actor_username == "officer2"


async def test_login_unknown_user_401_audited_with_null_actor(client, session_factory):
    response = await login(client, "ghost")

    assert response.status_code == 401
    rows = await denied_rows(session_factory, "auth.login")
    assert len(rows) == 1
    assert rows[0].actor_id is None
    assert rows[0].details["attempted_username"] == "ghost"


async def test_login_disabled_user_401(client, session_factory):
    await make_user(session_factory, "officer3", is_active=False)

    response = await login(client, "officer3")

    assert response.status_code == 401


async def test_protected_endpoint_requires_session(client, session_factory):
    await make_user(session_factory, "officer4")

    response = await client.get("/v1/documents")

    assert response.status_code == 401


async def test_bearer_token_accepted(client, session_factory):
    await make_user(session_factory, "officer5", enrolled=False)
    login_response = await login(client, "officer5")
    token = client.cookies.get("session")
    assert token

    other = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    response = await other.get("/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    await other.aclose()

    assert response.status_code == 200
    assert response.json()["username"] == "officer5"
    assert login_response.status_code == 200


async def test_me_returns_profile_for_auditor(client, session_factory):
    await make_user(session_factory, "auditor1", role=UserRole.AUDITOR, enrolled=False)
    await auth_client(client, "auditor1")

    response = await client.get("/v1/auth/me")

    assert response.status_code == 200
    assert response.json()["role"] == "auditor"


async def test_logout_revokes_session(client, session_factory):
    await make_user(session_factory, "officer6", enrolled=False)
    await auth_client(client, "officer6")

    response = await client.post("/v1/auth/logout")

    assert response.status_code == 204
    assert "session=" in response.headers.get("set-cookie", "")
    followup = await client.get("/v1/auth/me")
    assert followup.status_code == 401


# AC-4, AC-5, AC-16 (API part): admin user administration


async def make_admin(session_factory, username="admin1") -> User:
    return await make_user(session_factory, username, role=UserRole.ADMIN)


async def test_admin_creates_and_lists_users(client, session_factory):
    await make_admin(session_factory)
    await auth_client(client, "admin1")

    create = await client.post(
        "/v1/users",
        json={
            "username": "newofficer",
            "email": "new@example.com",
            "password": "a long password",
            "role": "user",
            "clearance": 4,
        },
    )
    assert create.status_code == 201, create.text
    assert create.json()["clearance"] == 4

    listing = await client.get("/v1/users")
    assert listing.status_code == 200
    names = {u["username"] for u in listing.json()["users"]}
    assert {"admin1", "newofficer"} <= names

    rows = await audit_rows(session_factory)
    actions = [r.action for r in rows]
    assert "user.create" in actions
    assert "user.list" in actions


async def test_create_user_rejects_admin_role_422(client, session_factory):
    await make_admin(session_factory)
    await auth_client(client, "admin1")

    response = await client.post(
        "/v1/users",
        json={
            "username": "sneaky",
            "email": "s@example.com",
            "password": "a long password",
            "role": "admin",
        },
    )

    assert response.status_code == 422


async def test_create_user_short_password_422(client, session_factory):
    await make_admin(session_factory)
    await auth_client(client, "admin1")

    response = await client.post(
        "/v1/users",
        json={
            "username": "shorty",
            "email": "s@example.com",
            "password": "short",
            "role": "user",
        },
    )

    assert response.status_code == 422


async def test_create_user_duplicate_409(client, session_factory):
    await make_admin(session_factory)
    await auth_client(client, "admin1")
    payload = {
        "username": "dup",
        "email": "dup@example.com",
        "password": "a long password",
        "role": "user",
    }
    assert (await client.post("/v1/users", json=payload)).status_code == 201

    response = await client.post("/v1/users", json=payload)
    assert response.status_code == 409


async def test_officer_denied_user_admin_403_audited(client, session_factory):
    await make_user(session_factory, "officer7")
    await auth_client(client, "officer7")

    create = await client.post(
        "/v1/users",
        json={
            "username": "nope",
            "email": "n@example.com",
            "password": "a long password",
            "role": "user",
        },
    )
    listing = await client.get("/v1/users")

    assert create.status_code == 403
    assert listing.status_code == 403
    rows = await denied_rows(session_factory, "user.create")
    assert len(rows) == 1
    assert rows[0].actor_username == "officer7"


# AC-6 through AC-13: documents


async def upload_doc(
    client: AsyncClient,
    title="My Doc",
    content=b"secret contents",
    mime="text/plain",
    filename="doc.txt",
):
    return await client.post(
        "/v1/documents",
        files={"file": (filename, content, mime)},
        data={"title": title},
    )


async def test_upload_document_encrypts_and_audits(client, session_factory, tmp_path):
    await make_user(session_factory, "officer8", clearance=ClassificationLevel.SECRET)
    await auth_client(client, "officer8")

    response = await upload_doc(client, content=b"top secret plans")

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["classification"] == 4
    assert body["title"] == "My Doc"

    async with session_factory() as session:
        doc = (
            await session.execute(select(Document).where(Document.id == uuid.UUID(body["id"])))
        ).scalar_one()
        version = (
            await session.execute(
                select(DocumentVersion).where(DocumentVersion.document_id == doc.id)
            )
        ).scalar_one()
        assert version.version_number == 1
        assert version.classification == ClassificationLevel.SECRET
        assert version.content_sha256 == hashlib.sha256(b"top secret plans").hexdigest()
        assert version.key_id == "master"
        assert version.key_version == "1"
        assert doc.current_version_id == version.id

        blob = get_settings().upload_dir / version.blob_path
        stored = blob.read_bytes()
        assert b"top secret plans" not in stored

        rows = await audit_rows(session_factory)
        upload_rows = [r for r in rows if r.action == "document.upload"]
        assert len(upload_rows) == 1
        assert upload_rows[0].outcome == "allowed"
        assert upload_rows[0].details["filename"] == "doc.txt"


async def test_upload_size_checked_before_mime(client, session_factory):
    await make_user(session_factory, "officer9")
    await auth_client(client, "officer9")

    big_bad_mime = await client.post(
        "/v1/documents",
        files={"file": ("big.bin", b"x" * (25 * 1024 * 1024 + 1), "application/x-msdownload")},
        data={"title": "big"},
    )
    assert big_bad_mime.status_code == 413

    bad_mime = await upload_doc(client, mime="application/x-msdownload")
    assert bad_mime.status_code == 415


async def test_list_documents_returns_only_own(client, session_factory):
    await make_user(session_factory, "owner1")
    await make_user(session_factory, "owner2")

    owner1_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    owner2_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(owner1_client, "owner1")
    await auth_client(owner2_client, "owner2")
    await upload_doc(owner1_client, title="first")
    await upload_doc(owner2_client, title="second")

    listing = await owner1_client.get("/v1/documents")

    assert listing.status_code == 200
    titles = [d["title"] for d in listing.json()["documents"]]
    assert titles == ["first"]
    await owner1_client.aclose()
    await owner2_client.aclose()


async def test_read_meta_and_content_roundtrip(client, session_factory):
    await make_user(session_factory, "reader1", clearance=ClassificationLevel.SECRET)
    await auth_client(client, "reader1")
    upload = await upload_doc(client, content=b"roundtrip bytes")
    doc_id = upload.json()["id"]

    meta = await client.get(f"/v1/documents/{doc_id}")
    assert meta.status_code == 200
    assert meta.json()["classification"] == 4

    content = await client.get(f"/v1/documents/{doc_id}/content")
    assert content.status_code == 200
    assert content.content == b"roundtrip bytes"
    assert "attachment" in content.headers["content-disposition"]
    assert content.headers["content-disposition"].endswith('.txt"')

    rows = await audit_rows(session_factory)
    assert {r.action for r in rows} >= {"document.upload", "document.read", "document.download"}


async def test_read_denied_by_clearance_403_audited(client, session_factory):
    await make_user(session_factory, "low1", clearance=ClassificationLevel.CONFIDENTIAL)
    await make_user(session_factory, "high1", clearance=ClassificationLevel.SECRET)
    high_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(high_client, "high1")
    upload = await upload_doc(high_client, content=b"secret")
    doc_id = upload.json()["id"]
    await high_client.aclose()

    await auth_client(client, "low1")
    meta = await client.get(f"/v1/documents/{doc_id}")
    content = await client.get(f"/v1/documents/{doc_id}/content")

    assert meta.status_code == 403
    assert content.status_code == 403
    rows = await denied_rows(session_factory, "document.read")
    assert len(rows) == 1
    rows_dl = await denied_rows(session_factory, "document.download")
    assert len(rows_dl) == 1


async def test_edit_creates_new_version_and_updates_meta(client, session_factory):
    await make_user(session_factory, "editor1", clearance=ClassificationLevel.SECRET)
    await auth_client(client, "editor1")
    upload = await upload_doc(client, content=b"v1")
    doc_id = upload.json()["id"]

    edit = await client.post(
        f"/v1/documents/{doc_id}/versions",
        files={"file": ("v2.txt", b"v2 contents", "text/plain")},
        data={"title": "Renamed"},
    )

    assert edit.status_code == 201, edit.text
    assert edit.json()["title"] == "Renamed"
    assert edit.json()["classification"] == 4

    content = await client.get(f"/v1/documents/{doc_id}/content")
    assert content.content == b"v2 contents"

    async with session_factory() as session:
        versions = (
            (
                await session.execute(
                    select(DocumentVersion)
                    .where(DocumentVersion.document_id == uuid.UUID(doc_id))
                    .order_by(DocumentVersion.version_number)
                )
            )
            .scalars()
            .all()
        )
        assert [v.version_number for v in versions] == [1, 2]


async def test_edit_denied_for_non_owner_404_audited(client, session_factory):
    await make_user(session_factory, "ownerA")
    await make_user(session_factory, "ownerB")

    client_a = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(client_a, "ownerA")
    upload = await upload_doc(client_a, content=b"mine")
    doc_id = upload.json()["id"]
    await client_a.aclose()

    await auth_client(client, "ownerB")
    edit = await client.post(
        f"/v1/documents/{doc_id}/versions",
        files={"file": ("x.txt", b"theirs", "text/plain")},
    )
    delete = await client.delete(f"/v1/documents/{doc_id}")

    assert edit.status_code == 404
    assert delete.status_code == 404
    rows = await denied_rows(session_factory, "document.edit")
    assert len(rows) == 1
    rows_del = await denied_rows(session_factory, "document.delete")
    assert len(rows_del) == 1


async def test_edit_blocked_when_clearance_lowered(client, session_factory):
    user = await make_user(session_factory, "downgrade1", clearance=ClassificationLevel.SECRET)
    await auth_client(client, "downgrade1")
    upload = await upload_doc(client, content=b"v1")
    doc_id = upload.json()["id"]

    async with session_factory() as session:
        row = (await session.execute(select(User).where(User.id == user.id))).scalar_one()
        row.clearance = ClassificationLevel.CONFIDENTIAL
        await session.commit()

    edit = await client.post(
        f"/v1/documents/{doc_id}/versions",
        files={"file": ("v2.txt", b"v2", "text/plain")},
    )

    assert edit.status_code == 403


async def test_delete_owner_only_hard_delete(client, session_factory):
    await make_user(session_factory, "deleter1")
    await auth_client(client, "deleter1")
    upload = await upload_doc(client, content=b"doomed")
    doc_id = upload.json()["id"]

    response = await client.delete(f"/v1/documents/{doc_id}")

    assert response.status_code == 204
    gone = await client.get(f"/v1/documents/{doc_id}")
    assert gone.status_code == 404

    async with session_factory() as session:
        assert (
            await session.execute(select(Document).where(Document.id == uuid.UUID(doc_id)))
        ).scalar_one_or_none() is None
        assert (
            await session.execute(
                select(DocumentVersion).where(DocumentVersion.document_id == uuid.UUID(doc_id))
            )
        ).scalars().all() == []

    rows = await audit_rows(session_factory)
    delete_rows = [r for r in rows if r.action == "document.delete"]
    assert len(delete_rows) == 1
    assert delete_rows[0].outcome == "allowed"


# AC-12: role gates on document endpoints


async def test_admin_and_auditor_denied_documents_403_audited(client, session_factory):
    await make_user(session_factory, "admin2", role=UserRole.ADMIN)
    await make_user(session_factory, "auditor2", role=UserRole.AUDITOR)

    admin_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(admin_client, "admin2")
    for method, url in [
        ("get", "/v1/documents"),
        ("post", "/v1/documents"),
    ]:
        if method == "post":
            response = await admin_client.post(
                url,
                files={"file": ("x.txt", b"x", "text/plain")},
                data={"title": "x"},
            )
        else:
            response = await getattr(admin_client, method)(url)
        assert response.status_code == 403
    await admin_client.aclose()

    await auth_client(client, "auditor2")
    assert (await client.get("/v1/documents")).status_code == 403

    rows = await denied_rows(session_factory)
    assert len(rows) >= 3
    assert all(r.outcome == "denied" for r in rows)


# AC-14, AC-15: audit chain


async def test_audit_chain_verifies_after_mixed_operations(client, session_factory):
    await make_admin(session_factory, "admin3")
    await auth_client(client, "admin3")
    await client.post(
        "/v1/users",
        json={
            "username": "chainofficer",
            "email": "c@example.com",
            "password": "a long password",
            "role": "user",
            "clearance": 5,
        },
    )

    await enroll_user(session_factory, "chainofficer")
    officer_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(officer_client, "chainofficer", password="a long password")
    upload = await upload_doc(officer_client, content=b"chain")
    doc_id = upload.json()["id"]
    await officer_client.post(
        f"/v1/documents/{doc_id}/versions",
        files={"file": ("v2.txt", b"v2", "text/plain")},
    )
    await officer_client.delete(f"/v1/documents/{doc_id}")
    await officer_client.aclose()

    await client.post("/v1/auth/login", json={"username": "ghost", "password": "x"})

    async with session_factory() as session:
        bad = await audit.verify_chain(session)
        rows = (await session.execute(select(AuditLog).order_by(AuditLog.seq))).scalars().all()

    assert bad == []
    assert len(rows) >= 6
    assert rows[0].prev_hash == "0" * 64
    for prev, cur in itertools.pairwise(rows):
        assert cur.prev_hash == prev.hash


async def test_tampered_audit_row_detected(client, session_factory):
    await make_user(session_factory, "officer10")
    await auth_client(client, "officer10")

    async with session_factory() as session:
        await audit.verify_chain(session)
        row = (await session.execute(select(AuditLog).order_by(AuditLog.seq).limit(1))).scalar_one()
        row.action = "document.delete"
        await session.commit()
        bad = await audit.verify_chain(session)

    assert bad == [row.seq]


# AC-17: rate limiting


async def test_login_rate_limited(client, session_factory):
    settings = get_settings()
    settings.rate_limit_enabled = True
    settings.rate_limit_auth = "3/minute"
    try:
        await make_user(session_factory, "rl1")
        codes = [
            (await login(client, "rl1", password="bad password 1")).status_code for _ in range(4)
        ]
        assert codes[-1] == 429
    finally:
        settings.rate_limit_enabled = False
        settings.rate_limit_auth = "10/minute"


# AC-16: create-admin CLI


async def test_create_admin_cli(session_factory, monkeypatch):
    import argparse
    import getpass

    from app import cli

    monkeypatch.setattr(cli, "SessionLocal", session_factory)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "cli admin password")
    args = argparse.Namespace(
        username="cliadmin",
        email="cli@example.com",
        clearance=1,
        display_name=None,
    )

    assert await cli._create_admin(args) == 0

    async with session_factory() as session:
        user = (await session.execute(select(User).where(User.username == "cliadmin"))).scalar_one()
        assert user.role == UserRole.ADMIN

    assert await cli._create_admin(args) == 1


async def test_upload_rejections_are_audited(client, session_factory):
    """AC-14: 413/415 after authorization must write denied audit rows."""
    await make_user(session_factory, "auditreject1")
    await auth_client(client, "auditreject1")

    bad_mime = await upload_doc(client, mime="application/x-msdownload")
    assert bad_mime.status_code == 415

    big = await client.post(
        "/v1/documents",
        files={"file": ("big.bin", b"x" * (25 * 1024 * 1024 + 1), "text/plain")},
        data={"title": "big"},
    )
    assert big.status_code == 413

    rows = await denied_rows(session_factory, "document.upload")
    reasons = sorted((r.details or {}).get("reason") for r in rows)
    assert reasons == ["too_large", "unsupported_media_type"]


async def test_edit_rejections_are_audited(client, session_factory):
    await make_user(session_factory, "auditreject2")
    await auth_client(client, "auditreject2")
    upload = await upload_doc(client, content=b"v1")
    doc_id = upload.json()["id"]

    bad_mime = await client.post(
        f"/v1/documents/{doc_id}/versions",
        files={"file": ("x.bin", b"x", "application/x-msdownload")},
    )
    assert bad_mime.status_code == 415

    rows = await denied_rows(session_factory, "document.edit")
    assert len(rows) == 1
    assert rows[0].details["reason"] == "unsupported_media_type"
