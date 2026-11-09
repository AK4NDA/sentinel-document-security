"""API acceptance tests for the core classified document loop (spec 0003)."""

import hashlib
import itertools
import uuid
from datetime import UTC, datetime, timedelta

import pyotp
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update

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
from app.models import (
    Session as UserSession,
)
from app.security import totp as totp_security
from app.security.passwords import hash_password
from app.services import audit
from app.services import sessions as sessions_service

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


async def make_admin(session_factory, username="admin1", *, enrolled: bool = True) -> User:
    return await make_user(session_factory, username, role=UserRole.ADMIN, enrolled=enrolled)


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


# covers: AC-1, AC-2 (spec 0005)
async def test_admin_patch_user_privileges_and_audit(client, session_factory):
    await make_admin(session_factory, "admin2")
    target = await make_user(session_factory, "target1", clearance=ClassificationLevel.SECRET)
    await auth_client(client, "admin2")

    response = await client.patch(
        f"/v1/users/{target.id}",
        json={"role": "auditor", "clearance": 2},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["role"] == "auditor"
    assert body["clearance"] == 2

    rows = await audit_rows(session_factory)
    privilege_rows = [r for r in rows if r.action == "user.privilege_update"]
    assert len(privilege_rows) == 1
    assert privilege_rows[0].outcome == "allowed"
    assert privilege_rows[0].details["role"] == {"old": "user", "new": "auditor"}
    assert privilege_rows[0].details["clearance"] == {"old": 4, "new": 2}


# covers: AC-6, AC-9 (spec 0005)
async def test_disable_enable_conflicts_and_audit(client, session_factory):
    await make_admin(session_factory, "admin4")
    target = await make_user(session_factory, "target9")
    await auth_client(client, "admin4")

    missing = uuid.uuid4()
    assert (await client.post(f"/v1/users/{missing}/disable")).status_code == 404
    assert (await client.post(f"/v1/users/{missing}/enable")).status_code == 404

    disable = await client.post(f"/v1/users/{target.id}/disable")
    assert disable.status_code == 204, disable.text
    again = await client.post(f"/v1/users/{target.id}/disable")
    assert again.status_code == 409
    assert again.json()["detail"] == {"reason": "already_disabled"}

    enable = await client.post(f"/v1/users/{target.id}/enable")
    assert enable.status_code == 204, enable.text
    again = await client.post(f"/v1/users/{target.id}/enable")
    assert again.status_code == 409
    assert again.json()["detail"] == {"reason": "already_enabled"}

    rows = await audit_rows(session_factory)
    disabled = [r for r in rows if r.action == "user.disabled" and r.outcome == "allowed"]
    enabled = [r for r in rows if r.action == "user.enabled" and r.outcome == "allowed"]
    assert len(disabled) == 1
    assert disabled[0].details == {"is_active": {"old": True, "new": False}}
    assert len(enabled) == 1
    assert enabled[0].details == {"is_active": {"old": False, "new": True}}

    denials = await denied_rows(session_factory)
    not_found = [r for r in denials if r.details["reason"] == "not_found"]
    assert len(not_found) == 2
    dup_disabled = [r for r in denials if r.details["reason"] == "already_disabled"]
    assert len(dup_disabled) == 1
    assert dup_disabled[0].action == "user.disabled"
    assert dup_disabled[0].details == {"reason": "already_disabled", "is_active": False}
    dup_enabled = [r for r in denials if r.details["reason"] == "already_enabled"]
    assert len(dup_enabled) == 1
    assert dup_enabled[0].action == "user.enabled"
    assert dup_enabled[0].details == {"reason": "already_enabled", "is_active": True}


# covers: AC-3, AC-8 (spec 0005)
async def test_admin_self_disable_409_audited(client, session_factory):
    admin = await make_admin(session_factory, "admin5")
    await auth_client(client, "admin5")

    response = await client.post(f"/v1/users/{admin.id}/disable")

    assert response.status_code == 409
    assert response.json()["detail"] == {"reason": "self_disable"}
    assert (await client.get("/v1/auth/me")).status_code == 200
    denials = await denied_rows(session_factory, "user.disabled")
    assert len(denials) == 1
    assert denials[0].details == {"reason": "self_disable"}
    assert denials[0].actor_username == "admin5"


# covers: AC-3 (spec 0005)
async def test_disable_deletes_pending_mfa_challenge(client, session_factory):
    await make_admin(session_factory, "admin6")
    target = await make_user(session_factory, "target3")
    await auth_client(client, "admin6")

    login_response = await login(client, "target3")
    assert login_response.status_code == 200
    pending_token = login_response.json()["pending_token"]

    disable = await client.post(f"/v1/users/{target.id}/disable")
    assert disable.status_code == 204, disable.text

    verify = await client.post(
        "/v1/auth/mfa/verify",
        json={"pending_token": pending_token, "code": await totp_code(session_factory, "target3")},
    )
    assert verify.status_code == 401, verify.text


# covers: AC-4 (spec 0005)
async def test_revoke_sessions_audits_exact_count(client, session_factory):
    await make_admin(session_factory, "admin7")
    target = await make_user(session_factory, "target4")
    await auth_client(client, "admin7")

    target_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(target_client, "target4")
    async with session_factory() as session:
        user = (await session.execute(select(User).where(User.username == "target4"))).scalar_one()
        token, _row = await sessions_service.create(session, user)
        await session.commit()
    second_client = AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert (await second_client.get("/v1/auth/me")).status_code == 200

    revoke = await client.post(f"/v1/users/{target.id}/sessions/revoke")
    assert revoke.status_code == 204, revoke.text
    assert (await target_client.get("/v1/auth/me")).status_code == 401
    assert (await second_client.get("/v1/auth/me")).status_code == 401
    await target_client.aclose()
    await second_client.aclose()

    again = await client.post(f"/v1/users/{target.id}/sessions/revoke")
    assert again.status_code == 204, again.text

    rows = [r for r in await audit_rows(session_factory) if r.action == "session.revoke_all"]
    assert len(rows) == 2
    assert rows[0].outcome == "allowed"
    assert rows[0].details == {"revoked_count": 2}
    assert rows[1].details == {"revoked_count": 0}


# covers: AC-5 (spec 0005)
async def test_reset_password_clears_lockout_and_pending_challenge(client, session_factory):
    await make_admin(session_factory, "admin8")
    target = await make_user(session_factory, "target5")
    await auth_client(client, "admin8")

    for _ in range(5):
        await login(client, "target5", "wrong password here")
    locked = await login(client, "target5")
    assert locked.status_code == 429

    pending_login = await login(client, "target5", "wrong password here")
    assert pending_login.status_code == 429

    reset = await client.post(
        f"/v1/users/{target.id}/reset-password",
        json={"new_password": "new strong password"},
    )
    assert reset.status_code == 204, reset.text

    fresh = await login(client, "target5", "new strong password")
    assert fresh.status_code == 200, fresh.text
    assert fresh.json()["mfa_required"] is True
    pending_token = fresh.json()["pending_token"]

    reset_again = await client.post(
        f"/v1/users/{target.id}/reset-password",
        json={"new_password": "another strong password"},
    )
    assert reset_again.status_code == 204, reset_again.text
    verify = await client.post(
        "/v1/auth/mfa/verify",
        json={"pending_token": pending_token, "code": await totp_code(session_factory, "target5")},
    )
    assert verify.status_code == 401, verify.text

    rows = [r for r in await audit_rows(session_factory) if r.action == "user.password_reset"]
    assert len(rows) == 2
    assert rows[0].details == {"sessions_revoked": 0, "lockout_cleared": True}
    assert rows[1].details == {"sessions_revoked": 0, "lockout_cleared": False}


# covers: AC-1 (spec 0005)
async def test_patch_validation_422_cases(client, session_factory):
    await make_admin(session_factory, "admin9")
    target = await make_user(session_factory, "target6")
    await auth_client(client, "admin9")

    bodies = [
        {},
        {"role": None},
        {"clearance": None},
        {"is_active": False},
        {"password": "a long password"},
        {"nickname": "x"},
        {"role": "superuser"},
        {"clearance": 0},
        {"clearance": 6},
    ]
    for body in bodies:
        response = await client.patch(f"/v1/users/{target.id}", json=body)
        assert response.status_code == 422, (body, response.text)

    rows = [r for r in await audit_rows(session_factory) if r.action == "user.privilege_update"]
    assert rows == []
    me = await client.get("/v1/users")
    profile = next(u for u in me.json()["users"] if u["id"] == str(target.id))
    assert profile["role"] == "user"
    assert profile["is_active"] is True


# covers: AC-1 (spec 0005)
async def test_patch_noop_is_idempotent(client, session_factory):
    await make_admin(session_factory, "admin10")
    target = await make_user(session_factory, "target7", role=UserRole.AUDITOR)
    await auth_client(client, "admin10")

    response = await client.patch(f"/v1/users/{target.id}", json={"role": "auditor"})

    assert response.status_code == 200, response.text
    rows = [r for r in await audit_rows(session_factory) if r.action == "user.privilege_update"]
    assert len(rows) == 1
    assert rows[0].outcome == "allowed"
    assert rows[0].details["role"] == {"old": "auditor", "new": "auditor"}
    assert rows[0].details["clearance"] == {"old": 1, "new": 1}


# covers: AC-8 (spec 0005)
async def test_self_demotion_blocked_other_admin_may_demote(client, session_factory):
    admin = await make_admin(session_factory, "admin11")
    await make_admin(session_factory, "admin12")
    await auth_client(client, "admin11")

    response = await client.patch(f"/v1/users/{admin.id}", json={"role": "user"})
    assert response.status_code == 409
    assert response.json()["detail"] == {"reason": "self_demotion"}
    denials = await denied_rows(session_factory, "user.privilege_update")
    assert len(denials) == 1
    assert denials[0].details == {"reason": "self_demotion"}
    assert (await client.get("/v1/users")).status_code == 200

    other = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(other, "admin12")
    demote = await other.patch(f"/v1/users/{admin.id}", json={"role": "user"})
    assert demote.status_code == 200, demote.text
    assert demote.json()["role"] == "user"
    await other.aclose()


# covers: AC-8 (spec 0005)
async def test_self_revoke_allowed(client, session_factory):
    admin = await make_admin(session_factory, "admin13")
    await auth_client(client, "admin13")

    revoke = await client.post(f"/v1/users/{admin.id}/sessions/revoke")
    assert revoke.status_code == 204, revoke.text
    assert (await client.get("/v1/auth/me")).status_code == 401
    rows = [r for r in await audit_rows(session_factory) if r.action == "session.revoke_all"]
    assert len(rows) == 1
    assert rows[0].details == {"revoked_count": 1}


# covers: AC-8 (spec 0005)
async def test_self_reset_allowed(client, session_factory):
    admin = await make_admin(session_factory, "admin18")
    await auth_client(client, "admin18")

    reset = await client.post(
        f"/v1/users/{admin.id}/reset-password",
        json={"new_password": "self serve new password"},
    )
    assert reset.status_code == 204, reset.text
    assert (await client.get("/v1/auth/me")).status_code == 401

    old = await login(client, "admin18")
    assert old.status_code == 401
    new = await login(client, "admin18", "self serve new password")
    assert new.status_code == 200, new.text
    assert new.json()["mfa_required"] is True


# covers: AC-9 (spec 0005)
async def test_non_admin_denied_all_lifecycle_routes(client, session_factory):
    target = await make_user(session_factory, "target8")
    await make_user(session_factory, "officer8")
    await make_user(session_factory, "auditor8", role=UserRole.AUDITOR)

    for username in ("officer8", "auditor8"):
        actor_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
        await auth_client(actor_client, username)
        calls = [
            actor_client.patch(f"/v1/users/{target.id}", json={"role": "auditor"}),
            actor_client.post(f"/v1/users/{target.id}/disable"),
            actor_client.post(f"/v1/users/{target.id}/enable"),
            actor_client.post(f"/v1/users/{target.id}/sessions/revoke"),
            actor_client.post(
                f"/v1/users/{target.id}/reset-password",
                json={"new_password": "a long password"},
            ),
        ]
        for call in calls:
            response = await call
            assert response.status_code == 403, (username, response.text)
        await actor_client.aclose()

    for action in (
        "user.privilege_update",
        "user.disabled",
        "user.enabled",
        "session.revoke_all",
        "user.password_reset",
    ):
        denials = await denied_rows(session_factory, action)
        assert len(denials) == 2, action
        assert {r.actor_username for r in denials} == {"officer8", "auditor8"}
        assert all(r.details["reason"] == "role" for r in denials)


# covers: AC-9 (spec 0005)
async def test_unenrolled_admin_held_at_enrollment_gate(client, session_factory):
    await make_admin(session_factory, "admin14", enrolled=False)
    target = await make_user(session_factory, "target10")
    await auth_client(client, "admin14")

    calls = [
        ("user.privilege_update", client.patch(f"/v1/users/{target.id}", json={"role": "auditor"})),
        ("user.disabled", client.post(f"/v1/users/{target.id}/disable")),
        ("user.enabled", client.post(f"/v1/users/{target.id}/enable")),
        ("session.revoke_all", client.post(f"/v1/users/{target.id}/sessions/revoke")),
        (
            "user.password_reset",
            client.post(
                f"/v1/users/{target.id}/reset-password",
                json={"new_password": "a long password"},
            ),
        ),
    ]
    for action, call in calls:
        response = await call
        assert response.status_code == 403, (action, response.text)
        denials = await denied_rows(session_factory, action)
        assert len(denials) == 1, action
        assert denials[0].details["reason"] == "mfa_enrollment_required"
        assert denials[0].actor_username == "admin14"


# covers: AC-5, AC-7 (spec 0005)
async def test_reset_password_on_disabled_account_needs_enable(client, session_factory):
    await make_admin(session_factory, "admin15")
    target = await make_user(session_factory, "target11")
    await auth_client(client, "admin15")

    assert (await client.post(f"/v1/users/{target.id}/disable")).status_code == 204
    reset = await client.post(
        f"/v1/users/{target.id}/reset-password",
        json={"new_password": "disabled account password"},
    )
    assert reset.status_code == 204, reset.text

    still_disabled = await login(client, "target11", "disabled account password")
    assert still_disabled.status_code == 401

    assert (await client.post(f"/v1/users/{target.id}/enable")).status_code == 204
    fresh = await login(client, "target11", "disabled account password")
    assert fresh.status_code == 200, fresh.text
    assert fresh.json()["mfa_required"] is True


# covers: AC-5, AC-7 (spec 0005)
async def test_enable_does_not_clear_lockout(client, session_factory):
    await make_admin(session_factory, "admin16")
    target = await make_user(session_factory, "target12")
    await auth_client(client, "admin16")

    for _ in range(5):
        await login(client, "target12", "wrong password here")
    assert (await client.post(f"/v1/users/{target.id}/disable")).status_code == 204
    assert (await client.post(f"/v1/users/{target.id}/enable")).status_code == 204

    still_locked = await login(client, "target12")
    assert still_locked.status_code == 429, still_locked.text


# covers: AC-5, AC-9 (spec 0005)
async def test_reset_password_validation_and_unknown_user(client, session_factory):
    await make_admin(session_factory, "admin17")
    target = await make_user(session_factory, "target13")
    await auth_client(client, "admin17")

    short = await client.post(
        f"/v1/users/{target.id}/reset-password", json={"new_password": "short"}
    )
    assert short.status_code == 422
    missing = await client.post(f"/v1/users/{target.id}/reset-password", json={})
    assert missing.status_code == 422

    unknown = uuid.uuid4()
    assert (await client.post(f"/v1/users/{unknown}/sessions/revoke")).status_code == 404
    not_found_reset = await client.post(
        f"/v1/users/{unknown}/reset-password", json={"new_password": "a long password"}
    )
    assert not_found_reset.status_code == 404

    for action in ("session.revoke_all", "user.password_reset"):
        denials = await denied_rows(session_factory, action)
        assert len(denials) == 1, action
        assert denials[0].details == {"reason": "not_found"}


# covers: AC-7 (spec 0005)
async def test_role_change_takes_effect_next_request(client, session_factory):
    await make_admin(session_factory, "admin19")
    target = await make_user(session_factory, "target14")
    await auth_client(client, "admin19")
    target_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(target_client, "target14")
    assert (await target_client.get("/v1/documents")).status_code == 200

    patch = await client.patch(f"/v1/users/{target.id}", json={"role": "auditor"})
    assert patch.status_code == 200, patch.text

    assert (await target_client.get("/v1/auth/me")).status_code == 200
    assert (await target_client.get("/v1/documents")).status_code == 403
    await target_client.aclose()


# covers: AC-7 (spec 0005)
async def test_clearance_change_takes_effect_next_request(client, session_factory):
    await make_admin(session_factory, "admin20")
    target = await make_user(session_factory, "target15", clearance=ClassificationLevel.SECRET)
    await auth_client(client, "admin20")
    target_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(target_client, "target15")
    upload = await upload_doc(target_client, content=b"secret plans")
    assert upload.status_code == 201, upload.text
    doc_id = upload.json()["id"]
    assert (await target_client.get(f"/v1/documents/{doc_id}/content")).status_code == 200

    patch = await client.patch(f"/v1/users/{target.id}", json={"clearance": 1})
    assert patch.status_code == 200, patch.text

    assert (await target_client.get("/v1/auth/me")).status_code == 200
    assert (await target_client.get(f"/v1/documents/{doc_id}/content")).status_code == 403
    await target_client.aclose()


# covers: AC-7 (spec 0005)
async def test_disabled_sessions_revive_on_enable_unless_revoked(client, session_factory):
    await make_admin(session_factory, "admin21")
    target = await make_user(session_factory, "target16")
    await auth_client(client, "admin21")
    target_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(target_client, "target16")

    assert (await client.post(f"/v1/users/{target.id}/disable")).status_code == 204
    assert (await target_client.get("/v1/auth/me")).status_code == 401
    assert (await client.post(f"/v1/users/{target.id}/enable")).status_code == 204
    assert (await target_client.get("/v1/auth/me")).status_code == 200

    assert (await client.post(f"/v1/users/{target.id}/disable")).status_code == 204
    assert (await client.post(f"/v1/users/{target.id}/sessions/revoke")).status_code == 204
    assert (await client.post(f"/v1/users/{target.id}/enable")).status_code == 204
    assert (await target_client.get("/v1/auth/me")).status_code == 401
    await target_client.aclose()


async def test_revoke_leaves_expired_sessions_alone(client, session_factory):
    # covers: AC-4 (spec 0005)
    await make_admin(session_factory, "admin22")
    target = await make_user(session_factory, "target17")
    await auth_client(client, "admin22")
    target_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(target_client, "target17")

    async with session_factory() as session:
        await session.execute(
            update(UserSession)
            .where(UserSession.user_id == target.id)
            .values(expires_at=datetime.now(UTC) - timedelta(minutes=1))
        )
        await session.commit()

    revoke = await client.post(f"/v1/users/{target.id}/sessions/revoke")
    assert revoke.status_code == 204, revoke.text
    rows = [r for r in await audit_rows(session_factory) if r.action == "session.revoke_all"]
    assert rows[0].details == {"revoked_count": 0}
    async with session_factory() as session:
        row = (
            await session.execute(select(UserSession).where(UserSession.user_id == target.id))
        ).scalar_one()
        assert row.revoked_at is None
    await target_client.aclose()


async def test_reset_password_revokes_live_session_and_rehashes(client, session_factory):
    # covers: AC-5 (spec 0005)
    await make_admin(session_factory, "admin23")
    target = await make_user(session_factory, "target18")
    await auth_client(client, "admin23")
    target_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(target_client, "target18")

    reset = await client.post(
        f"/v1/users/{target.id}/reset-password",
        json={"new_password": "fresh strong password"},
    )
    assert reset.status_code == 204, reset.text
    assert (await target_client.get("/v1/auth/me")).status_code == 401
    await target_client.aclose()

    rows = [r for r in await audit_rows(session_factory) if r.action == "user.password_reset"]
    assert rows[0].details == {"sessions_revoked": 1, "lockout_cleared": False}

    old = await login(client, "target18")
    assert old.status_code == 401
    new = await login(client, "target18", "fresh strong password")
    assert new.status_code == 200, new.text
    assert new.json()["mfa_required"] is True
    async with session_factory() as session:
        row = (await session.execute(select(User).where(User.id == target.id))).scalar_one()
        assert row.password_hash.startswith("$argon2id$")


async def test_reset_clears_failure_count_below_lockout_threshold(client, session_factory):
    # covers: AC-5 (spec 0005)
    await make_admin(session_factory, "admin24")
    target = await make_user(session_factory, "target19")
    await auth_client(client, "admin24")

    for _ in range(2):
        await login(client, "target19", "wrong password here")
    reset = await client.post(
        f"/v1/users/{target.id}/reset-password",
        json={"new_password": "fresh strong password"},
    )
    assert reset.status_code == 204, reset.text
    rows = [r for r in await audit_rows(session_factory) if r.action == "user.password_reset"]
    assert rows[0].details["lockout_cleared"] is True
    fresh = await login(client, "target19", "fresh strong password")
    assert fresh.status_code == 200, fresh.text


async def test_disable_spares_other_users_pending_challenge(client, session_factory):
    # covers: AC-3 (spec 0005)
    await make_admin(session_factory, "admin25")
    target = await make_user(session_factory, "target20")
    await make_user(session_factory, "bystander")
    await auth_client(client, "admin25")

    target_token = (await login(client, "target20")).json()["pending_token"]
    other_token = (await login(client, "bystander")).json()["pending_token"]

    assert (await client.post(f"/v1/users/{target.id}/disable")).status_code == 204
    dead = await client.post(
        "/v1/auth/mfa/verify",
        json={"pending_token": target_token, "code": await totp_code(session_factory, "target20")},
    )
    assert dead.status_code == 401
    alive = await client.post(
        "/v1/auth/mfa/verify",
        json={"pending_token": other_token, "code": await totp_code(session_factory, "bystander")},
    )
    assert alive.status_code == 200, alive.text


async def test_audit_actor_snapshot_survives_later_demotion(client, session_factory):
    # covers: AC-9 (spec 0005)
    actor = await make_admin(session_factory, "admin26")
    await make_admin(session_factory, "admin27")
    target = await make_user(session_factory, "target21")
    await auth_client(client, "admin26")

    assert (await client.patch(f"/v1/users/{target.id}", json={"clearance": 3})).status_code == 200

    other = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(other, "admin27")
    assert (await other.patch(f"/v1/users/{actor.id}", json={"role": "user"})).status_code == 200
    await other.aclose()

    rows = [
        r
        for r in await audit_rows(session_factory)
        if r.action == "user.privilege_update" and r.target_id == str(target.id)
    ]
    assert len(rows) == 1
    assert rows[0].actor_username == "admin26"
    assert rows[0].actor_role == "admin"


# covers: AC-3, AC-4, AC-5 (spec 0005)
async def test_admin_disable_enable_revoke_sessions_and_reset_password(client, session_factory):
    await make_admin(session_factory, "admin3")
    target = await make_user(session_factory, "target2", password=PASSWORD)
    await auth_client(client, "admin3")

    target_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(target_client, "target2")

    disable = await client.post(f"/v1/users/{target.id}/disable")
    assert disable.status_code == 204, disable.text
    disabled_me = await target_client.get("/v1/auth/me")
    assert disabled_me.status_code == 401

    enable = await client.post(f"/v1/users/{target.id}/enable")
    assert enable.status_code == 204, enable.text

    revoke = await client.post(f"/v1/users/{target.id}/sessions/revoke")
    assert revoke.status_code == 204, revoke.text
    revoked_me = await target_client.get("/v1/auth/me")
    assert revoked_me.status_code == 401

    reset = await client.post(
        f"/v1/users/{target.id}/reset-password",
        json={"new_password": "new strong password"},
    )
    assert reset.status_code == 204, reset.text

    old_password = await client.post(
        "/v1/auth/login",
        json={"username": "target2", "password": PASSWORD},
    )
    assert old_password.status_code == 401

    new_password = await client.post(
        "/v1/auth/login",
        json={"username": "target2", "password": "new strong password"},
    )
    assert new_password.status_code == 200, new_password.text
    await target_client.aclose()

    rows = await audit_rows(session_factory)
    actions = [r.action for r in rows]
    assert "user.disabled" in actions
    assert "user.enabled" in actions
    assert "session.revoke_all" in actions
    assert "user.password_reset" in actions


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
