"""MFA acceptance tests for spec 0004."""

from datetime import UTC, datetime, timedelta

import pyotp
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from test_api import (
    PASSWORD,
    audit_rows,
    auth_client,
    denied_rows,
    login,
    make_user,
    totp_code,
)

from app.main import app
from app.models import MfaChallenge, User, UserRole
from app.security import totp as totp_security


async def _limited_client(client: AsyncClient, session_factory, username: str) -> AsyncClient:
    """Log in an unenrolled user; returns client holding the limited session."""
    await make_user(session_factory, username, enrolled=False)
    response = await login(client, username)
    assert response.status_code == 200
    assert "session=" in response.headers.get("set-cookie", "")
    return client


# AC-2, AC-3: enrollment flow


async def test_enroll_start_returns_secret_uri_qr(client, session_factory):
    await _limited_client(client, session_factory, "enroll1")

    response = await client.post("/v1/auth/mfa/enroll/start")

    assert response.status_code == 200
    body = response.json()
    assert body["secret"]
    assert body["otpauth_uri"].startswith("otpauth://totp/")
    assert "<svg" in body["qr_svg"]

    async with session_factory() as session:
        user = (await session.execute(select(User).where(User.username == "enroll1"))).scalar_one()
        assert user.totp_secret_encrypted is not None
        assert user.totp_enabled_at is None


async def test_enroll_confirm_enables_mfa(client, session_factory):
    await _limited_client(client, session_factory, "enroll2")
    await client.post("/v1/auth/mfa/enroll/start")
    code = await totp_code(session_factory, "enroll2")

    response = await client.post("/v1/auth/mfa/enroll/confirm", json={"code": code})

    assert response.status_code == 200
    assert response.json()["mfa_enrolled"] is True

    async with session_factory() as session:
        user = (await session.execute(select(User).where(User.username == "enroll2"))).scalar_one()
        assert user.totp_enabled_at is not None
        assert user.totp_last_counter is not None


async def test_enroll_confirm_bad_code_401_audited(client, session_factory):
    await _limited_client(client, session_factory, "enroll3")
    await client.post("/v1/auth/mfa/enroll/start")

    response = await client.post("/v1/auth/mfa/enroll/confirm", json={"code": "000000"})

    assert response.status_code == 401
    rows = await denied_rows(session_factory, "mfa.enroll")
    assert rows and rows[-1].details["reason"] == "invalid_code"


async def test_enroll_restart_regenerates_secret(client, session_factory):
    await _limited_client(client, session_factory, "enroll4")
    first = (await client.post("/v1/auth/mfa/enroll/start")).json()["secret"]
    second = (await client.post("/v1/auth/mfa/enroll/start")).json()["secret"]
    assert first != second


async def test_enroll_start_denied_when_already_enrolled(client, session_factory):
    await make_user(session_factory, "enroll5")
    await auth_client(client, "enroll5")

    response = await client.post("/v1/auth/mfa/enroll/start")

    assert response.status_code == 403
    rows = await denied_rows(session_factory, "mfa.enroll")
    assert rows and rows[-1].details["reason"] == "already_enrolled"


# AC-4: limited session gate


async def test_unenrolled_session_blocked_from_documents(client, session_factory):
    await _limited_client(client, session_factory, "limited1")

    response = await client.get("/v1/documents")

    assert response.status_code == 403
    rows = await denied_rows(session_factory)
    gate = [r for r in rows if r.details.get("reason") == "mfa_enrollment_required"]
    assert gate and gate[-1].action == "document.list"


async def test_unenrolled_session_can_use_me_and_logout(client, session_factory):
    await _limited_client(client, session_factory, "limited2")

    assert (await client.get("/v1/auth/me")).status_code == 200
    assert (await client.post("/v1/auth/logout")).status_code == 204


# AC-5, AC-6: login challenge and verify


async def test_enrolled_login_returns_pending_token_no_cookie(client, session_factory):
    await make_user(session_factory, "chal1")

    response = await login(client, "chal1")

    assert response.status_code == 200
    body = response.json()
    assert body["mfa_required"] is True
    assert body["pending_token"]
    assert body["expires_in"] == 300
    assert "session=" not in response.headers.get("set-cookie", "")

    async with session_factory() as session:
        rows = (await session.execute(select(MfaChallenge))).scalars().all()
        assert len(rows) == 1
        assert len(rows[0].token_hash) == 64


async def test_mfa_verify_issues_session(client, session_factory):
    await make_user(session_factory, "chal2")
    pending = (await login(client, "chal2")).json()["pending_token"]
    code = await totp_code(session_factory, "chal2")

    response = await client.post(
        "/v1/auth/mfa/verify", json={"pending_token": pending, "code": code}
    )

    assert response.status_code == 200
    assert response.json()["mfa_enrolled"] is True
    assert "session=" in response.headers.get("set-cookie", "")
    assert (await client.get("/v1/auth/me")).status_code == 200


async def test_mfa_verify_wrong_code_401_and_audited(client, session_factory):
    await make_user(session_factory, "chal3")
    pending = (await login(client, "chal3")).json()["pending_token"]

    response = await client.post(
        "/v1/auth/mfa/verify", json={"pending_token": pending, "code": "000000"}
    )

    assert response.status_code == 401
    rows = await denied_rows(session_factory, "mfa.verify")
    assert rows and rows[-1].details["reason"] == "invalid_code"


async def test_mfa_verify_unknown_token_401(client, session_factory):
    response = await client.post(
        "/v1/auth/mfa/verify", json={"pending_token": "bogus", "code": "123456"}
    )
    assert response.status_code == 401


async def test_mfa_verify_consumed_token_rejected(client, session_factory):
    await make_user(session_factory, "chal4")
    pending = (await login(client, "chal4")).json()["pending_token"]
    code = await totp_code(session_factory, "chal4")
    await client.post("/v1/auth/mfa/verify", json={"pending_token": pending, "code": code})

    replay = await client.post("/v1/auth/mfa/verify", json={"pending_token": pending, "code": code})
    assert replay.status_code == 401


async def test_new_login_invalidates_prior_challenge(client, session_factory):
    await make_user(session_factory, "chal5")
    first = (await login(client, "chal5")).json()["pending_token"]
    second = (await login(client, "chal5")).json()["pending_token"]
    assert first != second

    code = await totp_code(session_factory, "chal5")
    stale = await client.post("/v1/auth/mfa/verify", json={"pending_token": first, "code": code})
    assert stale.status_code == 401
    fresh = await client.post("/v1/auth/mfa/verify", json={"pending_token": second, "code": code})
    assert fresh.status_code == 200


async def test_challenge_expires(client, session_factory):
    await make_user(session_factory, "chal6")
    pending = (await login(client, "chal6")).json()["pending_token"]
    async with session_factory() as session:
        row = (await session.execute(select(MfaChallenge))).scalar_one()
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

    code = await totp_code(session_factory, "chal6")
    response = await client.post(
        "/v1/auth/mfa/verify", json={"pending_token": pending, "code": code}
    )
    assert response.status_code == 401
    rows = await denied_rows(session_factory, "mfa.verify")
    assert rows[-1].details["reason"] == "expired_challenge"


# AC-7: replay protection


async def test_same_totp_code_cannot_be_used_twice(client, session_factory):
    await make_user(session_factory, "replay1")
    await auth_client(client, "replay1")

    # The code just consumed by verify is burned; the next login needs a fresh step.
    # Force a new login and try reusing the previous step's code.
    async with session_factory() as session:
        user = (await session.execute(select(User).where(User.username == "replay1"))).scalar_one()
        secret = totp_security.open_secret(user.totp_secret_encrypted)
        last = user.totp_last_counter

    totp_obj = pyotp.TOTP(secret)
    # code for an already consumed step must be rejected
    old_code = totp_obj.at(for_time=datetime.fromtimestamp(last * 30, UTC))
    # craft a fresh challenge and try the old code
    pending = (await login(client, "replay1")).json()["pending_token"]
    response = await client.post(
        "/v1/auth/mfa/verify", json={"pending_token": pending, "code": old_code}
    )
    assert response.status_code == 401


# AC-8: lockout


async def test_five_bad_passwords_lock_account_429(client, session_factory):
    await make_user(session_factory, "lock1", enrolled=False)

    for _ in range(5):
        response = await login(client, "lock1", password="bad password")
        assert response.status_code == 401

    locked = await login(client, "lock1")
    assert locked.status_code == 429
    assert locked.json()["detail"]["retry_after_seconds"] > 0

    # Even the correct password gets 429 while locked.
    assert (await login(client, "lock1", password=PASSWORD)).status_code == 429


async def test_lockout_attempts_do_not_extend_lock(client, session_factory):
    await make_user(session_factory, "lock2", enrolled=False)
    for _ in range(5):
        await login(client, "lock2", password="bad password")

    async with session_factory() as session:
        user = (await session.execute(select(User).where(User.username == "lock2"))).scalar_one()
        first_until = user.locked_until

    await login(client, "lock2", password="bad password")

    async with session_factory() as session:
        user = (await session.execute(select(User).where(User.username == "lock2"))).scalar_one()
        assert user.locked_until == first_until
        assert user.failed_login_attempts == 5


async def test_successful_login_clears_lockout(client, session_factory):
    user = await make_user(session_factory, "lock3", enrolled=False)
    async with session_factory() as session:
        row = await session.get(User, user.id)
        row.failed_login_attempts = 4
        await session.commit()

    response = await login(client, "lock3")
    assert response.status_code == 200

    async with session_factory() as session:
        row = await session.get(User, user.id)
        assert row.failed_login_attempts == 0
        assert row.locked_until is None


async def test_bad_totp_counts_toward_lockout(client, session_factory):
    await make_user(session_factory, "lock4")
    async with session_factory() as session:
        user = (await session.execute(select(User).where(User.username == "lock4"))).scalar_one()
        user.failed_login_attempts = 4
        await session.commit()

    pending = (await login(client, "lock4")).json()["pending_token"]
    response = await client.post(
        "/v1/auth/mfa/verify", json={"pending_token": pending, "code": "000000"}
    )
    assert response.status_code == 401

    async with session_factory() as session:
        user = (await session.execute(select(User).where(User.username == "lock4"))).scalar_one()
        assert user.failed_login_attempts == 5
        assert user.locked_until is not None


# AC-9: admin reset


async def test_admin_reset_clears_mfa_and_revokes_sessions(client, session_factory):
    target = await make_user(session_factory, "reset1")
    await make_user(session_factory, "adminreset", role=UserRole.ADMIN)
    admin_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(admin_client, "adminreset")
    await auth_client(client, "reset1")

    response = await admin_client.post(f"/v1/users/{target.id}/mfa/reset")
    assert response.status_code == 204

    async with session_factory() as session:
        user = await session.get(User, target.id)
        assert user.totp_enabled_at is None
        assert user.totp_secret_encrypted is None
        assert user.totp_last_counter is None
        from app.models import Session as UserSession

        sessions_rows = (
            (await session.execute(select(UserSession).where(UserSession.user_id == target.id)))
            .scalars()
            .all()
        )
        assert all(s.revoked_at is not None for s in sessions_rows)

    # Old session is dead; user must log in and re-enroll.
    assert (await client.get("/v1/auth/me")).status_code == 401
    relogin = await login(client, "reset1")
    assert "session=" in relogin.headers.get("set-cookie", "")
    assert (await client.get("/v1/documents")).status_code == 403

    rows = await audit_rows(session_factory)
    assert any(r.action == "mfa.reset" and r.outcome == "allowed" for r in rows)


async def test_mfa_reset_denied_for_non_admin(client, session_factory):
    target = await make_user(session_factory, "reset2")
    await make_user(session_factory, "officerreset")
    await auth_client(client, "officerreset")

    response = await client.post(f"/v1/users/{target.id}/mfa/reset")
    assert response.status_code == 403


async def test_mfa_reset_unknown_user_404(client, session_factory):
    await make_user(session_factory, "adminreset2", role=UserRole.ADMIN)
    admin_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(admin_client, "adminreset2")

    response = await admin_client.post("/v1/users/00000000-0000-0000-0000-000000000000/mfa/reset")
    assert response.status_code == 404
