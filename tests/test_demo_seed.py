"""Tests for `seed-demo` (spec 0011 AC-2 to AC-5)."""

import pyotp
import pytest
from sqlalchemy import func, select

from app.core.config import get_settings
from app.demo_constants import BY_USERNAME, DEMO_USERS
from app.models import AuditLog, User
from app.services import audit as audit_service
from app.services.demo import SeedEnvRefused, seed_demo


async def _demo_login(client, demo_user) -> None:
    """Full enrolled-user flow: password login then TOTP verify."""
    resp = await client.post(
        "/v1/auth/login",
        json={"username": demo_user.username, "password": demo_user.password},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["mfa_required"] is True
    code = pyotp.TOTP(demo_user.totp_secret).now()
    resp = await client.post(
        "/v1/auth/mfa/verify",
        json={"pending_token": body["pending_token"], "code": code},
    )
    assert resp.status_code == 200, resp.text
    me = await client.get("/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == demo_user.username


async def test_seed_creates_cast_and_everyone_can_log_in(client, session_factory):
    results = await seed_demo(session_factory)
    assert [r.status for r in results] == ["created"] * len(DEMO_USERS)

    async with session_factory() as session:
        count = (await session.execute(select(func.count()).select_from(User))).scalar_one()
    assert count == len(DEMO_USERS)

    for demo in DEMO_USERS:
        await _demo_login(client, demo)


async def test_seed_is_idempotent(client, session_factory):
    await seed_demo(session_factory)
    results = await seed_demo(session_factory)
    assert [r.status for r in results] == ["exists"] * len(DEMO_USERS)

    async with session_factory() as session:
        count = (await session.execute(select(func.count()).select_from(User))).scalar_one()
    assert count == len(DEMO_USERS)


async def test_seed_repairs_drifted_users(client, session_factory):
    await seed_demo(session_factory)
    drifted = BY_USERNAME["demo-officer-mid"]
    async with session_factory() as session:
        user = (
            await session.execute(select(User).where(User.username == drifted.username))
        ).scalar_one()
        user.clearance = 1
        user.role = "auditor"
        user.is_active = False
        user.totp_enabled_at = None
        await session.commit()

    results = await seed_demo(session_factory)
    by_name = {r.username: r for r in results}
    assert by_name["demo-officer-mid"].status == "repaired"
    assert by_name["demo-admin"].status == "exists"

    async with session_factory() as session:
        user = (
            await session.execute(select(User).where(User.username == drifted.username))
        ).scalar_one()
    assert user.clearance == drifted.clearance
    assert user.role == drifted.role
    assert user.is_active is True
    assert user.totp_enabled_at is not None

    await _demo_login(client, drifted)


async def test_seed_refuses_non_dev_env(session_factory, monkeypatch):
    monkeypatch.setenv("ENV", "prod")
    get_settings.cache_clear()
    try:
        with pytest.raises(SeedEnvRefused):
            await seed_demo(session_factory)
    finally:
        get_settings.cache_clear()


async def test_seed_writes_audit_entries_and_chain_verifies(session_factory):
    await seed_demo(session_factory)
    async with session_factory() as session:
        rows = (
            (
                await session.execute(
                    select(AuditLog).where(
                        AuditLog.action == "user.create",
                        AuditLog.outcome == "allowed",
                    )
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == len(DEMO_USERS)
        assert all(row.actor_id is None for row in rows)
        assert all(
            isinstance(row.details, dict) and row.details.get("via") == "seed-demo" for row in rows
        )
        assert await audit_service.verify_chain(session) == []
