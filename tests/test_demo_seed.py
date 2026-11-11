"""Tests for `seed-demo` (spec 0011 AC-2 to AC-5)."""

import pyotp
import pytest
from sqlalchemy import func, select

import app.cli as cli_module
from app.core.config import get_settings
from app.demo_constants import BY_USERNAME, DEMO_USERS
from app.models import AuditLog, User
from app.security import totp as totp_security
from app.services import audit as audit_service
from app.services.demo import SeedEnvRefused, SeedResult, seed_demo


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


async def test_seed_repairs_wrong_totp_secret(client, session_factory):
    await seed_demo(session_factory)
    demo = BY_USERNAME["demo-officer-high"]
    async with session_factory() as session:
        user = (
            await session.execute(select(User).where(User.username == demo.username))
        ).scalar_one()
        user.totp_secret_encrypted = totp_security.seal_secret("JBSWY3DPEHPK3PXP")
        await session.commit()

    results = await seed_demo(session_factory)
    assert {r.username: r.status for r in results}[demo.username] == "repaired"

    async with session_factory() as session:
        user = (
            await session.execute(select(User).where(User.username == demo.username))
        ).scalar_one()
    assert totp_security.open_secret(user.totp_secret_encrypted) == demo.totp_secret
    await _demo_login(client, demo)


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


# --- CLI wiring ------------------------------------------------------------


def _stub_seed(monkeypatch, outcome):
    async def fake_seed(session_factory):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(cli_module, "seed_demo", fake_seed)


def test_cli_seed_demo_prints_per_user_status(capsys, monkeypatch):
    _stub_seed(
        monkeypatch,
        [SeedResult(u.username, "exists") for u in DEMO_USERS],
    )
    assert cli_module.main(["seed-demo"]) == 0
    out = capsys.readouterr().out
    assert "exists: demo-admin" in out
    assert "5 unchanged" in out


def test_cli_seed_demo_reports_created_and_repaired(capsys, monkeypatch):
    _stub_seed(
        monkeypatch,
        [
            SeedResult("demo-admin", "created"),
            SeedResult("demo-auditor", "repaired"),
            *[SeedResult(u.username, "exists") for u in DEMO_USERS[2:]],
        ],
    )
    assert cli_module.main(["seed-demo"]) == 0
    out = capsys.readouterr().out
    assert "1 created, 1 repaired, 3 unchanged" in out


def test_cli_seed_demo_env_refusal_exits_2(capsys, monkeypatch):
    _stub_seed(monkeypatch, SeedEnvRefused("seed-demo only runs when ENV is dev"))
    assert cli_module.main(["seed-demo"]) == 2
    assert "ENV is dev" in capsys.readouterr().err


def test_cli_seed_demo_integrity_error_exits_1(capsys, monkeypatch):
    from sqlalchemy.exc import IntegrityError

    _stub_seed(monkeypatch, IntegrityError("stmt", {}, Exception("dup")))
    assert cli_module.main(["seed-demo"]) == 1
    assert "uniqueness conflict" in capsys.readouterr().err
