"""Auditor access and log verification tests (spec 0006)."""

from datetime import UTC, datetime, timedelta

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from test_api import (
    audit_rows,
    auth_client,
    denied_rows,
    login,
    make_admin,
    make_user,
)

from app.core.config import get_settings
from app.main import app
from app.models import AuditLog, ClassificationLevel, User, UserRole


async def make_auditor(session_factory, username: str, *, enrolled: bool = True):
    return await make_user(
        session_factory,
        username,
        role=UserRole.AUDITOR,
        clearance=ClassificationLevel.TOP_SECRET,
        enrolled=enrolled,
    )


ENTRY_FIELDS = {
    "seq",
    "id",
    "occurred_at",
    "actor_id",
    "actor_username",
    "actor_role",
    "action",
    "outcome",
    "target_type",
    "target_id",
    "details",
    "prev_hash",
    "hash",
}


# AC-1: auditor lists entries newest first with full shape
async def test_auditor_lists_entries_newest_first(client, session_factory):
    await make_auditor(session_factory, "aud1")
    await auth_client(client, "aud1")
    # produce a couple of audit rows beyond login
    await client.get("/v1/audit/entries")

    response = await client.get("/v1/audit/entries")

    assert response.status_code == 200, response.text
    body = response.json()
    entries = body["entries"]
    assert len(entries) >= 2
    assert set(entries[0].keys()) == ENTRY_FIELDS
    seqs = [e["seq"] for e in entries]
    assert seqs == sorted(seqs, reverse=True)
    assert body["next_cursor"] is None or isinstance(body["next_cursor"], int)


# AC-2: filters combine with AND; invalid values 422
async def test_entries_filters_and_validation(client, session_factory):
    await make_user(session_factory, "officer_f1")
    await make_auditor(session_factory, "aud2")
    await auth_client(client, "aud2")
    # denied login attempt by officer_f1 creates an outcome=denied row
    await login(client, "officer_f1", password="wrong password!!")

    ok = await client.get(
        "/v1/audit/entries",
        params={
            "actor_username": "officer_f1",
            "outcome": "denied",
            "action": "auth.login",
        },
    )
    assert ok.status_code == 200, ok.text
    entries = ok.json()["entries"]
    assert entries
    assert all(e["actor_username"] == "officer_f1" for e in entries)
    assert all(e["outcome"] == "denied" for e in entries)
    assert all(e["action"] == "auth.login" for e in entries)

    # AND semantics: matching username but wrong outcome yields nothing
    empty = await client.get(
        "/v1/audit/entries",
        params={"actor_username": "officer_f1", "outcome": "allowed", "action": "auth.login"},
    )
    assert empty.status_code == 200
    assert empty.json()["entries"] == []

    # datetime bounds
    now = datetime.now(UTC)
    bounded = await client.get(
        "/v1/audit/entries",
        params={
            "occurred_after": (now - timedelta(hours=1)).isoformat(),
            "occurred_before": (now + timedelta(hours=1)).isoformat(),
        },
    )
    assert bounded.status_code == 200
    assert bounded.json()["entries"]

    inverted = await client.get(
        "/v1/audit/entries",
        params={
            "occurred_after": (now + timedelta(hours=1)).isoformat(),
            "occurred_before": (now - timedelta(hours=1)).isoformat(),
        },
    )
    assert inverted.status_code == 200
    assert inverted.json()["entries"] == []

    for params in (
        {"outcome": "maybe"},
        {"occurred_after": "not-a-date"},
        {"occurred_after": "2026-01-01T00:00:00"},  # naive datetime
        {"limit": 0},
        {"limit": 201},
        {"limit": "abc"},
        {"cursor": 0},
        {"cursor": -3},
        {"cursor": "abc"},
    ):
        response = await client.get("/v1/audit/entries", params=params)
        assert response.status_code == 422, (params, response.text)


# AC-2: target_type and target_id filters
async def test_entries_target_filters(client, session_factory):
    await make_admin(session_factory, "admin_t1")
    await make_auditor(session_factory, "aud_t1")
    admin_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(admin_client, "admin_t1")
    await auth_client(client, "aud_t1")
    # role denial row carries target_type="user", target_id=<admin id>
    assert (await admin_client.get("/v1/audit/entries")).status_code == 403
    await admin_client.aclose()

    async with session_factory() as session:
        admin = (
            await session.execute(select(User).where(User.username == "admin_t1"))
        ).scalar_one()
        target_id = str(admin.id)

    by_type = await client.get(
        "/v1/audit/entries", params={"target_type": "user", "action": "audit.entries_list"}
    )
    assert by_type.status_code == 200
    assert by_type.json()["entries"]
    assert all(e["target_type"] == "user" for e in by_type.json()["entries"])

    by_both = await client.get(
        "/v1/audit/entries",
        params={"target_type": "user", "target_id": target_id, "action": "audit.entries_list"},
    )
    assert by_both.status_code == 200
    entries = by_both.json()["entries"]
    assert entries
    assert all(e["target_id"] == target_id for e in entries)

    miss = await client.get("/v1/audit/entries", params={"target_id": "no-such-id"})
    assert miss.status_code == 200
    assert miss.json()["entries"] == []


# AC-3: cursor pagination walks older pages
async def test_entries_cursor_pagination(client, session_factory):
    await make_auditor(session_factory, "aud3")
    await auth_client(client, "aud3")
    # several audit rows exist from login/enrollment flows; force > page size
    page1 = await client.get("/v1/audit/entries", params={"limit": 2})
    assert page1.status_code == 200
    body1 = page1.json()
    assert len(body1["entries"]) == 2
    cursor = body1["next_cursor"]
    assert cursor == body1["entries"][-1]["seq"]

    page2 = await client.get("/v1/audit/entries", params={"limit": 2, "cursor": cursor})
    assert page2.status_code == 200
    body2 = page2.json()
    assert all(e["seq"] < cursor for e in body2["entries"])
    if body2["entries"]:
        assert all(e["seq"] < body1["entries"][-1]["seq"] for e in body2["entries"])

    # cursor older than everything -> empty page, null cursor
    ancient = await client.get("/v1/audit/entries", params={"cursor": 1})
    assert ancient.status_code == 200
    assert ancient.json() == {"entries": [], "next_cursor": None}


# AC-4, AC-5: verify on clean chain, self audit row
async def test_verify_clean_chain_and_self_audit(client, session_factory):
    await make_auditor(session_factory, "aud4")
    await auth_client(client, "aud4")

    before = await audit_rows(session_factory)
    response = await client.post("/v1/audit/verify")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["valid"] is True
    assert body["checked_count"] == len(before)
    assert body["bad_seq_numbers"] == []
    assert body["head_hash"] == before[-1].hash

    after = await audit_rows(session_factory)
    assert len(after) == len(before) + 1
    row = after[-1]
    assert row.action == "audit.verify"
    assert row.outcome == "allowed"
    assert row.actor_username == "aud4"
    assert row.details == {
        "valid": True,
        "checked_count": len(before),
        "bad_count": 0,
    }
    # the verify row itself extends the chain
    assert row.prev_hash == before[-1].hash


# AC-5: list calls append nothing
async def test_list_entries_appends_no_audit(client, session_factory):
    await make_auditor(session_factory, "aud5")
    await auth_client(client, "aud5")

    before = await audit_rows(session_factory)
    for _ in range(3):
        response = await client.get("/v1/audit/entries")
        assert response.status_code == 200
    after = await audit_rows(session_factory)
    assert len(after) == len(before)


# AC-4, AC-10: tampered middle entry detected, still listed
async def test_verify_detects_tampered_entry(client, session_factory):
    await make_user(session_factory, "officer_t1")
    await make_auditor(session_factory, "aud6")
    await auth_client(client, "aud6")
    await login(client, "officer_t1", password="wrong password!!")

    async with session_factory() as session:
        rows = (await session.execute(select(AuditLog).order_by(AuditLog.seq))).scalars().all()
        middle = rows[len(rows) // 2]
        middle.details = {"tampered": True}
        await session.commit()
        tampered_seq = middle.seq
        snapshot_head = rows[-1].hash

    response = await client.post("/v1/audit/verify")
    assert response.status_code == 200
    body = response.json()
    assert body["valid"] is False
    assert tampered_seq in body["bad_seq_numbers"]
    # head_hash describes the pre-append snapshot, unaffected by the verify row
    assert body["head_hash"] == snapshot_head

    verify_rows = await audit_rows(session_factory)
    self_audit = verify_rows[-1]
    assert self_audit.action == "audit.verify"
    assert self_audit.details["valid"] is False
    assert self_audit.details["bad_count"] == len(body["bad_seq_numbers"])
    assert self_audit.details["checked_count"] == body["checked_count"]

    listing = await client.get("/v1/audit/entries", params={"cursor": tampered_seq + 1})
    assert listing.status_code == 200
    found = [e for e in listing.json()["entries"] if e["seq"] == tampered_seq]
    assert found and found[0]["details"] == {"tampered": True}


# AC-10: tampered details of non-object JSON still listed verbatim
async def test_entries_lists_tampered_scalar_details(client, session_factory):
    await make_auditor(session_factory, "aud_t2")
    await auth_client(client, "aud_t2")

    async with session_factory() as session:
        stmt = select(AuditLog).order_by(AuditLog.seq.desc())
        row = (await session.execute(stmt)).scalars().first()
        row.details = "corrupted"
        await session.commit()
        tampered_seq = row.seq

    response = await client.get("/v1/audit/entries", params={"limit": 200})
    assert response.status_code == 200, response.text
    found = [e for e in response.json()["entries"] if e["seq"] == tampered_seq]
    assert found and found[0]["details"] == "corrupted"


# AC-4: deleted middle entry detected via successor flag
async def test_verify_detects_deleted_middle_entry(client, session_factory):
    await make_user(session_factory, "officer_t2")
    await make_auditor(session_factory, "aud7")
    await auth_client(client, "aud7")
    await login(client, "officer_t2", password="wrong password!!")

    async with session_factory() as session:
        rows = (await session.execute(select(AuditLog).order_by(AuditLog.seq))).scalars().all()
        assert len(rows) >= 3
        victim = rows[1]
        successor_seq = rows[2].seq
        await session.delete(victim)
        await session.commit()

    response = await client.post("/v1/audit/verify")
    body = response.json()
    assert body["valid"] is False
    assert successor_seq in body["bad_seq_numbers"]


# AC-4: empty log verifies clean
async def test_verify_empty_log(client, session_factory):
    await make_auditor(session_factory, "aud8")
    await auth_client(client, "aud8")
    async with session_factory() as session:
        from sqlalchemy import delete

        await session.execute(delete(AuditLog))
        await session.commit()

    response = await client.post("/v1/audit/verify")
    assert response.status_code == 200
    body = response.json()
    assert body == {
        "valid": True,
        "checked_count": 0,
        "head_hash": None,
        "bad_seq_numbers": [],
    }


# AC-6: admin and user roles denied with audited role denial
async def test_non_auditor_roles_denied(client, session_factory):
    await make_admin(session_factory, "admin_a1")
    await make_user(session_factory, "user_a1")

    admin_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(admin_client, "admin_a1")
    user_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(user_client, "user_a1")

    for c in (admin_client, user_client):
        assert (await c.get("/v1/audit/entries")).status_code == 403
        assert (await c.post("/v1/audit/verify")).status_code == 403
    await admin_client.aclose()
    await user_client.aclose()

    denials = await denied_rows(session_factory)
    list_denials = [r for r in denials if r.action == "audit.entries_list"]
    verify_denials = [r for r in denials if r.action == "audit.verify"]
    assert len(list_denials) == 2
    assert len(verify_denials) == 2
    assert {r.actor_username for r in list_denials} == {"admin_a1", "user_a1"}


# AC-7: auditor still denied documents (regression)
async def test_auditor_denied_documents(client, session_factory):
    await make_user(session_factory, "officer_t3")
    await make_auditor(session_factory, "aud9")
    await auth_client(client, "aud9")

    assert (await client.get("/v1/documents")).status_code == 403
    assert (await client.get("/v1/users")).status_code == 403
    denials = await denied_rows(session_factory)
    assert any(r.action == "document.list" for r in denials)


# AC-8: unenrolled auditor gets mfa_enrollment_required on both endpoints
async def test_unenrolled_auditor_gate_denied(client, session_factory):
    await make_auditor(session_factory, "aud10", enrolled=False)
    await auth_client(client, "aud10")

    for method, url in (("get", "/v1/audit/entries"), ("post", "/v1/audit/verify")):
        response = await getattr(client, method)(url)
        assert response.status_code == 403, response.text
        assert response.json()["detail"] == "mfa enrollment required"

    denials = await denied_rows(session_factory)
    actions = {r.action for r in denials if r.details.get("reason") == "mfa_enrollment_required"}
    assert "audit.entries_list" in actions
    assert "audit.verify" in actions


# AC-9: verify is rate limited per session
async def test_verify_rate_limited(client, session_factory):
    settings = get_settings()
    settings.rate_limit_enabled = True
    settings.rate_limit_audit = "3/minute"
    try:
        await make_auditor(session_factory, "aud11")
        await auth_client(client, "aud11")
        codes = [(await client.post("/v1/audit/verify")).status_code for _ in range(4)]
        assert codes[:3] == [200, 200, 200]
        assert codes[3] == 429
    finally:
        settings.rate_limit_enabled = False
        settings.rate_limit_audit = "30/minute"


# AC-9: limit is keyed per session token; RATE_LIMIT_ENABLED disables it
async def test_verify_rate_limit_per_session_and_kill_switch(client, session_factory):
    settings = get_settings()
    settings.rate_limit_enabled = True
    settings.rate_limit_audit = "2/minute"
    try:
        await make_auditor(session_factory, "aud12")
        await make_auditor(session_factory, "aud13")
        await auth_client(client, "aud12")
        # exhaust this session's budget
        assert (await client.post("/v1/audit/verify")).status_code == 200
        assert (await client.post("/v1/audit/verify")).status_code == 200
        assert (await client.post("/v1/audit/verify")).status_code == 429

        # a second auditor session has its own budget
        other = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
        await auth_client(other, "aud13")
        assert (await other.post("/v1/audit/verify")).status_code == 200
        await other.aclose()

        # kill switch disables the limit entirely
        settings.rate_limit_enabled = False
        assert (await client.post("/v1/audit/verify")).status_code == 200
    finally:
        settings.rate_limit_enabled = False
        settings.rate_limit_audit = "30/minute"
