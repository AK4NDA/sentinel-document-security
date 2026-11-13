"""Audit log export tests (spec 0013)."""

import csv
import io
import json
import uuid
from datetime import UTC, datetime, timedelta

from httpx import ASGITransport, AsyncClient
from test_api import (
    audit_rows,
    auth_client,
    denied_rows,
    login,
    make_admin,
    make_user,
)
from test_audit import make_auditor

from app.core.config import get_settings
from app.main import app
from app.models import AuditLog
from app.services import audit as audit_service

EXPORT_URL = "/v1/audit/export"


async def export(client, fmt="csv", **params):
    return await client.get(EXPORT_URL, params={"format": fmt, **params})


def parse_csv(text: str) -> tuple[list[str], list[list[str]]]:
    rows = list(csv.reader(io.StringIO(text)))
    return rows[0], rows[1:]


async def export_audit_entries(session_factory) -> list[AuditLog]:
    rows = await audit_rows(session_factory)
    return [r for r in rows if r.action == "audit.export"]


# AC-1, AC-3, AC-7, AC-11: CSV happy path, filters, order, columns, self audit
async def test_export_csv_happy_path(client, session_factory):
    await make_user(session_factory, "officer_e1")
    await make_auditor(session_factory, "aud_e1")
    await auth_client(client, "aud_e1")
    await login(client, "officer_e1", password="wrong password!!")

    before = await audit_rows(session_factory)
    head_seq = before[-1].seq
    head_hash = before[-1].hash

    response = await export(client, actor_username="officer_e1")

    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/csv")
    disposition = response.headers["content-disposition"]
    assert 'attachment; filename="audit-export-' in disposition
    assert disposition.endswith('.csv"')
    assert "x-export-truncated" not in response.headers

    header, data = parse_csv(response.text)
    assert header == list(audit_service.EXPORT_COLUMNS)
    assert data
    seqs = [int(r[0]) for r in data]
    assert seqs == sorted(seqs)
    assert all(s <= head_seq for s in seqs)
    actor_idx = audit_service.EXPORT_COLUMNS.index("actor_username")
    assert all(r[actor_idx] == "officer_e1" for r in data)
    occurred_idx = audit_service.EXPORT_COLUMNS.index("occurred_at")
    assert all(r[occurred_idx].endswith("Z") for r in data)
    details_idx = audit_service.EXPORT_COLUMNS.index("details")
    for r in data:
        if r[details_idx]:
            json.loads(r[details_idx])

    entries = await export_audit_entries(session_factory)
    assert len(entries) == 1
    er = entries[0]
    assert er.outcome == "allowed"
    assert er.actor_username == "aud_e1"
    assert er.actor_role == "auditor"
    assert er.target_type == "audit_log"
    assert er.seq > head_seq
    assert er.details == {
        "filters": {"actor_username": "officer_e1"},
        "format": "csv",
        "rows_exported": len(data),
        "truncated": False,
        "head_seq": head_seq,
        "head_hash": head_hash,
    }


# AC-2, AC-9, AC-11: JSONL shape and bad format rejection
async def test_export_jsonl_and_format_validation(client, session_factory):
    await make_auditor(session_factory, "aud_j1")
    await auth_client(client, "aud_j1")

    response = await export(client, "json")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/x-ndjson"
    assert response.headers["content-disposition"].endswith('.jsonl"')

    lines = [json.loads(line) for line in response.text.splitlines() if line.strip()]
    assert lines
    seqs = [row["seq"] for row in lines]
    assert seqs == sorted(seqs)
    for row in lines:
        assert set(row.keys()) == set(audit_service.EXPORT_COLUMNS)
        assert row["occurred_at"].endswith("Z")
        assert row["details"] is None or isinstance(row["details"], dict)

    bad = await export(client, "xml")
    assert bad.status_code == 422


# AC-3: filter parity with entries endpoint; paging params ignored; inverted range 422
async def test_export_filters_and_range_validation(client, session_factory):
    await make_user(session_factory, "officer_f1")
    await make_auditor(session_factory, "aud_f1")
    await auth_client(client, "aud_f1")
    await login(client, "officer_f1", password="wrong password!!")

    response = await export(
        client,
        action="auth.login",
        outcome="denied",
        actor_username="officer_f1",
    )
    assert response.status_code == 200, response.text
    _, data = parse_csv(response.text)
    assert data
    action_idx = audit_service.EXPORT_COLUMNS.index("action")
    outcome_idx = audit_service.EXPORT_COLUMNS.index("outcome")
    assert all(r[action_idx] == "auth.login" for r in data)
    assert all(r[outcome_idx] == "denied" for r in data)

    # cursor and limit are not export params; extra query params are ignored
    ignored = await client.get(EXPORT_URL, params={"format": "csv", "cursor": 1, "limit": 5})
    assert ignored.status_code == 200

    now = datetime.now(UTC)
    inverted = await export(
        client,
        occurred_after=(now + timedelta(hours=1)).isoformat(),
        occurred_before=(now - timedelta(hours=1)).isoformat(),
    )
    assert inverted.status_code == 422


# AC-5: snapshot pinning; own export row never inside its file, prior exports can appear
async def test_export_snapshot_boundaries(client, session_factory):
    await make_auditor(session_factory, "aud_s1")
    await auth_client(client, "aud_s1")

    first = await export(client)
    assert first.status_code == 200
    first_entries = await export_audit_entries(session_factory)
    assert len(first_entries) == 1

    second = await export(client)
    assert second.status_code == 200
    _, data = parse_csv(second.text)
    action_idx = audit_service.EXPORT_COLUMNS.index("action")
    seq_idx = 0
    export_seqs = {int(r[seq_idx]) for r in data if r[action_idx] == "audit.export"}
    # the first export's audit row committed before this export's head capture
    assert first_entries[0].seq in export_seqs
    # every exported row sits at or below this export's recorded head
    second_entries = await export_audit_entries(session_factory)
    assert len(second_entries) == 2
    own = second_entries[-1]
    assert own.seq > own.details["head_seq"]
    assert all(int(r[seq_idx]) <= own.details["head_seq"] for r in data)
    assert str(own.seq) not in {r[seq_idx] for r in data}


# AC-6: row cap truncates body, header flag, and audit detail agree
async def test_export_truncation_cap(client, session_factory):
    settings = get_settings()
    settings.export_max_rows = 3
    try:
        await make_auditor(session_factory, "aud_c1")
        await auth_client(client, "aud_c1")
        async with session_factory() as session:
            for _ in range(5):
                session.add(
                    AuditLog(
                        id=uuid.uuid4(),
                        occurred_at=datetime.now(UTC),
                        actor_id=None,
                        actor_username=None,
                        actor_role=None,
                        action="test.seed",
                        outcome="allowed",
                        target_type=None,
                        target_id=None,
                        details=None,
                        prev_hash=uuid.uuid4().hex * 2,
                        hash=uuid.uuid4().hex * 2,
                    )
                )
            await session.commit()

        response = await export(client)
        assert response.status_code == 200, response.text
        assert response.headers["x-export-truncated"] == "true"
        _, data = parse_csv(response.text)
        assert len(data) == 3

        entries = await export_audit_entries(session_factory)
        assert entries[-1].details["truncated"] is True
        assert entries[-1].details["rows_exported"] == 3
    finally:
        settings.export_max_rows = 50000


# AC-4: admin and user denied with audited role denial; unenrolled auditor gated
async def test_export_role_denials_and_mfa_gate(client, session_factory):
    await make_admin(session_factory, "admin_x1")
    await make_user(session_factory, "user_x1")
    await make_auditor(session_factory, "aud_x1", enrolled=False)

    admin_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(admin_client, "admin_x1")
    user_client = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    await auth_client(user_client, "user_x1")

    for c in (admin_client, user_client):
        response = await export(c)
        assert response.status_code == 403
    await admin_client.aclose()
    await user_client.aclose()

    denials = await denied_rows(session_factory, "audit.export")
    role_denials = [r for r in denials if r.details.get("reason") == "role"]
    assert {r.actor_username for r in role_denials} == {"admin_x1", "user_x1"}

    await auth_client(client, "aud_x1")
    gated = await export(client)
    assert gated.status_code == 403
    assert gated.json()["detail"] == "mfa enrollment required"
    gate_denials = [
        r
        for r in await denied_rows(session_factory, "audit.export")
        if r.details.get("reason") == "mfa_enrollment_required"
    ]
    assert gate_denials and gate_denials[0].actor_username == "aud_x1"


# AC-8: CSV formula injection sanitized, details stays valid JSON
async def test_export_csv_sanitizes_formula_cells(client, session_factory):
    await make_auditor(session_factory, "aud_i1")
    await auth_client(client, "aud_i1")

    async with session_factory() as session:
        for username in ("=1+1", " =cmd|' /C calc'!A0"):
            session.add(
                AuditLog(
                    id=uuid.uuid4(),
                    occurred_at=datetime.now(UTC),
                    actor_id=None,
                    actor_username=username,
                    actor_role="auditor",
                    action="test.inject",
                    outcome="allowed",
                    target_type=None,
                    target_id=None,
                    details={"note": "x"},
                    prev_hash=uuid.uuid4().hex * 2,
                    hash=uuid.uuid4().hex * 2,
                )
            )
        await session.commit()

    response = await export(client, action="test.inject")
    assert response.status_code == 200, response.text
    _, data = parse_csv(response.text)
    assert len(data) == 2
    actor_idx = audit_service.EXPORT_COLUMNS.index("actor_username")
    cells = {r[actor_idx] for r in data}
    assert cells == {"'=1+1", "' =cmd|' /C calc'!A0"}
    details_idx = audit_service.EXPORT_COLUMNS.index("details")
    for r in data:
        assert json.loads(r[details_idx]) == {"note": "x"}


# AC-9: empty result is a valid empty file, audited with zero rows
async def test_export_empty_result(client, session_factory):
    await make_auditor(session_factory, "aud_n1")
    await auth_client(client, "aud_n1")

    csv_response = await export(client, action="no.such.action")
    assert csv_response.status_code == 200
    header, data = parse_csv(csv_response.text)
    assert header == list(audit_service.EXPORT_COLUMNS)
    assert data == []

    json_response = await export(client, "json", action="no.such.action")
    assert json_response.status_code == 200
    assert json_response.text == ""

    entries = await export_audit_entries(session_factory)
    assert len(entries) == 2
    assert all(e.details["rows_exported"] == 0 for e in entries)
    assert all(e.details["truncated"] is False for e in entries)


# AC-7: aborted stream still records the export
async def test_export_audit_recorded_on_abort(client, session_factory):
    await make_auditor(session_factory, "aud_b1")
    await auth_client(client, "aud_b1")

    async with client.stream("GET", EXPORT_URL, params={"format": "csv"}) as response:
        assert response.status_code == 200
        async for _chunk in response.aiter_bytes():
            break

    entries = await export_audit_entries(session_factory)
    assert len(entries) == 1
    assert entries[0].details["rows_exported"] >= 0
    assert "rows_exported" in entries[0].details


# AC-5 edge: empty chain reports null head values
async def test_export_head_empty_log(session_factory):
    async with session_factory() as session:
        assert await audit_service.export_head(session) == (None, None)


# AC-8/AC-11: serializer units, nulls and remaining dangerous characters
def _make_row(**overrides) -> AuditLog:
    base = dict(
        id=uuid.uuid4(),
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
        actor_id=None,
        actor_username=None,
        actor_role=None,
        action="test.unit",
        outcome="allowed",
        target_type=None,
        target_id=None,
        details=None,
        prev_hash="0" * 64,
        hash="a" * 64,
    )
    base.update(overrides)
    return AuditLog(**base)


def _csv_cells(record: str) -> dict[str, str]:
    row = next(csv.reader(io.StringIO(record)))
    return dict(zip(audit_service.EXPORT_COLUMNS, row, strict=True))


def test_export_csv_nulls_and_dangerous_chars():
    row = _make_row(actor_username="\t=cmd", actor_id=uuid.uuid4())
    cells = _csv_cells(audit_service.export_csv_row(row))
    # leading tab is itself a dangerous char, and '=' follows after lstrip
    assert cells["actor_username"] == "'\t=cmd"
    assert cells["actor_id"] != ""
    assert cells["target_type"] == ""
    assert cells["details"] == ""


def test_export_csv_details_compact_sorted():
    row = _make_row(details={"b": 1, "a": {"y": 2, "x": 1}})
    cells = _csv_cells(audit_service.export_csv_row(row))
    assert cells["details"] == '{"a":{"x":1,"y":2},"b":1}'


def test_export_jsonl_nulls_and_shapes():
    row = _make_row(details={"k": "v"})
    parsed = json.loads(audit_service.export_jsonl_row(row))
    assert parsed["actor_id"] is None
    assert parsed["actor_username"] is None
    assert parsed["details"] == {"k": "v"}
    assert parsed["occurred_at"].endswith("Z")
    assert set(parsed.keys()) == set(audit_service.EXPORT_COLUMNS)


# AC-10: export shares the audit rate limit
async def test_export_rate_limited(client, session_factory):
    settings = get_settings()
    settings.rate_limit_enabled = True
    settings.rate_limit_audit = "2/minute"
    try:
        await make_auditor(session_factory, "aud_r1")
        await auth_client(client, "aud_r1")
        codes = [(await export(client)).status_code for _ in range(3)]
        assert codes == [200, 200, 429]
    finally:
        settings.rate_limit_enabled = False
        settings.rate_limit_audit = "30/minute"
