"""Maintenance and retention cleanup tests (spec 0012)."""

import asyncio
import os
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select
from test_api import make_user

import app.cli as cli
import app.main as main_module
import app.services.maintenance as maintenance
from app.core.config import Settings
from app.models import (
    Alert,
    AuditLog,
    ClassificationLevel,
    Document,
    DocumentShare,
    DocumentVersion,
    MfaChallenge,
    UserRole,
)
from app.models import Session as UserSession
from app.services import audit as audit_service
from app.services import blob_store
from app.services.maintenance import run_cleanup, scheduler_loop

NOW = datetime.now(UTC)
OLD = NOW - timedelta(days=120)
RECENT = NOW - timedelta(days=1)


def _settings(tmp_path: Path | None = None, **overrides) -> Settings:
    settings = Settings()
    if tmp_path is not None:
        settings.upload_dir = tmp_path
    for key, value in overrides.items():
        setattr(settings, key, value)
    return settings


async def _add(session_factory, row) -> None:
    async with session_factory() as session:
        session.add(row)
        await session.commit()


async def _challenge(session_factory, user_id, **kwargs) -> MfaChallenge:
    row = MfaChallenge(
        user_id=user_id,
        token_hash=uuid.uuid4().hex + uuid.uuid4().hex,
        created_at=NOW,
        expires_at=kwargs.pop("expires_at", NOW + timedelta(minutes=5)),
        attempts=kwargs.pop("attempts", 0),
        **kwargs,
    )
    await _add(session_factory, row)
    return row


async def _session_row(session_factory, user_id, **kwargs) -> UserSession:
    row = UserSession(
        user_id=user_id,
        token_hash=uuid.uuid4().hex + uuid.uuid4().hex,
        created_at=NOW,
        last_seen_at=NOW,
        expires_at=kwargs.pop("expires_at", NOW + timedelta(hours=1)),
        **kwargs,
    )
    await _add(session_factory, row)
    return row


async def _document(session_factory, owner_id) -> Document:
    doc = Document(id=uuid.uuid4(), title="doc", owner_id=owner_id)
    await _add(session_factory, doc)
    return doc


async def _version(session_factory, doc_id, owner_id, blob_path: str) -> DocumentVersion:
    row = DocumentVersion(
        id=uuid.uuid4(),
        document_id=doc_id,
        version_number=1,
        classification=ClassificationLevel.UNCLASSIFIED,
        content_sha256="0" * 64,
        blob_path=blob_path,
        size_bytes=1,
        mime_type="text/plain",
        created_by=owner_id,
    )
    await _add(session_factory, row)
    return row


async def _share(session_factory, doc_id, user_id, granter_id, **kwargs) -> DocumentShare:
    row = DocumentShare(
        id=uuid.uuid4(),
        document_id=doc_id,
        user_id=user_id,
        granted_by=granter_id,
        access_level="read",
        **kwargs,
    )
    await _add(session_factory, row)
    return row


async def _audit_seq(session_factory) -> int:
    async with session_factory() as session:
        entry = await audit_service.append(
            session,
            action="test.ping",
            outcome="allowed",
            actor_username="setup",
        )
        await session.commit()
        return entry.seq


async def _alert(session_factory, seq: int, **kwargs) -> Alert:
    fields = {
        "id": uuid.uuid4(),
        "alert_type": "denied_access",
        "state": "open",
        "summary": {},
        "audit_seq": seq,
    }
    fields.update(kwargs)
    row = Alert(**fields)
    await _add(session_factory, row)
    return row


async def _count(session_factory, model) -> int:
    async with session_factory() as session:
        return (await session.execute(select(func.count()).select_from(model))).scalar_one()


async def _cleanup_entries(session_factory) -> list[AuditLog]:
    async with session_factory() as session:
        result = await session.execute(
            select(AuditLog).where(AuditLog.action == "maintenance.cleanup")
        )
        return list(result.scalars().all())


# AC-1, AC-5, AC-9: dead challenges and sessions removed, live rows kept
async def test_dead_rows_removed_live_rows_kept(session_factory, tmp_path):
    user = await make_user(session_factory, "maint_user")
    uid = user.id
    await _challenge(session_factory, uid, consumed_at=NOW)
    await _challenge(session_factory, uid, expires_at=NOW - timedelta(seconds=1))
    await _challenge(session_factory, uid, attempts=5)
    live_challenge = await _challenge(session_factory, uid)

    await _session_row(session_factory, uid, expires_at=NOW - timedelta(seconds=1))
    await _session_row(session_factory, uid, revoked_at=NOW)
    live_session = await _session_row(session_factory, uid)

    report = await run_cleanup(session_factory, _settings(tmp_path))

    assert report.stages["mfa_challenges"] == 3
    assert report.stages["sessions"] == 2
    assert report.errors == {}
    async with session_factory() as session:
        remaining = (
            (await session.execute(select(MfaChallenge))).scalars().all(),
            (await session.execute(select(UserSession))).scalars().all(),
        )
    assert [r.id for r in remaining[0]] == [live_challenge.id]
    assert [r.id for r in remaining[1]] == [live_session.id]

    entries = await _cleanup_entries(session_factory)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.outcome == "allowed"
    assert entry.target_type == "maintenance"
    assert entry.target_id is None
    assert entry.actor_username == "system"
    assert entry.actor_id is None
    assert entry.actor_role is None
    assert entry.details["dry_run"] is False
    assert entry.details["stages"]["mfa_challenges"] == {"deleted": 3}
    assert entry.details["stages"]["sessions"] == {"deleted": 2}
    assert entry.details["errors"] == {}


# AC-2, AC-9, AC-10: retention window on revoked shares and acknowledged alerts
async def test_share_and_alert_retention_window(session_factory, tmp_path):
    owner = await make_user(session_factory, "ret_owner", role=UserRole.ADMIN)
    grantee = await make_user(session_factory, "ret_grantee")
    other = await make_user(session_factory, "ret_other")
    doc = await _document(session_factory, owner.id)
    doc2 = await _document(session_factory, owner.id)
    settings = _settings(tmp_path, maintenance_share_alert_retention_days=30)
    cutoff = NOW - timedelta(days=30)

    await _share(session_factory, doc.id, grantee.id, owner.id, revoked_at=OLD)
    await _share(session_factory, doc.id, other.id, owner.id, revoked_at=cutoff)
    await _share(session_factory, doc2.id, grantee.id, owner.id, revoked_at=RECENT)
    await _share(session_factory, doc2.id, other.id, owner.id, revoked_at=None)

    seq_old = await _audit_seq(session_factory)
    seq_recent = await _audit_seq(session_factory)
    seq_open = await _audit_seq(session_factory)
    seq_null = await _audit_seq(session_factory)
    await _alert(session_factory, seq_old, state="acknowledged", acknowledged_at=OLD)
    await _alert(session_factory, seq_recent, state="acknowledged", acknowledged_at=RECENT)
    await _alert(session_factory, seq_open, state="open")
    await _alert(session_factory, seq_null, state="acknowledged", acknowledged_at=None)

    report = await run_cleanup(session_factory, settings)

    assert report.stages["document_shares"] == 2
    assert report.stages["alerts"] == 1
    assert await _count(session_factory, DocumentShare) == 2
    assert await _count(session_factory, Alert) == 3


# AC-3, AC-8, AC-9: only unreferenced blobs past min age are collected
async def test_blob_collection_rules(session_factory, tmp_path):
    owner = await make_user(session_factory, "blob_owner")
    doc = await _document(session_factory, owner.id)
    settings = _settings(tmp_path, maintenance_blob_min_age_seconds=3600)

    def blob_file(rel: str, age_seconds: float) -> Path:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"ciphertext")
        stamp = (datetime.now(UTC) - timedelta(seconds=age_seconds)).timestamp()
        os.utime(path, (stamp, stamp))
        return path

    referenced_rel = "aa/" + "a" * 64 + ".enc"
    await _version(session_factory, doc.id, owner.id, referenced_rel)
    blob_file(referenced_rel, 7200)

    orphan_old = blob_file("bb/" + "b" * 64 + ".enc", 7200)
    orphan_young = blob_file("cc/" + "c" * 64 + ".enc", 60)
    tmp_old = blob_file("dd/" + "d" * 64 + ".enc.tmp", 7200)
    tmp_young = blob_file("ee/" + "e" * 64 + ".enc.tmp", 60)

    report = await run_cleanup(session_factory, settings)

    assert report.stages["blobs"] == 2
    assert not orphan_old.exists()
    assert not tmp_old.exists()
    assert orphan_young.exists()
    assert tmp_young.exists()
    assert (tmp_path / referenced_rel).exists()


async def test_blob_stage_missing_upload_dir_is_empty(session_factory, tmp_path):
    settings = _settings(tmp_path / "does-not-exist")
    report = await run_cleanup(session_factory, settings)
    assert report.stages["blobs"] == 0
    assert "blobs" not in report.errors


# AC-3, AC-9: only *.enc and *.enc.tmp names are candidates, at any depth
async def test_blob_stage_ignores_non_blob_files(session_factory, tmp_path):
    owner = await make_user(session_factory, "blob_edge_owner")
    await _document(session_factory, owner.id)
    settings = _settings(tmp_path, maintenance_blob_min_age_seconds=3600)

    def old_file(rel: str) -> Path:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"data")
        stamp = (datetime.now(UTC) - timedelta(hours=2)).timestamp()
        os.utime(path, (stamp, stamp))
        return path

    txt = old_file("aa/notes.txt")
    bak = old_file("bb/blob.enc.bak")
    tmp_named = old_file("cc/keep.tmp")
    deep = old_file("dd/ee/ff/blob.enc")

    report = await run_cleanup(session_factory, settings)

    assert report.stages["blobs"] == 1
    assert txt.exists() and bak.exists() and tmp_named.exists()
    assert not deep.exists()


# AC-3, AC-9, AC-10: a blob exactly at the min age boundary is collected
async def test_blob_exactly_at_min_age_is_collected(session_factory, tmp_path):
    settings = _settings(tmp_path, maintenance_blob_min_age_seconds=3600)
    path = tmp_path / "ab" / ("a" * 64 + ".enc")
    path.parent.mkdir(parents=True)
    path.write_bytes(b"ct")
    stamp = (datetime.now(UTC) - timedelta(seconds=3600)).timestamp()
    os.utime(path, (stamp, stamp))

    report = await run_cleanup(session_factory, settings)

    assert report.stages["blobs"] == 1
    assert not path.exists()


# AC-3, AC-9: a blob claimed between scan and unlink survives (review TOCTOU)
async def test_cleanup_skips_blob_referenced_mid_run(session_factory, tmp_path, monkeypatch):
    owner = await make_user(session_factory, "toctou_owner")
    doc = await _document(session_factory, owner.id)
    settings = _settings(tmp_path, maintenance_blob_min_age_seconds=3600)
    rel = "ab/" + "a" * 64 + ".enc"
    path = tmp_path / rel
    path.parent.mkdir(parents=True)
    path.write_bytes(b"ct")
    old = (datetime.now(UTC) - timedelta(hours=2)).timestamp()
    os.utime(path, (old, old))

    loop = asyncio.get_running_loop()
    committed = threading.Event()
    real_scan = maintenance._orphan_blob_paths

    def scan_then_reference(upload_dir, referenced, cutoff_ts):
        doomed = real_scan(upload_dir, referenced, cutoff_ts)

        async def insert_ref():
            try:
                async with session_factory() as session:
                    session.add(
                        DocumentVersion(
                            id=uuid.uuid4(),
                            document_id=doc.id,
                            version_number=1,
                            classification=ClassificationLevel.UNCLASSIFIED,
                            content_sha256="0" * 64,
                            blob_path=rel,
                            size_bytes=1,
                            mime_type="text/plain",
                            created_by=owner.id,
                        )
                    )
                    await session.commit()
            finally:
                committed.set()

        loop.call_soon_threadsafe(lambda: asyncio.ensure_future(insert_ref()))
        assert committed.wait(timeout=10)
        return doomed

    monkeypatch.setattr(maintenance, "_orphan_blob_paths", scan_then_reference)
    report = await run_cleanup(session_factory, settings)

    assert report.stages["blobs"] == 0
    assert path.exists()


# AC-3, AC-9: a blob whose mtime refreshes mid run (dedup claim) survives
async def test_cleanup_skips_blob_refreshed_mid_run(session_factory, tmp_path, monkeypatch):
    settings = _settings(tmp_path, maintenance_blob_min_age_seconds=3600)
    rel = "cd/" + "c" * 64 + ".enc"
    path = tmp_path / rel
    path.parent.mkdir(parents=True)
    path.write_bytes(b"ct")
    old = (datetime.now(UTC) - timedelta(hours=2)).timestamp()
    os.utime(path, (old, old))

    real_scan = maintenance._orphan_blob_paths

    def scan_then_refresh(upload_dir, referenced, cutoff_ts):
        doomed = real_scan(upload_dir, referenced, cutoff_ts)
        os.utime(path, None)
        return doomed

    monkeypatch.setattr(maintenance, "_orphan_blob_paths", scan_then_refresh)
    report = await run_cleanup(session_factory, settings)

    assert report.stages["blobs"] == 0
    assert path.exists()


# _unlink_if_stale outcome contract: True deleted, False too fresh, None gone
def test_unlink_if_stale_outcomes(tmp_path):
    cutoff = (datetime.now(UTC) - timedelta(hours=1)).timestamp()

    old = tmp_path / "old.enc"
    old.write_bytes(b"x")
    past = cutoff - 10
    os.utime(old, (past, past))
    assert maintenance._unlink_if_stale(old, cutoff) is True
    assert not old.exists()

    fresh = tmp_path / "fresh.enc"
    fresh.write_bytes(b"x")
    assert maintenance._unlink_if_stale(fresh, cutoff) is False
    assert fresh.exists()

    assert maintenance._unlink_if_stale(tmp_path / "gone.enc", cutoff) is None


# store dedup hit refreshes mtime so retention treats the blob as in use
async def test_store_dedup_hit_refreshes_mtime(tmp_path, monkeypatch):
    settings = _settings(tmp_path)
    monkeypatch.setattr(blob_store, "get_settings", lambda: settings)

    rel, _digest = await blob_store.store(b"same content")
    path = tmp_path / rel
    old = (datetime.now(UTC) - timedelta(hours=2)).timestamp()
    os.utime(path, (old, old))

    await blob_store.store(b"same content")

    assert path.stat().st_mtime > old


# AC-4: no stage ever deletes audit_log rows
async def test_audit_log_rows_survive_cleanup(session_factory, tmp_path):
    await _audit_seq(session_factory)
    await _audit_seq(session_factory)
    before = await _count(session_factory, AuditLog)

    await run_cleanup(session_factory, _settings(tmp_path))
    await run_cleanup(session_factory, _settings(tmp_path))

    after = await _count(session_factory, AuditLog)
    assert after == before + 2  # one maintenance.cleanup entry per run, none removed


# AC-6 dry run: zero writes, counts still reported, audit records dry_run
async def test_dry_run_deletes_nothing_but_reports_counts(session_factory, tmp_path):
    user = await make_user(session_factory, "dry_user")
    uid = user.id
    await _challenge(session_factory, uid, consumed_at=NOW)
    await _session_row(session_factory, uid, expires_at=NOW - timedelta(seconds=1))
    orphan = tmp_path / "ff" / ("f" * 64 + ".enc")
    orphan.parent.mkdir(parents=True)
    orphan.write_bytes(b"ciphertext")
    old = datetime.now(UTC).timestamp() - 7200
    os.utime(orphan, (old, old))

    report = await run_cleanup(session_factory, _settings(tmp_path), dry_run=True)

    assert report.dry_run is True
    assert report.stages["mfa_challenges"] == 1
    assert report.stages["sessions"] == 1
    assert report.stages["blobs"] == 1
    assert await _count(session_factory, MfaChallenge) == 1
    assert await _count(session_factory, UserSession) == 1
    assert orphan.exists()

    entries = await _cleanup_entries(session_factory)
    assert len(entries) == 1
    assert entries[0].details["dry_run"] is True
    assert entries[0].details["stages"]["blobs"] == {"deleted": 1}


# AC-5, AC-7: one failing stage does not block the others and lands in the audit entry
async def test_stage_failure_isolated_and_audited(session_factory, tmp_path, monkeypatch):
    user = await make_user(session_factory, "iso_user")
    await _challenge(session_factory, user.id, consumed_at=NOW)

    async def boom(*_args, **_kwargs):
        raise RuntimeError("stage exploded")

    monkeypatch.setattr(maintenance, "_cleanup_sessions", boom)
    report = await run_cleanup(session_factory, _settings(tmp_path))

    assert report.stages["mfa_challenges"] == 1
    assert "sessions" not in report.stages
    assert "stage exploded" in report.errors["sessions"]
    assert await _count(session_factory, MfaChallenge) == 0

    entries = await _cleanup_entries(session_factory)
    assert len(entries) == 1
    assert entries[0].details["errors"]["sessions"] == "stage exploded"
    assert entries[0].details["stages"]["mfa_challenges"] == {"deleted": 1}


# AC-5, AC-6: audit append failure propagates and the CLI exits 1
async def test_cli_exits_1_when_audit_append_fails(session_factory, tmp_path, monkeypatch):
    await make_user(session_factory, "cli_user")

    async def failing_append(*_args, **_kwargs):
        raise audit_service.AuditChainFork()

    monkeypatch.setattr(audit_service, "append_with_retry", failing_append)
    monkeypatch.setattr(cli, "SessionLocal", session_factory)
    monkeypatch.setattr(cli, "get_settings", lambda: _settings(tmp_path))

    assert await cli._cleanup(SimpleNamespace(dry_run=False)) == 1


# AC-6: CLI reports per stage counts and exits 0 even with stage errors
async def test_cli_cleanup_prints_counts_and_exits_0(
    session_factory, tmp_path, monkeypatch, capsys
):
    user = await make_user(session_factory, "cli_ok")
    await _challenge(session_factory, user.id, consumed_at=NOW)
    monkeypatch.setattr(cli, "SessionLocal", session_factory)
    monkeypatch.setattr(cli, "get_settings", lambda: _settings(tmp_path))

    assert await cli._cleanup(SimpleNamespace(dry_run=True)) == 0
    out = capsys.readouterr().out
    assert "dry run" in out
    assert "mfa_challenges: 1 would delete" in out


# AC-8: repeated and concurrent runs are safe
async def test_cleanup_is_idempotent_and_concurrency_safe(session_factory, tmp_path):
    user = await make_user(session_factory, "idem_user")
    await _challenge(session_factory, user.id, consumed_at=NOW)
    await _session_row(session_factory, user.id, expires_at=NOW - timedelta(seconds=1))
    settings = _settings(tmp_path)

    first = await run_cleanup(session_factory, settings)
    second = await run_cleanup(session_factory, settings)
    assert first.stages["mfa_challenges"] == 1
    assert second.stages["mfa_challenges"] == 0
    assert second.stages["sessions"] == 0

    user2 = await make_user(session_factory, "idem_user2")
    await _challenge(session_factory, user2.id, consumed_at=NOW)
    reports = await asyncio.gather(
        run_cleanup(session_factory, settings),
        run_cleanup(session_factory, settings),
    )
    assert sum(r.stages["mfa_challenges"] for r in reports) == 1
    assert await _count(session_factory, MfaChallenge) == 0
    assert len(await _cleanup_entries(session_factory)) == 4


# AC-6, AC-8: scheduler runs once at start, recurs, and 0 disables it
async def test_scheduler_loop_recurs_and_zero_disables(session_factory, monkeypatch):
    calls = 0

    async def fake_run(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls >= 3:
            raise asyncio.CancelledError

    monkeypatch.setattr(maintenance, "run_cleanup", fake_run)
    real_sleep = asyncio.sleep

    async def fast_sleep(_seconds):
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", fast_sleep)
    settings = _settings(maintenance_interval_seconds=1)

    with pytest.raises(asyncio.CancelledError):
        await scheduler_loop(session_factory, settings)
    assert calls == 3

    settings_zero = _settings(maintenance_interval_seconds=0)
    await scheduler_loop(session_factory, settings_zero)
    assert calls == 3


# AC-5, AC-7: the audit entry is appended even when every stage fails
async def test_audit_entry_appended_when_all_stages_fail(session_factory, tmp_path, monkeypatch):
    async def boom(*_args, **_kwargs):
        raise RuntimeError("total failure")

    for name in (
        "_cleanup_mfa_challenges",
        "_cleanup_sessions",
        "_cleanup_shares",
        "_cleanup_alerts",
        "_cleanup_blobs",
    ):
        monkeypatch.setattr(maintenance, name, boom)

    report = await run_cleanup(session_factory, _settings(tmp_path))

    assert report.stages == {}
    assert set(report.errors) == {
        "mfa_challenges",
        "sessions",
        "document_shares",
        "alerts",
        "blobs",
    }
    entries = await _cleanup_entries(session_factory)
    assert len(entries) == 1
    assert entries[0].details["errors"]["blobs"] == "total failure"


# AC-6: lifespan starts the scheduler task only when the interval is positive
async def test_lifespan_starts_and_cancels_scheduler(tmp_path, monkeypatch):
    state = {"started": False, "cancelled": False}

    async def fake_loop(_session_factory, _settings):
        state["started"] = True
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            state["cancelled"] = True
            raise

    monkeypatch.setattr(maintenance, "scheduler_loop", fake_loop)
    settings = _settings(tmp_path, maintenance_interval_seconds=3600)
    monkeypatch.setattr(main_module, "get_settings", lambda: settings)

    async with main_module.lifespan(None):
        await asyncio.sleep(0.05)
        assert state["started"] is True
    assert state["cancelled"] is True


async def test_lifespan_skips_scheduler_when_interval_zero(tmp_path, monkeypatch):
    state = {"started": False}

    async def fake_loop(_session_factory, _settings):
        state["started"] = True

    monkeypatch.setattr(maintenance, "scheduler_loop", fake_loop)
    settings = _settings(tmp_path, maintenance_interval_seconds=0)
    monkeypatch.setattr(main_module, "get_settings", lambda: settings)

    async with main_module.lifespan(None):
        await asyncio.sleep(0.05)
    assert state["started"] is False


# cli class: the cleanup subcommand parses, runs, and rejects bad flags
def test_cli_main_cleanup_dry_run_reports_counts(session_factory, tmp_path, monkeypatch, capsys):
    async def seed() -> None:
        user = await make_user(session_factory, "cli_main_user")
        await _challenge(session_factory, user.id, consumed_at=NOW)

    asyncio.run(seed())
    monkeypatch.setattr(cli, "SessionLocal", session_factory)
    monkeypatch.setattr(cli, "get_settings", lambda: _settings(tmp_path))

    assert cli.main(["cleanup", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "dry run complete" in out
    assert "mfa_challenges: 1 would delete" in out


def test_cli_main_cleanup_rejects_unknown_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "get_settings", lambda: _settings(tmp_path))
    with pytest.raises(SystemExit):
        cli.main(["cleanup", "--bogus"])
