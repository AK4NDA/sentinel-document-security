"""Retention cleanup job: dead rows, old shares and alerts, orphan blobs (spec 0012)."""

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog
from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.models import (
    Alert,
    DocumentShare,
    DocumentVersion,
    MfaChallenge,
)
from app.models import Session as UserSession
from app.services import audit
from app.services.mfa import CHALLENGE_MAX_ATTEMPTS

logger = structlog.get_logger(__name__)

CLEANUP_ACTION = "maintenance.cleanup"

StageFn = Callable[[async_sessionmaker[AsyncSession], Settings, datetime, bool], Awaitable[int]]


@dataclass
class CleanupReport:
    dry_run: bool
    stages: dict[str, int] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    def audit_details(self) -> dict[str, Any]:
        return {
            "dry_run": self.dry_run,
            "stages": {name: {"deleted": count} for name, count in self.stages.items()},
            "errors": self.errors,
        }


async def _delete_matching(
    session_factory: async_sessionmaker[AsyncSession],
    model: Any,
    where: Any,
    dry_run: bool,
) -> int:
    """Count (dry run) or delete rows matching where; commits on delete."""
    async with session_factory() as session:
        if dry_run:
            stmt = select(func.count()).select_from(model).where(where)
            return (await session.execute(stmt)).scalar_one()
        result = await session.execute(delete(model).where(where))
        await session.commit()
        return result.rowcount or 0


async def _cleanup_mfa_challenges(
    session_factory: async_sessionmaker[AsyncSession],
    _settings: Settings,
    now: datetime,
    dry_run: bool,
) -> int:
    where = or_(
        MfaChallenge.consumed_at.is_not(None),
        MfaChallenge.expires_at <= now,
        MfaChallenge.attempts >= CHALLENGE_MAX_ATTEMPTS,
    )
    return await _delete_matching(session_factory, MfaChallenge, where, dry_run)


async def _cleanup_sessions(
    session_factory: async_sessionmaker[AsyncSession],
    _settings: Settings,
    now: datetime,
    dry_run: bool,
) -> int:
    where = or_(UserSession.expires_at <= now, UserSession.revoked_at.is_not(None))
    return await _delete_matching(session_factory, UserSession, where, dry_run)


async def _cleanup_shares(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    now: datetime,
    dry_run: bool,
) -> int:
    cutoff = now - timedelta(days=settings.maintenance_share_alert_retention_days)
    where = DocumentShare.revoked_at.is_not(None) & (DocumentShare.revoked_at <= cutoff)
    return await _delete_matching(session_factory, DocumentShare, where, dry_run)


async def _cleanup_alerts(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    now: datetime,
    dry_run: bool,
) -> int:
    cutoff = now - timedelta(days=settings.maintenance_share_alert_retention_days)
    where = (
        (Alert.state == "acknowledged")
        & Alert.acknowledged_at.is_not(None)
        & (Alert.acknowledged_at <= cutoff)
    )
    return await _delete_matching(session_factory, Alert, where, dry_run)


def _orphan_blob_paths(upload_dir: Path, referenced: set[str], cutoff_ts: float) -> list[Path]:
    """Unreferenced *.enc / *.enc.tmp files at or beyond the min age."""
    if not upload_dir.is_dir():
        return []
    doomed: list[Path] = []
    for pattern in ("*.enc", "*.enc.tmp"):
        for path in upload_dir.rglob(pattern):
            if not path.is_file():
                continue
            if path.relative_to(upload_dir).as_posix() in referenced:
                continue
            try:
                if path.stat().st_mtime <= cutoff_ts:
                    doomed.append(path)
            except OSError:
                continue
    return doomed


async def _blob_still_referenced(session: AsyncSession, blob_path: str) -> bool:
    stmt = select(DocumentVersion.id).where(DocumentVersion.blob_path == blob_path).limit(1)
    return (await session.execute(stmt)).scalar_one_or_none() is not None


def _unlink_if_stale(path: Path, cutoff_ts: float) -> bool | None:
    """Unlink path if still older than cutoff.

    Returns True when this call deleted the file, False when it is too fresh,
    None when it was already gone. Runs in a worker thread.
    """
    try:
        if path.stat().st_mtime > cutoff_ts:
            return False
    except FileNotFoundError:
        return None
    try:
        path.unlink()
    except FileNotFoundError:
        return None
    return True


async def _cleanup_blobs(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    now: datetime,
    dry_run: bool,
) -> int:
    upload_dir = Path(settings.upload_dir)
    cutoff_ts = now.timestamp() - settings.maintenance_blob_min_age_seconds
    async with session_factory() as session:
        referenced = set(
            (await session.execute(select(DocumentVersion.blob_path).distinct())).scalars().all()
        )
    doomed = await asyncio.to_thread(_orphan_blob_paths, upload_dir, referenced, cutoff_ts)
    if dry_run:
        return len(doomed)
    deleted = 0
    for path in doomed:
        rel = path.relative_to(upload_dir).as_posix()
        async with session_factory() as session:
            if await _blob_still_referenced(session, rel):
                continue
        try:
            removed = await asyncio.to_thread(_unlink_if_stale, path, cutoff_ts)
        except OSError as exc:
            logger.warning("maintenance blob unlink failed", path=str(path), error=str(exc))
            continue
        if removed:
            deleted += 1
    return deleted


def _stages() -> list[tuple[str, StageFn]]:
    return [
        ("mfa_challenges", _cleanup_mfa_challenges),
        ("sessions", _cleanup_sessions),
        ("document_shares", _cleanup_shares),
        ("alerts", _cleanup_alerts),
        ("blobs", _cleanup_blobs),
    ]


_cleanup_lock = asyncio.Lock()


async def run_cleanup(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    *,
    dry_run: bool = False,
) -> CleanupReport:
    """Run every retention stage, then append one maintenance.cleanup audit entry.

    Stage failures are captured into the report and never abort the run; the
    audit append runs last via append_with_retry and may raise AuditChainFork.
    """
    async with _cleanup_lock:
        report = CleanupReport(dry_run=dry_run)
        now = datetime.now(UTC)
        for name, stage in _stages():
            try:
                report.stages[name] = await stage(session_factory, settings, now, dry_run)
            except Exception as exc:
                logger.error("maintenance stage failed", stage=name, error=str(exc))
                report.errors[name] = str(exc)
        await audit.append_with_retry(
            session_factory,
            action=CLEANUP_ACTION,
            outcome="allowed",
            actor_username="system",
            target_type="maintenance",
            details=report.audit_details(),
        )
        return report


async def scheduler_loop(
    session_factory: async_sessionmaker[AsyncSession], settings: Settings
) -> None:
    """Run cleanup once, then every maintenance_interval_seconds; never raises."""
    if settings.maintenance_interval_seconds <= 0:
        return
    while True:
        try:
            await run_cleanup(session_factory, settings)
        except Exception:
            logger.exception("maintenance cleanup run failed")
        await asyncio.sleep(settings.maintenance_interval_seconds)
