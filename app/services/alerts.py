"""Alert classifier hooked into audit.append plus alert feed queries (spec 0010)."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import Alert, AuditLog, ClassificationLevel, Document, DocumentVersion, User
from app.services import audit

RAISE_ACTION = "alert.raise"
LIST_ACTION = "alert.list"
ACK_ACTION = "alert.acknowledge"

_SENSITIVE_ACTIONS = frozenset({"document.download", "document.version_download"})
_PRIVILEGE_ACTIONS = frozenset(
    {
        "user.privilege_update",
        "user.disabled",
        "user.enabled",
        "user.password_reset",
        "mfa.reset",
        "session.revoke_all",
    }
)
# Policy surfaces that produce denied_access alerts; auth.* stays out (lockout
# story), audit.* is not a document policy surface, alert.* never recurses.
_DENIED_PREFIXES = ("document.", "user.", "session.")
_DENIED_ACTIONS = frozenset({"mfa.reset"})


async def maybe_raise(session: AsyncSession, entry: AuditLog) -> None:
    """Insert an alert row plus its alert.raise audit entry for one audit row.

    Runs inside the caller's transaction right after the triggering entry
    flushed, so alert, alert.raise, and the trigger commit or roll back
    together (AC-11). Replays safely on AuditChainFork retries.
    """
    if entry.action.startswith("alert."):
        return
    alert_type = await _classify(session, entry)
    if alert_type is None:
        return
    if await _hourly_capped(session, entry.actor_id, alert_type):
        return
    alert = Alert(
        alert_type=alert_type,
        state="open",
        actor_id=entry.actor_id,
        actor_username=entry.actor_username,
        summary=_summary(entry),
        audit_seq=entry.seq,
    )
    session.add(alert)
    await session.flush()
    await audit.append(
        session,
        action=RAISE_ACTION,
        outcome="allowed",
        actor_id=entry.actor_id,
        actor_username=entry.actor_username,
        actor_role=entry.actor_role,
        target_type="alert",
        target_id=str(alert.id),
        details={
            "alert_type": alert_type,
            "trigger_action": entry.action,
            "trigger_seq": entry.seq,
        },
    )


async def _classify(session: AsyncSession, entry: AuditLog) -> str | None:
    action = entry.action
    if action == "audit.verify":
        details = entry.details if isinstance(entry.details, dict) else {}
        if details.get("valid") is False:
            return "chain_tamper"
        return None
    if action in _SENSITIVE_ACTIONS and entry.outcome == "allowed":
        if await _reads_top_secret(session, entry):
            return "sensitive_read"
        return None
    if entry.outcome == "allowed" and action in _PRIVILEGE_ACTIONS:
        return "privilege_change"
    if entry.outcome == "denied" and (
        action in _DENIED_ACTIONS or action.startswith(_DENIED_PREFIXES)
    ):
        return "denied_access"
    return None


async def _reads_top_secret(session: AsyncSession, entry: AuditLog) -> bool:
    """True when the downloaded content's own classification is Top Secret."""
    if entry.target_type != "document" or not entry.target_id:
        return False
    try:
        doc_id = uuid.UUID(str(entry.target_id))
    except ValueError:
        return False
    if entry.action == "document.version_download":
        details = entry.details if isinstance(entry.details, dict) else {}
        version_number = details.get("version_number")
        if version_number is None:
            return False
        stmt = select(DocumentVersion.classification).where(
            DocumentVersion.document_id == doc_id,
            DocumentVersion.version_number == version_number,
        )
    else:
        stmt = (
            select(DocumentVersion.classification)
            .join(Document, Document.current_version_id == DocumentVersion.id)
            .where(Document.id == doc_id)
        )
    classification = (await session.execute(stmt)).scalar_one_or_none()
    return classification == ClassificationLevel.TOP_SECRET


async def _hourly_capped(
    session: AsyncSession, actor_id: uuid.UUID | None, alert_type: str
) -> bool:
    """Best effort cap: ALERT_HOURLY_CAP rows per actor per type per hour."""
    since = datetime.now(UTC) - timedelta(hours=1)
    stmt = (
        select(func.count())
        .select_from(Alert)
        .where(
            Alert.alert_type == alert_type,
            Alert.created_at > since,
        )
    )
    if actor_id is None:
        stmt = stmt.where(Alert.actor_id.is_(None))
    else:
        stmt = stmt.where(Alert.actor_id == actor_id)
    count = (await session.execute(stmt)).scalar_one()
    return count >= get_settings().alert_hourly_cap


def _summary(entry: AuditLog) -> dict[str, Any]:
    details = entry.details if isinstance(entry.details, dict) else {}
    summary: dict[str, Any] = {
        "action": entry.action,
        "outcome": entry.outcome,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
    }
    if "reason" in details:
        summary["reason"] = details["reason"]
    elif details:
        summary["details"] = details
    return summary


async def list_alerts(
    db: AsyncSession,
    actor: User,
    *,
    cursor: int | None,
    limit: int,
    state: str | None,
    alert_type: str | None,
    actor_username: str | None,
    created_after: datetime | None,
    created_before: datetime | None,
) -> tuple[list[Alert], int | None]:
    """Newest first page of alerts; appends the alert.list audit entry."""
    snapshot = audit.actor_kwargs(actor)

    async def attempt(session: AsyncSession) -> tuple[list[Alert], int | None]:
        stmt = select(Alert)
        if state is not None:
            stmt = stmt.where(Alert.state == state)
        if alert_type is not None:
            stmt = stmt.where(Alert.alert_type == alert_type)
        if actor_username is not None:
            stmt = stmt.where(Alert.actor_username == actor_username)
        if created_after is not None:
            stmt = stmt.where(Alert.created_at >= created_after)
        if created_before is not None:
            stmt = stmt.where(Alert.created_at <= created_before)
        if cursor is not None:
            stmt = stmt.where(Alert.audit_seq < cursor)
        stmt = stmt.order_by(Alert.audit_seq.desc()).limit(limit)
        rows = list((await session.execute(stmt)).scalars().all())
        next_cursor = rows[-1].audit_seq if len(rows) == limit else None
        await audit.append(
            session,
            action=LIST_ACTION,
            outcome="allowed",
            target_type="alert",
            **snapshot,
        )
        return rows, next_cursor

    try:
        return await audit.transact(db, attempt)
    except audit.AuditChainFork:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR) from None


async def _append_denial(
    session: AsyncSession,
    snapshot: dict,
    alert_id: uuid.UUID,
    reason: str,
) -> None:
    await audit.append(
        session,
        action=ACK_ACTION,
        outcome="denied",
        target_type="alert",
        target_id=str(alert_id),
        details={"reason": reason},
        **snapshot,
    )


async def acknowledge(db: AsyncSession, actor: User, alert_id: uuid.UUID) -> Alert:
    """Move an open alert to acknowledged; one way, self ack is denied."""
    snapshot = audit.actor_kwargs(actor)
    actor_id = actor.id

    async def attempt(session: AsyncSession) -> tuple[str, Alert | None]:
        alert = await session.get(Alert, alert_id)
        if alert is None:
            await _append_denial(session, snapshot, alert_id, "not_found")
            return "not_found", None
        if alert.actor_id == actor_id:
            await _append_denial(session, snapshot, alert_id, "self_acknowledge")
            return "self_acknowledge", None
        result = await session.execute(
            update(Alert)
            .where(Alert.id == alert_id, Alert.state == "open")
            .values(
                state="acknowledged",
                acknowledged_by_id=actor_id,
                acknowledged_by_username=actor.username,
                acknowledged_at=datetime.now(UTC),
            )
            .execution_options(synchronize_session=False)
        )
        if result.rowcount == 0:
            await _append_denial(session, snapshot, alert_id, "already_acknowledged")
            return "already_acknowledged", None
        await session.refresh(alert)
        await audit.append(
            session,
            action=ACK_ACTION,
            outcome="allowed",
            target_type="alert",
            target_id=str(alert_id),
            details={"alert_type": alert.alert_type},
            **snapshot,
        )
        return "ok", alert

    try:
        kind, alert = await audit.transact(db, attempt)
    except audit.AuditChainFork:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR) from None

    if kind == "not_found":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
    if kind == "self_acknowledge":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "cannot acknowledge own alert")
    if kind == "already_acknowledged":
        raise HTTPException(status.HTTP_409_CONFLICT, "alert already acknowledged")
    assert alert is not None
    return alert
