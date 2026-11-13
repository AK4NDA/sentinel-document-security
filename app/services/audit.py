"""Hash chained audit log append and verification (spec 0003 AC-14, AC-15)."""

import csv
import hashlib
import io
import json
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog, User

GENESIS_PREV_HASH = "0" * 64
MAX_APPEND_ATTEMPTS = 5

_HASHED_FIELDS = (
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
)


class AuditChainFork(Exception):
    """Two writers raced for the same chain tail; the unique prev_hash fired."""


def _canonical(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _canonical(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return value


def canonical_payload(fields: dict[str, Any]) -> str:
    ordered = {key: _canonical(fields[key]) for key in _HASHED_FIELDS}
    return json.dumps(ordered, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(fields: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_payload(fields).encode("utf-8")).hexdigest()


def actor_kwargs(actor: User | None) -> dict[str, Any]:
    """Snapshot actor columns as primitives so retries survive rollbacks."""
    if actor is None:
        return {"actor_id": None, "actor_username": None, "actor_role": None}
    return {
        "actor_id": actor.id,
        "actor_username": actor.username,
        "actor_role": actor.role.value,
    }


def entry_fields(entry: AuditLog) -> dict[str, Any]:
    return {
        "occurred_at": entry.occurred_at,
        "actor_id": entry.actor_id,
        "actor_username": entry.actor_username,
        "actor_role": entry.actor_role,
        "action": entry.action,
        "outcome": entry.outcome,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "details": entry.details,
        "prev_hash": entry.prev_hash,
    }


async def _tail_hash(session: AsyncSession) -> str:
    result = await session.execute(select(AuditLog.hash).order_by(AuditLog.seq.desc()).limit(1))
    return result.scalar_one_or_none() or GENESIS_PREV_HASH


def _is_chain_fork(exc: IntegrityError) -> bool:
    orig = str(getattr(exc, "orig", exc))
    return "uq_audit_log_prev_hash" in orig or "prev_hash" in orig


async def append(
    session: AsyncSession,
    *,
    action: str,
    outcome: str,
    actor_id: uuid.UUID | None = None,
    actor_username: str | None = None,
    actor_role: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict[str, Any] | None = None,
    occurred_at: datetime | None = None,
) -> AuditLog:
    """Append one chained entry inside the caller's transaction.

    Actor columns are plain values (see actor_kwargs) so the entry can be
    rebuilt safely after a rollback. Raises AuditChainFork when the unique
    prev_hash constraint fires; the caller owns retrying the whole unit.
    """
    occurred_at = occurred_at or datetime.now(UTC)
    prev_hash = await _tail_hash(session)
    fields = {
        "occurred_at": occurred_at,
        "actor_id": actor_id,
        "actor_username": actor_username,
        "actor_role": actor_role,
        "action": action,
        "outcome": outcome,
        "target_type": target_type,
        "target_id": target_id,
        "details": details,
        "prev_hash": prev_hash,
    }
    entry = AuditLog(
        id=uuid.uuid4(),
        occurred_at=occurred_at,
        actor_id=actor_id,
        actor_username=actor_username,
        actor_role=actor_role,
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=target_id,
        details=details,
        prev_hash=prev_hash,
        hash=compute_hash(fields),
    )
    session.add(entry)
    try:
        await session.flush()
    except IntegrityError as exc:
        if _is_chain_fork(exc):
            raise AuditChainFork() from exc
        raise
    # Lazy import: alerts calls back into append for alert.raise entries.
    from app.services import alerts as alerts_service

    await alerts_service.maybe_raise(session, entry)
    return entry


async def transact(db: AsyncSession, op):
    """Run op(db) plus commit, retrying the whole unit on a chain fork."""
    for _ in range(MAX_APPEND_ATTEMPTS):
        try:
            result = await op(db)
            await db.commit()
            return result
        except AuditChainFork:
            await db.rollback()
    raise AuditChainFork()


async def record_denial(
    db: AsyncSession,
    *,
    action: str,
    reason: str,
    actor: User | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Commit an audited denial independently of any business write."""
    snapshot = actor_kwargs(actor)
    await db.rollback()
    payload = {"reason": reason, **(details or {})}
    for _ in range(MAX_APPEND_ATTEMPTS):
        try:
            await append(
                db,
                action=action,
                outcome="denied",
                target_type=target_type,
                target_id=target_id,
                details=payload,
                **snapshot,
            )
            await db.commit()
            return
        except AuditChainFork:
            await db.rollback()
    raise AuditChainFork()


async def append_with_retry(
    session_factory,
    *,
    action: str,
    outcome: str,
    actor_id: uuid.UUID | None = None,
    actor_username: str | None = None,
    actor_role: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Append in its own transaction, retrying the whole unit on a fork."""
    occurred_at = datetime.now(UTC)
    last_exc: Exception | None = None
    for _ in range(MAX_APPEND_ATTEMPTS):
        async with session_factory() as session:
            try:
                entry = await append(
                    session,
                    action=action,
                    outcome=outcome,
                    actor_id=actor_id,
                    actor_username=actor_username,
                    actor_role=actor_role,
                    target_type=target_type,
                    target_id=target_id,
                    details=details,
                    occurred_at=occurred_at,
                )
                await session.commit()
                return entry
            except AuditChainFork as exc:
                last_exc = exc
                await session.rollback()
    raise AuditChainFork() from last_exc


async def _chain_rows(session: AsyncSession) -> list[AuditLog]:
    return list((await session.execute(select(AuditLog).order_by(AuditLog.seq))).scalars().all())


def _scan_chain(rows: list[AuditLog]) -> tuple[list[int], int]:
    """Single pass over ordered rows: bad seqs plus rows examined."""
    bad: list[int] = []
    expected_prev = GENESIS_PREV_HASH
    for row in rows:
        fields = entry_fields(row)
        if row.prev_hash != expected_prev or compute_hash(fields) != row.hash:
            bad.append(row.seq)
        expected_prev = row.hash
    return bad, len(rows)


async def verify_chain(session: AsyncSession) -> list[int]:
    """Return the seq numbers whose stored hash does not recompute."""
    bad, _ = _scan_chain(await _chain_rows(session))
    return bad


@dataclass
class VerifySummary:
    valid: bool
    checked_count: int
    head_hash: str | None
    bad_seq_numbers: list[int]


async def verify_summary(session: AsyncSession) -> VerifySummary:
    """Full chain recompute plus head hash from one ordered scan.

    head_hash and bad_seq_numbers describe the snapshot read here, before any
    audit row this call may append afterwards.
    """
    rows = await _chain_rows(session)
    bad, checked = _scan_chain(rows)
    return VerifySummary(
        valid=not bad,
        checked_count=checked,
        head_hash=rows[-1].hash if rows else None,
        bad_seq_numbers=bad,
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _apply_filters(
    stmt,
    *,
    actor_username: str | None = None,
    action: str | None = None,
    outcome: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    occurred_after: datetime | None = None,
    occurred_before: datetime | None = None,
):
    """Shared where clauses for entries listing and export (spec 0013)."""
    if actor_username is not None:
        stmt = stmt.where(AuditLog.actor_username == actor_username)
    if action is not None:
        stmt = stmt.where(AuditLog.action == action)
    if outcome is not None:
        stmt = stmt.where(AuditLog.outcome == outcome)
    if target_type is not None:
        stmt = stmt.where(AuditLog.target_type == target_type)
    if target_id is not None:
        stmt = stmt.where(AuditLog.target_id == target_id)
    if occurred_after is not None:
        stmt = stmt.where(AuditLog.occurred_at >= _as_utc(occurred_after))
    if occurred_before is not None:
        stmt = stmt.where(AuditLog.occurred_at <= _as_utc(occurred_before))
    return stmt


async def list_entries(
    session: AsyncSession,
    *,
    cursor: int | None = None,
    limit: int = 50,
    actor_username: str | None = None,
    action: str | None = None,
    outcome: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    occurred_after: datetime | None = None,
    occurred_before: datetime | None = None,
) -> tuple[list[AuditLog], int | None]:
    """Newest first page of audit entries; next_cursor is the last row's seq."""
    stmt = _apply_filters(
        select(AuditLog),
        actor_username=actor_username,
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=target_id,
        occurred_after=occurred_after,
        occurred_before=occurred_before,
    )
    if cursor is not None:
        stmt = stmt.where(AuditLog.seq < cursor)
    stmt = stmt.order_by(AuditLog.seq.desc()).limit(limit)
    rows = list((await session.execute(stmt)).scalars().all())
    next_cursor = rows[-1].seq if len(rows) == limit else None
    return rows, next_cursor


EXPORT_COLUMNS = (
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
)

_EXPORT_DANGEROUS = ("=", "+", "-", "@", "\t", "\r")


async def export_head(session: AsyncSession) -> tuple[int | None, str | None]:
    """Chain head (seq, hash) for the export snapshot; (None, None) when empty."""
    result = await session.execute(
        select(AuditLog.seq, AuditLog.hash).order_by(AuditLog.seq.desc()).limit(1)
    )
    row = result.first()
    return (row.seq, row.hash) if row is not None else (None, None)


async def export_count(
    session: AsyncSession,
    *,
    head_seq: int | None,
    actor_username: str | None = None,
    action: str | None = None,
    outcome: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    occurred_after: datetime | None = None,
    occurred_before: datetime | None = None,
) -> int:
    """Matching rows inside the snapshot bound; decides truncation up front."""
    stmt = _apply_filters(
        select(func.count()).select_from(AuditLog),
        actor_username=actor_username,
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=target_id,
        occurred_after=occurred_after,
        occurred_before=occurred_before,
    )
    if head_seq is not None:
        stmt = stmt.where(AuditLog.seq <= head_seq)
    return (await session.execute(stmt)).scalar_one()


async def export_rows(
    session: AsyncSession,
    *,
    head_seq: int | None,
    max_rows: int,
    actor_username: str | None = None,
    action: str | None = None,
    outcome: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    occurred_after: datetime | None = None,
    occurred_before: datetime | None = None,
) -> AsyncIterator[AuditLog]:
    """Stream matching rows oldest first inside the snapshot, capped at max_rows."""
    stmt = _apply_filters(
        select(AuditLog),
        actor_username=actor_username,
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=target_id,
        occurred_after=occurred_after,
        occurred_before=occurred_before,
    )
    if head_seq is not None:
        stmt = stmt.where(AuditLog.seq <= head_seq)
    stmt = stmt.order_by(AuditLog.seq.asc()).limit(max_rows).execution_options(yield_per=500)
    result = await session.stream(stmt)
    try:
        async for partition in result.partitions():
            for row in partition:
                yield row[0]
    finally:
        await result.close()


def _export_values(row: AuditLog) -> dict[str, Any]:
    """Logical export row: canonical scalars, details kept as a JSON object."""
    return {
        "seq": row.seq,
        "id": str(row.id),
        "occurred_at": _canonical(row.occurred_at),
        "actor_id": str(row.actor_id) if row.actor_id is not None else None,
        "actor_username": row.actor_username,
        "actor_role": row.actor_role,
        "action": row.action,
        "outcome": row.outcome,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "details": row.details,
        "prev_hash": row.prev_hash,
        "hash": row.hash,
    }


def _csv_safe(text: str) -> str:
    """Prefix cells that could execute as spreadsheet formulas (spec 0013 AC-8)."""
    if text[:1] in _EXPORT_DANGEROUS or text.lstrip()[:1] in _EXPORT_DANGEROUS:
        return "'" + text
    return text


def _csv_record(cells: list[str]) -> str:
    buf = io.StringIO()
    csv.writer(buf, lineterminator="\n").writerow(cells)
    return buf.getvalue()


def export_csv_header() -> str:
    return _csv_record([_csv_safe(col) for col in EXPORT_COLUMNS])


def export_csv_row(row: AuditLog) -> str:
    values = _export_values(row)
    cells = []
    for col in EXPORT_COLUMNS:
        val = values[col]
        if val is None:
            text = ""
        elif col == "details":
            text = json.dumps(val, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        else:
            text = str(val)
        cells.append(_csv_safe(text))
    return _csv_record(cells)


def export_jsonl_row(row: AuditLog) -> str:
    return json.dumps(_export_values(row), ensure_ascii=False, separators=(",", ":")) + "\n"
