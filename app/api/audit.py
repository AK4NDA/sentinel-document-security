"""Auditor audit log browsing, export, and chain verification endpoints."""

import hashlib
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from pydantic import AwareDatetime
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.auth import limiter
from app.api.deps import extract_token, require_role
from app.core.config import get_settings
from app.core.database import get_db, get_session_factory
from app.models import User, UserRole
from app.schemas.audit import AuditEntry, AuditEntryPage, VerifyResult
from app.services import audit as audit_service

router = APIRouter(prefix="/v1/audit", tags=["audit"])
AUDITOR = UserRole.AUDITOR


def _session_key(request: Request) -> str:
    """Rate limit per session (token hash only); IP fallback pre auth."""
    token = extract_token(request)
    if token is not None:
        return f"session:{hashlib.sha256(token.encode()).hexdigest()}"
    return f"ip:{get_remote_address(request)}"


def _audit_limit():
    settings = get_settings()
    return settings.rate_limit_audit if settings.rate_limit_enabled else "1000000/minute"


@router.get("/entries", response_model=AuditEntryPage)
async def list_entries(
    cursor: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    actor_username: str | None = None,
    action: str | None = None,
    outcome: Literal["allowed", "denied"] | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    occurred_after: AwareDatetime | None = None,
    occurred_before: AwareDatetime | None = None,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("audit.entries_list", AUDITOR)),
):
    rows, next_cursor = await audit_service.list_entries(
        db,
        cursor=cursor,
        limit=limit,
        actor_username=actor_username,
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=target_id,
        occurred_after=occurred_after,
        occurred_before=occurred_before,
    )
    return AuditEntryPage(
        entries=[AuditEntry.model_validate(row) for row in rows],
        next_cursor=next_cursor,
    )


@router.get("/export")
@limiter.limit(_audit_limit, key_func=_session_key)
async def export_entries(
    request: Request,
    format: Literal["csv", "json"],
    actor_username: str | None = None,
    action: str | None = None,
    outcome: Literal["allowed", "denied"] | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    occurred_after: AwareDatetime | None = None,
    occurred_before: AwareDatetime | None = None,
    db: AsyncSession = Depends(get_db),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
    actor: User = Depends(require_role("audit.export", AUDITOR)),
):
    """Stream a filtered audit slice as CSV or JSONL (spec 0013)."""
    if (
        occurred_after is not None
        and occurred_before is not None
        and occurred_after > occurred_before
    ):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "occurred_after must not be later than occurred_before",
        )
    settings = get_settings()
    filters = {
        "actor_username": actor_username,
        "action": action,
        "outcome": outcome,
        "target_type": target_type,
        "target_id": target_id,
        "occurred_after": occurred_after,
        "occurred_before": occurred_before,
    }
    head_seq, head_hash = await audit_service.export_head(db)
    total = await audit_service.export_count(db, head_seq=head_seq, **filters)
    truncated = total > settings.export_max_rows

    is_csv = format == "csv"
    ext = "csv" if is_csv else "jsonl"
    media_type = "text/csv" if is_csv else "application/x-ndjson"
    filename = f"audit-export-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.{ext}"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    if truncated:
        headers["X-Export-Truncated"] = "true"

    rows_sent = 0

    async def body():
        nonlocal rows_sent
        try:
            if is_csv:
                yield audit_service.export_csv_header()
            async for row in audit_service.export_rows(
                db,
                head_seq=head_seq,
                max_rows=settings.export_max_rows,
                **filters,
            ):
                yield (
                    audit_service.export_csv_row(row)
                    if is_csv
                    else audit_service.export_jsonl_row(row)
                )
                rows_sent += 1
        finally:
            echo = {
                key: val.isoformat() if isinstance(val, datetime) else val
                for key, val in filters.items()
                if val is not None
            }
            await audit_service.append_with_retry(
                session_factory,
                action="audit.export",
                outcome="allowed",
                actor_id=actor.id,
                actor_username=actor.username,
                actor_role=actor.role.value,
                target_type="audit_log",
                details={
                    "filters": echo,
                    "format": format,
                    "rows_exported": rows_sent,
                    "truncated": truncated,
                    "head_seq": head_seq,
                    "head_hash": head_hash,
                },
            )

    return StreamingResponse(body(), media_type=media_type, headers=headers)


@router.post("/verify", response_model=VerifyResult)
@limiter.limit(_audit_limit, key_func=_session_key)
async def verify_chain(
    request: Request,
    db: AsyncSession = Depends(get_db),
    session_factory: async_sessionmaker[AsyncSession] = Depends(get_session_factory),
    actor: User = Depends(require_role("audit.verify", AUDITOR)),
):
    summary = await audit_service.verify_summary(db)
    await audit_service.append_with_retry(
        session_factory,
        action="audit.verify",
        outcome="allowed",
        actor_id=actor.id,
        actor_username=actor.username,
        actor_role=actor.role.value,
        target_type="audit_log",
        details={
            "valid": summary.valid,
            "checked_count": summary.checked_count,
            "bad_count": len(summary.bad_seq_numbers),
        },
    )
    return VerifyResult(
        valid=summary.valid,
        checked_count=summary.checked_count,
        head_hash=summary.head_hash,
        bad_seq_numbers=summary.bad_seq_numbers,
    )
