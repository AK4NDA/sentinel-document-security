"""Auditor audit log browsing and chain verification endpoints."""

import hashlib
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import AwareDatetime
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api.deps import extract_token, require_role
from app.core.config import get_settings
from app.core.database import get_db, get_session_factory
from app.models import User, UserRole
from app.schemas.audit import AuditEntry, AuditEntryPage, VerifyResult
from app.services import audit as audit_service

router = APIRouter(prefix="/v1/audit", tags=["audit"])
AUDITOR = UserRole.AUDITOR


def _verify_key(request: Request) -> str:
    """Rate limit per session (token hash only); IP fallback pre auth."""
    token = extract_token(request)
    if token is not None:
        return f"session:{hashlib.sha256(token.encode()).hexdigest()}"
    return f"ip:{get_remote_address(request)}"


audit_limiter = Limiter(key_func=_verify_key)


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


@router.post("/verify", response_model=VerifyResult)
@audit_limiter.limit(_audit_limit)
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
