"""Alert feed endpoints for admins and auditors (spec 0010)."""

import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import AwareDatetime
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_role
from app.core.database import get_db
from app.models import User, UserRole
from app.schemas.alerts import AlertOut, AlertPage
from app.services import alerts as alerts_service

router = APIRouter(prefix="/v1/alerts", tags=["alerts"])

AlertState = Literal["open", "acknowledged"]
AlertType = Literal["denied_access", "sensitive_read", "privilege_change", "chain_tamper"]
ALERT_ROLES = (UserRole.ADMIN, UserRole.AUDITOR)


@router.get("", response_model=AlertPage)
async def list_alerts(
    state: AlertState | None = None,
    alert_type: AlertType | None = None,
    actor_username: str | None = None,
    created_after: AwareDatetime | None = None,
    created_before: AwareDatetime | None = None,
    cursor: Annotated[int | None, Query(ge=1)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("alert.list", *ALERT_ROLES)),
):
    rows, next_cursor = await alerts_service.list_alerts(
        db,
        actor,
        cursor=cursor,
        limit=limit,
        state=state,
        alert_type=alert_type,
        actor_username=actor_username,
        created_after=created_after,
        created_before=created_before,
    )
    return AlertPage(
        items=[AlertOut.model_validate(row) for row in rows],
        next_cursor=next_cursor,
    )


@router.post("/{alert_id}/acknowledge", response_model=AlertOut)
async def acknowledge_alert(
    alert_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    actor: User = Depends(require_role("alert.acknowledge", *ALERT_ROLES)),
):
    alert = await alerts_service.acknowledge(db, actor, alert_id)
    return AlertOut.model_validate(alert)
