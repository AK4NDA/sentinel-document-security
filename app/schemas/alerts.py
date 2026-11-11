import uuid
from datetime import datetime

from pydantic import BaseModel, JsonValue


class AlertOut(BaseModel):
    id: uuid.UUID
    alert_type: str
    state: str
    actor_id: uuid.UUID | None
    actor_username: str | None
    summary: JsonValue
    audit_seq: int
    acknowledged_by_id: uuid.UUID | None
    acknowledged_by_username: str | None
    acknowledged_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertPage(BaseModel):
    items: list[AlertOut]
    next_cursor: int | None
