import uuid
from datetime import datetime

from pydantic import BaseModel, JsonValue


class AuditEntry(BaseModel):
    seq: int
    id: uuid.UUID
    occurred_at: datetime
    actor_id: uuid.UUID | None
    actor_username: str | None
    actor_role: str | None
    action: str
    outcome: str
    target_type: str | None
    target_id: str | None
    details: JsonValue
    prev_hash: str | None
    hash: str

    model_config = {"from_attributes": True}


class AuditEntryPage(BaseModel):
    entries: list[AuditEntry]
    next_cursor: int | None


class VerifyResult(BaseModel):
    valid: bool
    checked_count: int
    head_hash: str | None
    bad_seq_numbers: list[int]
