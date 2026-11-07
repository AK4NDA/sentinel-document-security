import uuid
from datetime import datetime

from sqlalchemy import JSON, CheckConstraint, DateTime, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.common import audit_seq, created_at


class AuditLog(Base):
    """Append only hash chained audit trail.

    Actor and target are plain snapshot columns with no foreign keys so
    entries survive deletion of the users and documents they describe.
    The chain format and append serialization are owned by the slice 4
    auditor spec; this table only reserves the columns.
    """

    __tablename__ = "audit_log"
    __table_args__ = (
        CheckConstraint("outcome IN ('allowed', 'denied')", name="ck_audit_log_outcome"),
        UniqueConstraint("prev_hash", name="uq_audit_log_prev_hash"),
    )

    seq: Mapped[int] = audit_seq()
    id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    actor_username: Mapped[str | None] = mapped_column(String(64))
    actor_role: Mapped[str | None] = mapped_column(String(20))
    action: Mapped[str] = mapped_column(String(100))
    outcome: Mapped[str] = mapped_column(String(10))
    target_type: Mapped[str | None] = mapped_column(String(50))
    target_id: Mapped[str | None] = mapped_column(String(64), index=True)
    details: Mapped[dict | None] = mapped_column(JSON)
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = created_at()
