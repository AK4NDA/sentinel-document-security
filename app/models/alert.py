import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.models.common import created_at, uuid_pk


class Alert(Base):
    """Operator alert raised from an audit log entry (spec 0010).

    Actor fields are snapshots like audit_log's; audit_seq points at the
    triggering entry and is unique so it doubles as the list cursor.
    """

    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint(
            "alert_type IN ('denied_access', 'sensitive_read', 'privilege_change', 'chain_tamper')",
            name="ck_alerts_alert_type",
        ),
        CheckConstraint("state IN ('open', 'acknowledged')", name="ck_alerts_state"),
        Index("ix_alerts_state_audit_seq", "state", "audit_seq"),
        Index("ix_alerts_actor_type_created", "actor_id", "alert_type", "created_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    alert_type: Mapped[str] = mapped_column(String(30))
    state: Mapped[str] = mapped_column(String(20), default="open")
    actor_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    actor_username: Mapped[str | None] = mapped_column(String(64))
    summary: Mapped[dict[str, Any]] = mapped_column(JSON)
    audit_seq: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        ForeignKey("audit_log.seq"),
        unique=True,
    )
    acknowledged_by_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    acknowledged_by_username: Mapped[str | None] = mapped_column(String(64))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at()
