import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.common import created_at, uuid_pk

if TYPE_CHECKING:
    from app.models.document import Document
    from app.models.user import User


class DocumentShare(Base):
    __tablename__ = "document_shares"
    __table_args__ = (
        UniqueConstraint("document_id", "user_id", name="uq_document_shares_document_user"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    document_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    granted_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    access_level: Mapped[str] = mapped_column(String(20), default="read")
    created_at: Mapped[datetime] = created_at()
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT")
    )

    document: Mapped["Document"] = relationship(back_populates="shares", lazy="raise")
    grantee: Mapped["User"] = relationship(foreign_keys="DocumentShare.user_id", lazy="raise")
    granter: Mapped["User"] = relationship(foreign_keys="DocumentShare.granted_by", lazy="raise")
    revoker: Mapped["User | None"] = relationship(
        foreign_keys="DocumentShare.revoked_by", lazy="raise"
    )
