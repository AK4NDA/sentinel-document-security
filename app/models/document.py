import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.common import created_at, updated_at, uuid_pk

if TYPE_CHECKING:
    from app.models.document_share import DocumentShare
    from app.models.document_version import DocumentVersion
    from app.models.user import User


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[uuid.UUID] = uuid_pk()
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str | None] = mapped_column(Text)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    current_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey(
            "document_versions.id",
            ondelete="SET NULL",
            name="fk_documents_current_version_id",
        ),
        index=True,
    )
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    owner: Mapped["User"] = relationship(
        back_populates="owned_documents",
        foreign_keys="Document.owner_id",
        lazy="raise",
    )
    versions: Mapped[list["DocumentVersion"]] = relationship(
        back_populates="document",
        foreign_keys="DocumentVersion.document_id",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="raise",
    )
    current_version: Mapped["DocumentVersion | None"] = relationship(
        foreign_keys="Document.current_version_id", lazy="raise"
    )
    shares: Mapped[list["DocumentShare"]] = relationship(
        back_populates="document",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="raise",
    )
