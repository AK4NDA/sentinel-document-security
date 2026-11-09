import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.common import created_at, uuid_pk
from app.models.enums import ClassificationLevel

if TYPE_CHECKING:
    from app.models.document import Document
    from app.models.user import User


class DocumentVersion(Base):
    __tablename__ = "document_versions"
    __table_args__ = (
        UniqueConstraint("document_id", "version_number", name="uq_document_versions_number"),
        CheckConstraint(
            "classification BETWEEN 1 AND 5", name="ck_document_versions_classification_range"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    document_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), index=True
    )
    version_number: Mapped[int] = mapped_column(Integer)
    classification: Mapped[ClassificationLevel] = mapped_column(Integer)
    content_sha256: Mapped[str] = mapped_column(String(64))
    blob_path: Mapped[str] = mapped_column(String(1024))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    mime_type: Mapped[str] = mapped_column(String(128))
    key_id: Mapped[str | None] = mapped_column(String(64))
    key_version: Mapped[str | None] = mapped_column(String(64))
    search_text: Mapped[bytes | None] = mapped_column(LargeBinary)
    created_by: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    created_at: Mapped[datetime] = created_at()

    document: Mapped["Document"] = relationship(
        back_populates="versions",
        foreign_keys="DocumentVersion.document_id",
        lazy="raise",
    )
    created_by_user: Mapped["User"] = relationship(back_populates="document_versions", lazy="raise")
