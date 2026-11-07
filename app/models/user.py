import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, DateTime, Enum, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base
from app.models.common import created_at, updated_at, uuid_pk
from app.models.enums import ClassificationLevel, UserRole

if TYPE_CHECKING:
    from app.models.document import Document
    from app.models.document_share import DocumentShare
    from app.models.document_version import DocumentVersion
    from app.models.session import Session


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("clearance BETWEEN 1 AND 5", name="ck_users_clearance_range"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    username: Mapped[str] = mapped_column(String(64), unique=True)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    display_name: Mapped[str | None] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(
        Enum(
            UserRole,
            native_enum=False,
            create_constraint=True,
            length=20,
            values_callable=lambda enum: [member.value for member in enum],
        ),
        default=UserRole.USER,
    )
    clearance: Mapped[ClassificationLevel] = mapped_column(
        Integer, default=ClassificationLevel.UNCLASSIFIED
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    totp_secret_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    totp_enabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()

    sessions: Mapped[list["Session"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", lazy="raise"
    )
    owned_documents: Mapped[list["Document"]] = relationship(
        back_populates="owner", foreign_keys="Document.owner_id", lazy="raise"
    )
    document_versions: Mapped[list["DocumentVersion"]] = relationship(
        back_populates="created_by_user", lazy="raise"
    )
    granted_shares: Mapped[list["DocumentShare"]] = relationship(
        foreign_keys="DocumentShare.granted_by", viewonly=True, lazy="raise"
    )
    revoked_shares: Mapped[list["DocumentShare"]] = relationship(
        foreign_keys="DocumentShare.revoked_by", viewonly=True, lazy="raise"
    )
    received_shares: Mapped[list["DocumentShare"]] = relationship(
        foreign_keys="DocumentShare.user_id", viewonly=True, lazy="raise"
    )
