"""reshape alerts for access alerts

The alerts table shipped in the core data model as a reserved placeholder
with no writers; spec 0010 defines the real shape, so it is dropped and
recreated rather than altered.

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-11-09 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "d4e5f6a7b8c9"
down_revision: str | None = "c3d4e5f6a7b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_table("alerts")
    op.create_table(
        "alerts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("alert_type", sa.String(length=30), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("actor_username", sa.String(length=64), nullable=True),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column(
            "audit_seq",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            nullable=False,
        ),
        sa.Column("acknowledged_by_id", sa.Uuid(), nullable=True),
        sa.Column("acknowledged_by_username", sa.String(length=64), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "alert_type IN ('denied_access', 'sensitive_read', 'privilege_change', 'chain_tamper')",
            name="ck_alerts_alert_type",
        ),
        sa.CheckConstraint("state IN ('open', 'acknowledged')", name="ck_alerts_state"),
        sa.ForeignKeyConstraint(["audit_seq"], ["audit_log.seq"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("audit_seq"),
    )
    op.create_index("ix_alerts_state_audit_seq", "alerts", ["state", "audit_seq"], unique=False)
    op.create_index(
        "ix_alerts_actor_type_created",
        "alerts",
        ["actor_id", "alert_type", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_alerts_actor_type_created", table_name="alerts")
    op.drop_index("ix_alerts_state_audit_seq", table_name="alerts")
    op.drop_table("alerts")
    op.create_table(
        "alerts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("alert_type", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("document_id", sa.Uuid(), nullable=True),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("fingerprint", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.Uuid(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_alerts_created_at"), "alerts", ["created_at"], unique=False)
