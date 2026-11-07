"""audit log prev_hash unique

Revision ID: a1b2c3d4e5f6
Revises: 6200bd2ef651
Create Date: 2026-11-07 00:00:00.000000

"""

from collections.abc import Sequence

from alembic import op

revision: str = "a1b2c3d4e5f6"
down_revision: str | None = "6200bd2ef651"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("audit_log") as batch_op:
        batch_op.create_unique_constraint("uq_audit_log_prev_hash", ["prev_hash"])


def downgrade() -> None:
    with op.batch_alter_table("audit_log") as batch_op:
        batch_op.drop_constraint("uq_audit_log_prev_hash", type_="unique")
