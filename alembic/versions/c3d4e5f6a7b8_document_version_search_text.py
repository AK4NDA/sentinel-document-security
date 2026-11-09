"""document version search text

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-11-09 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c3d4e5f6a7b8"
down_revision: str | None = "b2c3d4e5f6a7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("document_versions") as batch_op:
        batch_op.add_column(sa.Column("search_text", sa.LargeBinary(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("document_versions") as batch_op:
        batch_op.drop_column("search_text")
