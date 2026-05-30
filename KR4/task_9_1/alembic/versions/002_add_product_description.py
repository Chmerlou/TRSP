"""add product description

Revision ID: 002
Revises: 001
Create Date: 2026-05-30

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("products") as batch_op:
        batch_op.add_column(
            sa.Column("description", sa.String(length=500), nullable=False, server_default="")
        )
    op.execute("UPDATE products SET description = '' WHERE description IS NULL")
    with op.batch_alter_table("products") as batch_op:
        batch_op.alter_column("description", server_default=None)


def downgrade() -> None:
    op.drop_column("products", "description")
