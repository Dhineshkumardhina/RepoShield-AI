"""Add commit_sha column to scans table

Revision ID: 0009_add_commit_sha_to_scans
Revises: 0008_verification_classified_and_provenance
Create Date: 2026-10-17 15:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0009_add_commit_sha_to_scans"
down_revision: Union[str, None] = "0008_verification_classified_and_provenance"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("scans") as batch_op:
        batch_op.add_column(sa.Column("commit_sha", sa.String(length=64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch_op:
        batch_op.drop_column("commit_sha")
