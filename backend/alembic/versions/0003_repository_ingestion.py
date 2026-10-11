"""Repository ingestion tracking and workspace isolation

Revision ID: 0003_repository_ingestion
Revises: 0002_authentication_and_models
Create Date: 2026-10-11 10:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0003_repository_ingestion"
down_revision: Union[str, None] = "0002_authentication_and_models"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("repositories") as batch_op:
        batch_op.add_column(sa.Column("ingestion_status", sa.String(length=32), nullable=False, server_default="completed"))
        batch_op.add_column(sa.Column("ingestion_error", sa.String(length=1024), nullable=True))
        batch_op.add_column(sa.Column("file_count", sa.Integer(), nullable=False, server_default="0"))
        batch_op.add_column(sa.Column("total_size_bytes", sa.Integer(), nullable=False, server_default="0"))
        batch_op.add_column(sa.Column("workspace_path", sa.String(length=512), nullable=True))
        batch_op.create_index("ix_repositories_ingestion_status", ["ingestion_status"])


def downgrade() -> None:
    with op.batch_alter_table("repositories") as batch_op:
        batch_op.drop_index("ix_repositories_ingestion_status")
        batch_op.drop_column("workspace_path")
        batch_op.drop_column("total_size_bytes")
        batch_op.drop_column("file_count")
        batch_op.drop_column("ingestion_error")
        batch_op.drop_column("ingestion_status")
