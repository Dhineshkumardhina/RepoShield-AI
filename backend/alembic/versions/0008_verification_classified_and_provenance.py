"""Add classified findings and provenance columns to verification_runs

Revision ID: 0008_verification_classified_and_provenance
Revises: 0007_vulnerability_validation
Create Date: 2026-10-11 23:05:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0008_verification_classified_and_provenance"
down_revision: Union[str, None] = "0007_vulnerability_validation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("verification_runs") as batch_op:
        batch_op.alter_column("patch_proposal_id", existing_type=sa.String(length=64), nullable=True)
        batch_op.add_column(sa.Column("classified_findings", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("source_revision", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("target_revision", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("configuration_changes", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("findings_before_patch", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("findings_after_patch", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("ai_interpretation", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("integrity_hash", sa.String(length=64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("verification_runs") as batch_op:
        batch_op.alter_column("patch_proposal_id", existing_type=sa.String(length=64), nullable=False)
        batch_op.drop_column("integrity_hash")
        batch_op.drop_column("ai_interpretation")
        batch_op.drop_column("findings_after_patch")
        batch_op.drop_column("findings_before_patch")
        batch_op.drop_column("configuration_changes")
        batch_op.drop_column("target_revision")
        batch_op.drop_column("source_revision")
        batch_op.drop_column("classified_findings")
