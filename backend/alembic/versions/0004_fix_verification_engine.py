"""Fix verification engine schema columns

Revision ID: 0004_fix_verification_engine
Revises: 0003_repository_ingestion
Create Date: 2026-10-11 11:20:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0004_fix_verification_engine"
down_revision: Union[str, None] = "0003_repository_ingestion"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("verification_runs") as batch_op:
        batch_op.add_column(sa.Column("finding_id", sa.String(length=64), sa.ForeignKey("security_findings.id", ondelete="CASCADE", name="fk_verification_runs_finding_id"), nullable=True))
        batch_op.add_column(sa.Column("patch_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("baseline_hash", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("patched_hash", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("scanner_metadata", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("scanner_config", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("tests_executed", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("test_results", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("original_finding_status", sa.String(length=32), nullable=False, server_default="untested"))
        batch_op.add_column(sa.Column("new_findings", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("execution_errors", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("reasons", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("missing_evidence", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("evidence_references", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("patch_diff", sa.Text(), nullable=True))
        batch_op.create_index("ix_verification_runs_finding_id", ["finding_id"])
        batch_op.create_index("ix_verification_runs_patch_id", ["patch_id"])


def downgrade() -> None:
    with op.batch_alter_table("verification_runs") as batch_op:
        batch_op.drop_index("ix_verification_runs_patch_id")
        batch_op.drop_index("ix_verification_runs_finding_id")
        batch_op.drop_column("patch_diff")
        batch_op.drop_column("evidence_references")
        batch_op.drop_column("missing_evidence")
        batch_op.drop_column("reasons")
        batch_op.drop_column("execution_errors")
        batch_op.drop_column("new_findings")
        batch_op.drop_column("original_finding_status")
        batch_op.drop_column("test_results")
        batch_op.drop_column("tests_executed")
        batch_op.drop_column("scanner_config")
        batch_op.drop_column("scanner_metadata")
        batch_op.drop_column("patched_hash")
        batch_op.drop_column("baseline_hash")
        batch_op.drop_column("patch_id")
        batch_op.drop_column("finding_id")
