"""Security evidence management table

Revision ID: 0005_security_evidence_management
Revises: 0004_fix_verification_engine
Create Date: 2026-10-11 11:42:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0005_security_evidence_management"
down_revision: Union[str, None] = "0004_fix_verification_engine"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "security_evidence",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("repository_id", sa.String(length=64), sa.ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", sa.String(length=64), sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("verification_run_id", sa.String(length=64), sa.ForeignKey("verification_runs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("finding_id", sa.String(length=64), sa.ForeignKey("security_findings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("evidence_category", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("provenance", sa.String(length=64), nullable=False, server_default="scanner_observed"),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("tool_version", sa.String(length=64), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("sanitized_payload", sa.Text(), nullable=False),
        sa.Column("checks_not_performed", sa.Text(), nullable=True),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_security_evidence_repository_id", "security_evidence", ["repository_id"])
    op.create_index("ix_security_evidence_scan_id", "security_evidence", ["scan_id"])
    op.create_index("ix_security_evidence_verification_run_id", "security_evidence", ["verification_run_id"])
    op.create_index("ix_security_evidence_finding_id", "security_evidence", ["finding_id"])
    op.create_index("ix_security_evidence_evidence_category", "security_evidence", ["evidence_category"])
    op.create_index("ix_security_evidence_provenance", "security_evidence", ["provenance"])
    op.create_index("ix_security_evidence_content_hash", "security_evidence", ["content_hash"])
    op.create_index("ix_security_evidence_recorded_at", "security_evidence", ["recorded_at"])


def downgrade() -> None:
    op.drop_table("security_evidence")
