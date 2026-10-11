"""Initial schema for repositories, findings, and fix verifications

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-10-10 15:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Repositories table
    op.create_table(
        "repositories",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("git_url", sa.String(length=512), nullable=True),
        sa.Column("default_branch", sa.String(length=64), nullable=False, server_default="main"),
        sa.Column("health_score", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("critical_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("high_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("medium_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("low_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_repositories_name", "repositories", ["name"], unique=True)

    # 2. Security findings table
    op.create_table(
        "security_findings",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("repo_id", sa.String(length=64), sa.ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cwe", sa.String(length=128), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("scanner_name", sa.String(length=64), nullable=False),
        sa.Column("file_path", sa.String(length=512), nullable=False),
        sa.Column("line_number", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("code_excerpt", sa.Text(), nullable=True),
        sa.Column("pr_number", sa.Integer(), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="0.95"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_security_findings_repo_id", "security_findings", ["repo_id"])
    op.create_index("ix_security_findings_cwe", "security_findings", ["cwe"])
    op.create_index("ix_security_findings_severity", "security_findings", ["severity"])
    op.create_index("ix_security_findings_status", "security_findings", ["status"])

    # 3. Fix verifications table
    op.create_table(
        "fix_verifications",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("finding_id", sa.String(length=64), sa.ForeignKey("security_findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("test_status", sa.String(length=32), nullable=False, server_default="UNKNOWN"),
        sa.Column("patch_diff", sa.Text(), nullable=True),
        sa.Column("sandbox_env", sa.String(length=64), nullable=False, server_default="us-east-prod-01"),
        sa.Column("pr_number", sa.Integer(), nullable=True),
        sa.Column("merged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_fix_verifications_finding_id", "fix_verifications", ["finding_id"])


def downgrade() -> None:
    op.drop_table("fix_verifications")
    op.drop_table("security_findings")
    op.drop_table("repositories")
