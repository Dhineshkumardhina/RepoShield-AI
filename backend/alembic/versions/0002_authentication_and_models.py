"""Authentication, repository ownership, scans, patch proposals, and audit models

Revision ID: 0002_authentication_and_models
Revises: 0001_initial_schema
Create Date: 2026-10-10 16:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0002_authentication_and_models"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create users table
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("account_status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_account_status", "users", ["account_status"])

    # 2. Update repositories table with owner_id, source_type, language_metadata, last_scanned_at
    with op.batch_alter_table("repositories") as batch_op:
        batch_op.add_column(sa.Column("owner_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("source_type", sa.String(length=64), nullable=False, server_default="github"))
        batch_op.add_column(sa.Column("language_metadata", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.create_foreign_key("fk_repositories_owner_id_users", "users", ["owner_id"], ["id"], ondelete="CASCADE")
        batch_op.create_index("ix_repositories_owner_id", ["owner_id"])

    # 3. Create scans table
    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("repository_id", sa.String(length=64), sa.ForeignKey("repositories.id", ondelete="CASCADE", name="fk_scans_repository_id"), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("scanner_configuration", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scans_repository_id", "scans", ["repository_id"])
    op.create_index("ix_scans_status", "scans", ["status"])

    # 4. Update security_findings table
    with op.batch_alter_table("security_findings") as batch_op:
        batch_op.add_column(sa.Column("scan_id", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("scanner_identifier", sa.String(length=64), nullable=False, server_default="Semgrep OSS"))
        batch_op.add_column(sa.Column("rule_identifier", sa.String(length=128), nullable=False, server_default="CWE-89"))
        batch_op.add_column(sa.Column("category", sa.String(length=64), nullable=False, server_default="vulnerability"))
        batch_op.add_column(sa.Column("confidence", sa.String(length=32), nullable=False, server_default="HIGH"))
        batch_op.add_column(sa.Column("line_information", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("evidence_reference", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("finding_status", sa.String(length=32), nullable=False, server_default="open"))
        batch_op.create_foreign_key("fk_security_findings_scan_id_scans", "scans", ["scan_id"], ["id"], ondelete="SET NULL")
        batch_op.create_index("ix_security_findings_scan_id", ["scan_id"])
        batch_op.create_index("ix_security_findings_category", ["category"])
        batch_op.create_index("ix_security_findings_finding_status", ["finding_status"])

    # 5. Create patch_proposals table
    op.create_table(
        "patch_proposals",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("finding_id", sa.String(length=64), sa.ForeignKey("security_findings.id", ondelete="CASCADE", name="fk_patch_proposals_finding_id"), nullable=False),
        sa.Column("proposed_diff_reference", sa.Text(), nullable=False),
        sa.Column("ai_explanation", sa.Text(), nullable=False),
        sa.Column("review_status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_patch_proposals_finding_id", "patch_proposals", ["finding_id"])
    op.create_index("ix_patch_proposals_review_status", "patch_proposals", ["review_status"])

    # 6. Create verification_runs table
    op.create_table(
        "verification_runs",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("patch_proposal_id", sa.String(length=64), sa.ForeignKey("patch_proposals.id", ondelete="CASCADE", name="fk_verification_runs_patch_proposal_id"), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("test_summary", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_verification_runs_patch_proposal_id", "verification_runs", ["patch_proposal_id"])
    op.create_index("ix_verification_runs_status", "verification_runs", ["status"])

    # 7. Create verification_evidence table
    op.create_table(
        "verification_evidence",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("verification_run_id", sa.String(length=64), sa.ForeignKey("verification_runs.id", ondelete="CASCADE", name="fk_verification_evidence_verification_run_id"), nullable=False),
        sa.Column("evidence_type", sa.String(length=64), nullable=False),
        sa.Column("result", sa.String(length=32), nullable=False),
        sa.Column("tool_name_and_version", sa.String(length=128), nullable=False),
        sa.Column("evidence_reference", sa.Text(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_verification_evidence_verification_run_id", "verification_evidence", ["verification_run_id"])
    op.create_index("ix_verification_evidence_evidence_type", "verification_evidence", ["evidence_type"])

    # 8. Create audit_events table
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("actor_id", sa.String(length=64), sa.ForeignKey("users.id", ondelete="SET NULL", name="fk_audit_events_actor_id"), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_identifier", sa.String(length=128), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("safe_metadata", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_events_actor_id", "audit_events", ["actor_id"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])
    op.create_index("ix_audit_events_resource_type", "audit_events", ["resource_type"])
    op.create_index("ix_audit_events_timestamp", "audit_events", ["timestamp"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("verification_evidence")
    op.drop_table("verification_runs")
    op.drop_table("patch_proposals")

    with op.batch_alter_table("security_findings") as batch_op:
        batch_op.drop_constraint("fk_security_findings_scan_id_scans", type_="foreignkey")
        batch_op.drop_index("ix_security_findings_finding_status")
        batch_op.drop_index("ix_security_findings_category")
        batch_op.drop_index("ix_security_findings_scan_id")
        batch_op.drop_column("finding_status")
        batch_op.drop_column("evidence_reference")
        batch_op.drop_column("line_information")
        batch_op.drop_column("confidence")
        batch_op.drop_column("category")
        batch_op.drop_column("rule_identifier")
        batch_op.drop_column("scanner_identifier")
        batch_op.drop_column("scan_id")

    op.drop_table("scans")

    with op.batch_alter_table("repositories") as batch_op:
        batch_op.drop_constraint("fk_repositories_owner_id_users", type_="foreignkey")
        batch_op.drop_index("ix_repositories_owner_id")
        batch_op.drop_column("last_scanned_at")
        batch_op.drop_column("language_metadata")
        batch_op.drop_column("source_type")
        batch_op.drop_column("owner_id")

    op.drop_table("users")
