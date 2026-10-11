"""GitHub App and CI/CD integration tables

Revision ID: 0006_github_ci_integration
Revises: 0005_security_evidence_management
Create Date: 2026-10-11 12:20:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0006_github_ci_integration"
down_revision: Union[str, None] = "0005_security_evidence_management"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. github_integrations
    op.create_table(
        "github_integrations",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("owner_id", sa.String(length=64), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("installation_id", sa.String(length=64), nullable=False),
        sa.Column("app_id", sa.String(length=64), nullable=True),
        sa.Column("account_login", sa.String(length=255), nullable=False),
        sa.Column("account_type", sa.String(length=32), nullable=False, server_default="User"),
        sa.Column("auth_mode", sa.String(length=32), nullable=False, server_default="github_app"),
        sa.Column("encrypted_credentials", sa.Text(), nullable=True),
        sa.Column("webhook_secret_hash", sa.String(length=128), nullable=True),
        sa.Column("permissions_granted", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_github_integrations_owner_id", "github_integrations", ["owner_id"])
    op.create_index("ix_github_integrations_installation_id", "github_integrations", ["installation_id"])

    # 2. repository_github_links
    op.create_table(
        "repository_github_links",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("repository_id", sa.String(length=64), sa.ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("integration_id", sa.String(length=64), sa.ForeignKey("github_integrations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("github_repo_full_name", sa.String(length=255), nullable=False),
        sa.Column("default_branch", sa.String(length=128), nullable=False, server_default="main"),
        sa.Column("auto_scan_on_pr", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("publish_pr_comments", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("block_pr_on_critical", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_repo_github_links_repo_id", "repository_github_links", ["repository_id"])
    op.create_index("ix_repo_github_links_integration_id", "repository_github_links", ["integration_id"])
    op.create_index("ix_repo_github_links_full_name", "repository_github_links", ["github_repo_full_name"])

    # 3. pull_request_scans
    op.create_table(
        "pull_request_scans",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("repository_id", sa.String(length=64), sa.ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", sa.String(length=64), sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("pr_number", sa.Integer(), nullable=False),
        sa.Column("pr_title", sa.String(length=255), nullable=True),
        sa.Column("head_commit_sha", sa.String(length=64), nullable=False),
        sa.Column("base_commit_sha", sa.String(length=64), nullable=False),
        sa.Column("head_branch", sa.String(length=128), nullable=True),
        sa.Column("base_branch", sa.String(length=128), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("changed_files", sa.Text(), nullable=True),
        sa.Column("new_findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("resolved_findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unchanged_findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("regressed_findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_diff_json", sa.Text(), nullable=True),
        sa.Column("summary_published", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("summary_comment_id", sa.String(length=64), nullable=True),
        sa.Column("incomplete_checks", sa.Text(), nullable=True),
        sa.Column("execution_log", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_pr_scans_repo_id", "pull_request_scans", ["repository_id"])
    op.create_index("ix_pr_scans_pr_number", "pull_request_scans", ["pr_number"])
    op.create_index("ix_pr_scans_head_sha", "pull_request_scans", ["head_commit_sha"])

    # 4. webhook_deliveries
    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="processed"),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("webhook_deliveries")
    op.drop_table("pull_request_scans")
    op.drop_table("repository_github_links")
    op.drop_table("github_integrations")
