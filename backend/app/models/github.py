"""SQLAlchemy database models for GitHub App & CI/CD integrations."""
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from ..db.base import Base, TimestampMixin, generate_uuid


class GitHubIntegration(Base, TimestampMixin):
    """Stores GitHub App installations and tenant-isolated integration credentials."""
    __tablename__ = "github_integrations"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    owner_id = Column(String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    installation_id = Column(String(64), nullable=False, index=True)
    app_id = Column(String(64), nullable=True)
    account_login = Column(String(255), nullable=False)  # GitHub username or organization
    account_type = Column(String(32), default="User", nullable=False)  # "User" or "Organization"
    auth_mode = Column(String(32), default="github_app", nullable=False)  # "github_app" or "scoped_token"

    # Encrypted credentials at rest (AES-128-CBC / Fernet token)
    encrypted_credentials = Column(Text, nullable=True)
    webhook_secret_hash = Column(String(128), nullable=True)

    # Documented granted permissions JSON: {"contents": "read", "pull_requests": "write", ...}
    permissions_granted = Column(Text, nullable=True)

    is_active = Column(Boolean, default=True, nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revocation_reason = Column(String(255), nullable=True)

    # Relationships
    owner = relationship("User", backref="github_integrations")
    repo_links = relationship("RepositoryGitHubLink", back_populates="integration", cascade="all, delete-orphan")


class RepositoryGitHubLink(Base, TimestampMixin):
    """Binds a RepoShield repository to a specific GitHub repository."""
    __tablename__ = "repository_github_links"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    repository_id = Column(String(64), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    integration_id = Column(String(64), ForeignKey("github_integrations.id", ondelete="CASCADE"), nullable=False, index=True)

    github_repo_full_name = Column(String(255), nullable=False, index=True)  # e.g., "xerova/auth-gateway"
    default_branch = Column(String(128), default="main", nullable=False)

    # Operator policy toggles (least-privilege defaults)
    auto_scan_on_pr = Column(Boolean, default=True, nullable=False)
    publish_pr_comments = Column(Boolean, default=False, nullable=False)  # Default: read-only; requires explicit opt-in
    block_pr_on_critical = Column(Boolean, default=False, nullable=False)

    # Relationships
    repository = relationship("Repository", backref="github_link")
    integration = relationship("GitHubIntegration", back_populates="repo_links")


class PullRequestScan(Base, TimestampMixin):
    """Tracks security scans and finding diffs evaluated against a GitHub Pull Request."""
    __tablename__ = "pull_request_scans"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    repository_id = Column(String(64), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(64), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)

    pr_number = Column(Integer, nullable=False, index=True)
    pr_title = Column(String(255), nullable=True)
    head_commit_sha = Column(String(64), nullable=False, index=True)
    base_commit_sha = Column(String(64), nullable=False)
    head_branch = Column(String(128), nullable=True)
    base_branch = Column(String(128), nullable=True)

    # Status: pending, analyzing, completed, failed, inconclusive
    status = Column(String(32), default="pending", nullable=False, index=True)

    # Changed files JSON list: ["src/app.py", "requirements.txt"]
    changed_files = Column(Text, nullable=True)

    # Four diff dimensions
    new_findings_count = Column(Integer, default=0, nullable=False)
    resolved_findings_count = Column(Integer, default=0, nullable=False)
    unchanged_findings_count = Column(Integer, default=0, nullable=False)
    regressed_findings_count = Column(Integer, default=0, nullable=False)

    # Categorized finding details JSON
    findings_diff_json = Column(Text, nullable=True)

    # Summary publication status
    summary_published = Column(Boolean, default=False, nullable=False)
    summary_comment_id = Column(String(64), nullable=True)

    # Omission auditing: checks not performed / incomplete scanners
    incomplete_checks = Column(Text, nullable=True)  # JSON list
    execution_log = Column(Text, nullable=True)

    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    repository = relationship("Repository", backref="pr_scans")
    scan = relationship("Scan", backref="pr_scan")


class WebhookDelivery(Base):
    """Audit table preventing replay attacks and tracking webhook processing."""
    __tablename__ = "webhook_deliveries"

    id = Column(String(64), primary_key=True)  # Delivery GUID from X-GitHub-Delivery
    event_type = Column(String(64), nullable=False)
    payload_sha256 = Column(String(64), nullable=False)
    status = Column(String(32), default="processed", nullable=False)  # processed, duplicate_rejected, signature_failed
    received_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
