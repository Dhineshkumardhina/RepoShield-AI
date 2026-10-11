"""SQLAlchemy model for Security Evidence management."""
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from ..db.base import Base, TimestampMixin, generate_uuid


class SecurityEvidence(Base, TimestampMixin):
    """Stores granular, tamper-evident security evidence artifacts.
    
    Associates evidence with scans, verification runs, and findings while
    enforcing repository tenant isolation, secret scrubbing, and content hashing.
    """
    __tablename__ = "security_evidence"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    repository_id = Column(String(64), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(64), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    verification_run_id = Column(String(64), ForeignKey("verification_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    finding_id = Column(String(64), ForeignKey("security_findings.id", ondelete="SET NULL"), nullable=True, index=True)

    # Categories: scanner_output, revision_hash, patch_diff, test_result, comparison, tool_metadata, verification_report, audit_event, ai_analysis
    evidence_category = Column(String(64), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    
    # Provenance tracking: scanner_observed, sandbox_observed, ai_generated_commentary, user_supplied
    provenance = Column(String(64), default="scanner_observed", nullable=False, index=True)
    
    tool_name = Column(String(128), nullable=False)
    tool_version = Column(String(64), nullable=True)
    
    # Cryptographic integrity indicator for accidental alteration detection
    content_hash = Column(String(64), nullable=False, index=True)
    
    # Sanitized bounded text payload (never full source tree or raw secrets)
    sanitized_payload = Column(Text, nullable=False)
    
    # Explicit omission tracking: JSON list of checks not performed
    checks_not_performed = Column(Text, nullable=True)

    recorded_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    repository = relationship("Repository")
    scan = relationship("Scan")
    verification_run = relationship("VerificationRun")
    finding = relationship("SecurityFinding")
