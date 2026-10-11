"""SQLAlchemy models for fix verification runs and evidence."""
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from ..db.base import Base, TimestampMixin, generate_uuid


class VerificationRun(Base, TimestampMixin):
    __tablename__ = "verification_runs"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    finding_id = Column(String(64), ForeignKey("security_findings.id", ondelete="CASCADE"), nullable=True, index=True)
    patch_proposal_id = Column(String(64), ForeignKey("patch_proposals.id", ondelete="CASCADE"), nullable=True, index=True)
    patch_id = Column(String(64), nullable=True, index=True)

    # Status: NOT_TESTED, RUNNING, VERIFIED_AGAINST_DEFINED_CHECKS, FAILED_VERIFICATION, INCONCLUSIVE
    status = Column(String(64), default="NOT_TESTED", nullable=False, index=True)
    
    # Baseline & Patch Hashes
    baseline_hash = Column(String(64), nullable=True)
    patched_hash = Column(String(64), nullable=True)

    # Scanner & Test Configurations & Execution Provenance
    scanner_metadata = Column(Text, nullable=True)  # JSON: scanner names, versions, rule IDs
    scanner_config = Column(Text, nullable=True)    # JSON: config rules, flags, paths
    tests_executed = Column(Text, nullable=True)    # JSON: list of tests executed
    test_results = Column(Text, nullable=True)      # JSON: results mapping (passed, failed, timeout)

    # Comparisons and Regressions
    original_finding_status = Column(String(32), default="untested", nullable=False)  # resolved, persisting, modified, untested
    new_findings = Column(Text, nullable=True)      # JSON: new findings/regressions introduced
    classified_findings = Column(Text, nullable=True) # JSON: 6-status classified findings with rationales
    execution_errors = Column(Text, nullable=True)  # JSON: list of errors encountered
    
    # Decisions & Limitations
    reasons = Column(Text, nullable=True)           # JSON: reasons supporting the final result
    missing_evidence = Column(Text, nullable=True)  # JSON: missing evidence items
    evidence_references = Column(Text, nullable=True) # JSON: references / artifacts
    patch_diff = Column(Text, nullable=True)        # Unified diff proposed
    test_summary = Column(Text, nullable=True)

    # Timestamps
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Traceability, Revision Tracking & Evidence Integrity
    source_revision = Column(String(64), nullable=True)  # Base commit SHA / branch
    target_revision = Column(String(64), nullable=True)  # Target commit SHA / patch revision
    configuration_changes = Column(Text, nullable=True)  # JSON record of scanner configuration deviations
    findings_before_patch = Column(Text, nullable=True)  # JSON list of baseline findings
    findings_after_patch = Column(Text, nullable=True)   # JSON list of patched findings
    ai_interpretation = Column(Text, nullable=True)      # Advisory AI-generated interpretation (strictly separated from raw logs)
    integrity_hash = Column(String(64), nullable=True)   # Content-hash for accidental alteration detection

    # Relationships
    finding = relationship("SecurityFinding", back_populates="verification_runs")
    patch_proposal = relationship("PatchProposal", back_populates="verification_runs")
    evidence = relationship("VerificationEvidence", back_populates="verification_run", cascade="all, delete-orphan")


class VerificationEvidence(Base, TimestampMixin):
    __tablename__ = "verification_evidence"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    verification_run_id = Column(String(64), ForeignKey("verification_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type = Column(String(64), nullable=False)  # test_log, ast_diff, sast_scan, container_sandbox
    result = Column(String(32), nullable=False)  # passed, failed, error
    tool_name_and_version = Column(String(128), nullable=False)  # e.g. "pytest-9.1.1", "semgrep-1.78.0"
    evidence_reference = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    verification_run = relationship("VerificationRun", back_populates="evidence")


class FixVerification(Base, TimestampMixin):
    """Preserved verification entity for backward compatibility with initial schema."""
    __tablename__ = "fix_verifications"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    finding_id = Column(String(64), ForeignKey("security_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(32), default="pending", nullable=False)  # pending, passed, failed, merged
    test_status = Column(String(32), default="UNKNOWN", nullable=False)  # PASSING, FAILING, REGRESSION_DETECTED
    patch_diff = Column(Text, nullable=True)
    sandbox_env = Column(String(64), default="us-east-prod-01", nullable=False)
    pr_number = Column(Integer, nullable=True)
    merged_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    finding = relationship("SecurityFinding", back_populates="verifications")
