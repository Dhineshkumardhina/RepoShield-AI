"""SQLAlchemy model for Evidence-Driven Vulnerability Validation."""
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from ..db.base import Base, TimestampMixin, generate_uuid


class FindingValidation(Base, TimestampMixin):
    """Stores an evidence-driven assessment of an existing scanner finding.
    
    Preserves the original scanner finding pristine while recording RepoShield's
    separate epistemic assessment, supporting/refuting evidence, missing context,
    and analysis limitations.
    """
    __tablename__ = "finding_validations"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    finding_id = Column(String(64), ForeignKey("security_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    repo_id = Column(String(64), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True)

    # Assessment statuses: UNREVIEWED, SUPPORTED_BY_EVIDENCE, POSSIBLE_FALSE_POSITIVE, INSUFFICIENT_EVIDENCE, HUMAN_REVIEW_REQUIRED
    assessment_status = Column(String(32), default="UNREVIEWED", nullable=False, index=True)

    # Confidence metrics
    confidence_score = Column(Float, default=0.5, nullable=False)
    confidence_level = Column(String(32), default="MEDIUM", nullable=False)  # HIGH, MEDIUM, LOW

    # Technical evidence breakdown (stored as JSON arrays)
    explanation = Column(Text, nullable=False)
    evidence_summary = Column(Text, nullable=False)
    supporting_evidence = Column(Text, nullable=False)  # JSON-serialized list of EvidenceItem
    refuting_evidence = Column(Text, nullable=False)    # JSON-serialized list of EvidenceItem
    missing_evidence = Column(Text, nullable=False)     # JSON-serialized list of required evidence
    analysis_limitations = Column(Text, nullable=False) # JSON-serialized list of limitations
    suggested_next_steps = Column(Text, nullable=False) # JSON-serialized list of recommended actions

    # Contextual boundaries
    code_excerpt_inspected = Column(Text, nullable=True)
    context_start_line = Column(Column(String(32)).type, nullable=True)
    context_end_line = Column(Column(String(32)).type, nullable=True)
    is_context_truncated = Column(Boolean, default=False, nullable=False)

    # AI assistant metadata
    ai_assisted = Column(Boolean, default=False, nullable=False)
    ai_model = Column(String(64), nullable=True)

    # Tamper-evident cryptographic hash of the evaluated context and finding metadata
    evidence_hash = Column(String(64), nullable=False, index=True)

    recorded_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    # Relationships
    finding = relationship("SecurityFinding", back_populates="validations")
    repository = relationship("Repository")
