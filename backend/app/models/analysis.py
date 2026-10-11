"""SQLAlchemy model for AI Security Analysis explanations.

Stores the AI-generated security analyst interpretation separately from the
original scanner finding, ensuring scanner output remains pristine and distinct.
"""
from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from ..db.base import Base, TimestampMixin, generate_uuid


class FindingAnalysis(Base, TimestampMixin):
    __tablename__ = "finding_analyses"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    finding_id = Column(String(64), ForeignKey("security_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    repo_id = Column(String(64), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True)

    plain_language_explanation = Column(Text, nullable=False)
    potential_impact = Column(Text, nullable=False)
    relevant_code_evidence = Column(Text, nullable=False)  # JSON-serialized list
    likely_root_cause = Column(Text, nullable=False)
    suggested_remediation = Column(Text, nullable=False)  # JSON-serialized list
    suggested_targeted_tests = Column(Text, nullable=False)  # JSON-serialized list
    missing_context = Column(Text, nullable=True)  # JSON-serialized list
    limitations = Column(Text, nullable=True)  # JSON-serialized list
    ai_model = Column(String(64), nullable=False, default="gemini-2.5-flash")
    analysis_timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    confidence = Column(String(32), default="HIGH", nullable=False)
    is_exploitable_claim_supported = Column(Boolean, default=False, nullable=False)
    requires_human_review = Column(Boolean, default=True, nullable=False)
    user_authorized = Column(Boolean, default=True, nullable=False)

    # Relationships
    finding = relationship("SecurityFinding", back_populates="analyses")
    repository = relationship("Repository")
