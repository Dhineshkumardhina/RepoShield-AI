"""SQLAlchemy model for AI Patch Proposals."""
from sqlalchemy import Column, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from ..db.base import Base, TimestampMixin, generate_uuid


class PatchProposal(Base, TimestampMixin):
    __tablename__ = "patch_proposals"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    finding_id = Column(String(64), ForeignKey("security_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    proposed_diff_reference = Column(Text, nullable=False)
    ai_explanation = Column(Text, nullable=False)
    review_status = Column(String(32), default="pending", nullable=False, index=True)  # pending, approved, rejected, applied

    # Relationships
    finding = relationship("SecurityFinding", back_populates="patch_proposals")
    verification_runs = relationship("VerificationRun", back_populates="patch_proposal", cascade="all, delete-orphan")
