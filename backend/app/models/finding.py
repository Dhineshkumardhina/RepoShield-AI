"""SQLAlchemy model for AppSec findings."""
from sqlalchemy import Column, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from ..db.base import Base, TimestampMixin, generate_uuid


class SecurityFinding(Base, TimestampMixin):
    __tablename__ = "security_findings"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    repo_id = Column(String(64), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(64), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    
    # Identifiers
    scanner_identifier = Column(String(64), nullable=False, default="Semgrep OSS")
    scanner_name = Column(String(64), nullable=False)  # Alias/preserved for backward compatibility
    rule_identifier = Column(String(128), nullable=False, default="CWE-89")
    cwe = Column(String(128), nullable=False, index=True)  # Alias/preserved for backward compatibility
    
    title = Column(String(255), nullable=False)
    category = Column(String(64), default="vulnerability", nullable=False, index=True)
    severity = Column(String(32), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    confidence = Column(String(32), default="HIGH", nullable=False)
    confidence_score = Column(Float, default=0.95, nullable=False)
    
    file_path = Column(String(512), nullable=False)
    line_information = Column(String(64), nullable=True)  # String line info e.g. "34" or "34-45"
    line_number = Column(Integer, nullable=False)
    evidence_reference = Column(Text, nullable=True)
    
    finding_status = Column(String(32), default="open", nullable=False, index=True)
    status = Column(String(32), default="open", nullable=False, index=True)  # open, verified, remediated, false_positive
    
    code_excerpt = Column(Text, nullable=True)
    pr_number = Column(Integer, nullable=True)

    # Relationships
    repository = relationship("Repository", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")
    patch_proposals = relationship("PatchProposal", back_populates="finding", cascade="all, delete-orphan")
    verifications = relationship("FixVerification", back_populates="finding", cascade="all, delete-orphan")
    verification_runs = relationship("VerificationRun", back_populates="finding", cascade="all, delete-orphan")
    analyses = relationship("FindingAnalysis", back_populates="finding", cascade="all, delete-orphan")
    validations = relationship("FindingValidation", back_populates="finding", cascade="all, delete-orphan")
