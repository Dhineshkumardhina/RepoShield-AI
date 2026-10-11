"""SQLAlchemy model for AppSec repository scans."""
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from ..db.base import Base, TimestampMixin, generate_uuid


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    repository_id = Column(String(64), ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(32), default="pending", nullable=False, index=True)  # pending, running, completed, failed
    scanner_configuration = Column(Text, nullable=True)
    commit_sha = Column(String(64), nullable=True)  # Source revision commit hash
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    summary = Column(Text, nullable=True)

    # Relationships
    repository = relationship("Repository", back_populates="scans")
    findings = relationship("SecurityFinding", back_populates="scan")
