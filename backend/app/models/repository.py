"""SQLAlchemy model for software repositories."""
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from ..db.base import Base, TimestampMixin, generate_uuid


class Repository(Base, TimestampMixin):
    __tablename__ = "repositories"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    owner_id = Column(String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False, index=True)
    source_type = Column(String(64), default="github", nullable=False)  # github, gitlab, bitbucket, local
    language_metadata = Column(String(255), nullable=True)  # e.g. "Python, TypeScript"
    git_url = Column(String(512), nullable=True)
    default_branch = Column(String(64), default="main", nullable=False)
    health_score = Column(Integer, default=100, nullable=False)
    critical_count = Column(Integer, default=0, nullable=False)
    high_count = Column(Integer, default=0, nullable=False)
    medium_count = Column(Integer, default=0, nullable=False)
    low_count = Column(Integer, default=0, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    last_scanned_at = Column(DateTime(timezone=True), nullable=True)

    # Ingestion Status & Workspace Isolation
    ingestion_status = Column(String(32), default="completed", nullable=False, index=True)  # pending, in_progress, completed, failed
    ingestion_error = Column(String(1024), nullable=True)
    file_count = Column(Integer, default=0, nullable=False)
    total_size_bytes = Column(Integer, default=0, nullable=False)
    workspace_path = Column(String(512), nullable=True)

    # Relationships
    owner = relationship("User", back_populates="repositories")
    scans = relationship("Scan", back_populates="repository", cascade="all, delete-orphan")
    findings = relationship("SecurityFinding", back_populates="repository", cascade="all, delete-orphan")
