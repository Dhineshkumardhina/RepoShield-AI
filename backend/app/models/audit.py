"""SQLAlchemy model for AppSec platform audit events."""
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from ..db.base import Base, TimestampMixin, generate_uuid


class AuditEvent(Base, TimestampMixin):
    __tablename__ = "audit_events"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    actor_id = Column(String(64), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(String(64), nullable=False, index=True)  # e.g. USER_LOGIN, REPO_ACCESS_DENIED, CREATE_REPO
    resource_type = Column(String(64), nullable=False, index=True)  # e.g. user, repository, scan, finding
    resource_identifier = Column(String(128), nullable=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    safe_metadata = Column(Text, nullable=True)  # JSON-encoded sanitized metadata, never plaintext secrets

    # Relationships
    actor = relationship("User", back_populates="audit_events")
