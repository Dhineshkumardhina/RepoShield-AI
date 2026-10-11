"""SQLAlchemy model for application users."""
from sqlalchemy import Column, String
from sqlalchemy.orm import relationship

from ..db.base import Base, TimestampMixin, generate_uuid


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    account_status = Column(String(32), default="active", nullable=False, index=True)  # active, suspended, pending

    # Relationships
    repositories = relationship("Repository", back_populates="owner", cascade="all, delete-orphan")
    audit_events = relationship("AuditEvent", back_populates="actor")
