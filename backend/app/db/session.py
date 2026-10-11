"""SQLAlchemy engine, session factory, and dependency injection."""
from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from ..core.config import settings
from ..core.logging import get_logger

logger = get_logger("reposhield.db")

# Configure database engine based on dialect
if settings.is_sqlite:
    # SQLite requires check_same_thread=False for FastAPI concurrency
    engine = create_engine(
        settings.DATABASE_URL,
        connect_args={"check_same_thread": False},
        echo=False,
    )
else:
    # PostgreSQL / production connection pooling
    engine = create_engine(
        settings.DATABASE_URL,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        echo=False,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for managing database sessions with auto-rollback."""
    db = SessionLocal()
    try:
        yield db
    except Exception as exc:
        db.rollback()
        logger.error(f"Database transaction error: {exc}")
        raise
    finally:
        db.close()


def check_db_connection() -> bool:
    """Verifies that the database is responsive via a lightweight query."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.error(f"Database health check failed: {exc}")
        return False
