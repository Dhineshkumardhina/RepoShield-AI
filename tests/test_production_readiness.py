"""Tests verifying production deployment hardening and operational safety controls."""
from datetime import datetime, timedelta, timezone
import json
import logging
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.errors import SecurityPolicyViolationError, ValidationError
from app.core.logging import JSONFormatter, StandardFormatter, scrub_log_message
from app.core.quotas import (
    check_scan_concurrency_and_quota,
    check_verification_concurrency,
    reconcile_interrupted_jobs,
)
from app.core.workspace_cleanup import clean_stale_workspaces
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.user import User


def test_production_environment_config_validation():
    """Verify that production mode strictly rejects SQLite and default insecure secret keys."""
    # 1. Rejects SQLite in production
    with pytest.raises(ValueError, match="SQLite cannot be used in production"):
        Settings(
            APP_ENV="production",
            DATABASE_URL="sqlite:///./prod.db",
            SECRET_KEY="a" * 64,
        )

    # 2. Rejects default insecure secret key in production
    with pytest.raises(ValueError, match="requires a cryptographically strong SECRET_KEY"):
        Settings(
            APP_ENV="production",
            DATABASE_URL="postgresql+psycopg://user:pass@localhost:5432/prod_db",
            SECRET_KEY="dev-insecure-secret-key-32-chars-long!!",
        )

    # 3. Rejects short secret key in production (< 32 chars)
    with pytest.raises(ValueError, match="requires a cryptographically strong SECRET_KEY"):
        Settings(
            APP_ENV="production",
            DATABASE_URL="postgresql+psycopg://user:pass@localhost:5432/prod_db",
            SECRET_KEY="short-secret-key",
        )

    # 4. Valid production settings succeed
    prod_settings = Settings(
        APP_ENV="production",
        DATABASE_URL="postgresql+psycopg://user:pass@localhost:5432/prod_db",
        SECRET_KEY="strong_cryptographic_production_key_64_characters_long_for_security!",
        DOCS_ENABLED=False,
    )
    assert prod_settings.is_production is True
    assert prod_settings.cookie_secure is True


def test_log_secret_redaction():
    """Verify that log formatters redact passwords, tokens, API keys, and private keys."""
    raw_secret_message = (
        "User auth failed: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID "
        "with ghp_ABCDEF1234567890abcdef12345678901234 "
        "and password='SuperSecretPassword123!' "
        "connecting to postgres://admin:SuperSecretDbPass@db:5432/app"
    )

    scrubbed = scrub_log_message(raw_secret_message)
    assert "SuperSecretPassword123!" not in scrubbed
    assert "[REDACTED_SECRET]" in scrubbed
    assert "ghp_ABCDEF1234567890abcdef12345678901234" not in scrubbed
    assert "[REDACTED_API_KEY]" in scrubbed
    assert "SuperSecretDbPass" not in scrubbed
    assert "[REDACTED_DB_PASSWORD]" in scrubbed
    assert "[REDACTED_JWT_TOKEN]" in scrubbed

    # Test JSON formatter
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg=raw_secret_message,
        args=(),
        exc_info=None,
    )
    json_formatter = JSONFormatter()
    formatted_json = json.loads(json_formatter.format(record))
    assert "SuperSecretPassword123!" not in formatted_json["message"]
    assert "[REDACTED_SECRET]" in formatted_json["message"]


def test_interrupted_jobs_reconciliation(db_session: Session, user_a: User):
    """Verify that hanging or orphaned jobs from a crashed worker are safely reconciled."""
    # Create repository
    repo = Repository(
        id=f"repo_rec_{uuid.uuid4().hex[:6]}",
        owner_id=user_a.id,
        name="recon/repo",
        default_branch="main",
    )
    db_session.add(repo)
    db_session.commit()

    # Create an old running scan (started 30 minutes ago)
    old_scan = Scan(
        id=f"scan_rec_{uuid.uuid4().hex[:6]}",
        repository_id=repo.id,
        status="running",
        created_at=datetime.now(timezone.utc) - timedelta(minutes=30),
    )
    db_session.add(old_scan)
    db_session.commit()

    # Run reconciliation
    reconciled = reconcile_interrupted_jobs(db_session)
    assert reconciled >= 1

    # Verify scan transitioned to interrupted
    db_session.refresh(old_scan)
    assert old_scan.status == "interrupted"
    assert "interrupted" in old_scan.summary.lower()


def test_concurrency_limit_enforcement(db_session: Session, user_a: User):
    """Verify that active scan concurrency limit prevents runaway job flooding."""
    repo = Repository(
        id=f"repo_quota_{uuid.uuid4().hex[:6]}",
        owner_id=user_a.id,
        name="quota/repo",
        default_branch="main",
    )
    db_session.add(repo)
    db_session.commit()

    # Create 3 currently active running scans (hitting the default concurrency limit of 3)
    for i in range(3):
        active_scan = Scan(
            id=f"scan_active_{i}_{uuid.uuid4().hex[:4]}",
            repository_id=repo.id,
            status="running",
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(active_scan)
    db_session.commit()

    # Attempting to start another scan should raise SecurityPolicyViolationError
    with pytest.raises(SecurityPolicyViolationError, match="Concurrency limit reached"):
        check_scan_concurrency_and_quota(user=user_a, db=db_session)


def test_workspace_cleanup_utility(db_session: Session):
    """Verify clean_stale_workspaces executes without error and returns tracking summary."""
    summary = clean_stale_workspaces(db=db_session, max_age_hours=0)
    assert "removed_directories" in summary
    assert "reclaimed_bytes" in summary
    assert isinstance(summary["removed_directories"], int)


def test_security_headers_present_on_api(client: TestClient):
    """Verify essential AppSec security headers are returned on API endpoints."""
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
    assert "X-Request-ID" in res.headers


def test_request_size_limit_middleware(client: TestClient):
    """Verify that requests exceeding MAX_REQUEST_BODY_SIZE_BYTES are rejected before memory buffering."""
    oversized_bytes = 100 * 1024 * 1024  # 100 MB
    res = client.post(
        "/api/v1/repositories",
        content=b"test",
        headers={"Content-Length": str(oversized_bytes), "Content-Type": "application/json"},
    )
    assert res.status_code == 413
    err = res.json()
    assert "maximum allowed size" in err["error"]["message"].lower()
