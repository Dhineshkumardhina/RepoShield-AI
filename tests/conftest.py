"""Pytest fixtures for RepoShield AI backend and integration tests."""
import os
import sys
import uuid
import pytest
from typing import Generator
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

# Force test database configuration before importing app
os.environ["APP_ENV"] = "development"
os.environ["DATABASE_URL"] = "sqlite:///./test_reposhield.db"

from app.core.config import settings
from app.core.security import create_access_token, hash_password
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.user import User

# Test SQLite Engine
TEST_DATABASE_URL = "sqlite:///./test_reposhield.db"
test_engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Create test tables before tests, drop them after test session."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists("./test_reposhield.db"):
        try:
            os.remove("./test_reposhield.db")
        except Exception:
            pass


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    """Provide a clean transaction-isolated database session."""
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Test client with overridden get_db dependency."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def create_test_user(db_session: Session):
    """Factory fixture to create test users with active accounts."""
    def _create_user(email: str = None, password: str = "P@ssword1234!", status: str = "active") -> User:
        user_email = email or f"user_{uuid.uuid4().hex[:8]}@xerova.com"
        user = User(
            email=user_email,
            password_hash=hash_password(password),
            account_status=status,
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        return user
    return _create_user


@pytest.fixture
def auth_client(client: TestClient, create_test_user) -> TestClient:
    """Test client pre-authenticated with Bearer token."""
    user = create_test_user()
    token = create_access_token({"sub": user.id, "email": user.email})
    client.headers["Authorization"] = f"Bearer {token}"
    client.current_user = user
    return client


@pytest.fixture
def user_a(create_test_user) -> User:
    return create_test_user(email=f"alice_{uuid.uuid4().hex[:6]}@xerova.com")


@pytest.fixture
def user_b(create_test_user) -> User:
    return create_test_user(email=f"bob_{uuid.uuid4().hex[:6]}@xerova.com")


@pytest.fixture
def client_a(client: TestClient, user_a: User) -> TestClient:
    token = create_access_token({"sub": user_a.id, "email": user_a.email})
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    c.user = user_a
    return c


@pytest.fixture
def client_b(client: TestClient, user_b: User) -> TestClient:
    token = create_access_token({"sub": user_b.id, "email": user_b.email})
    c = TestClient(app)
    c.headers["Authorization"] = f"Bearer {token}"
    c.user = user_b
    return c
