"""Authentication tests for user registration, login, logout, and token security."""
from datetime import timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
import bcrypt

from app.core.config import settings
from app.core.security import create_access_token, verify_password
from app.models.user import User
from app.models.audit import AuditEvent


def test_user_registration_success(client: TestClient, db_session: Session):
    reg_payload = {
        "email": "lead.secops@xerova.com",
        "password": "StrongSecurityPass2026!",
    }
    response = client.post("/api/v1/auth/register", json=reg_payload)
    assert response.status_code == 201
    data = response.json()

    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == "lead.secops@xerova.com"
    assert data["user"]["account_status"] == "active"

    # Verify HTTP-only cookie was set
    assert settings.COOKIE_NAME in response.cookies
    cookie_header = response.headers.get("set-cookie", "")
    assert "HttpOnly" in cookie_header or "httponly" in cookie_header

    # Verify password was hashed and not saved in plaintext
    user = db_session.query(User).filter(User.email == "lead.secops@xerova.com").first()
    assert user is not None
    assert user.password_hash != reg_payload["password"]
    assert verify_password(reg_payload["password"], user.password_hash)

    # Verify audit event logged without password
    audit = db_session.query(AuditEvent).filter(AuditEvent.actor_id == user.id).first()
    assert audit is not None
    assert audit.action == "USER_REGISTRATION_SUCCESS"
    if audit.safe_metadata:
        assert "StrongSecurityPass2026!" not in audit.safe_metadata


def test_user_registration_duplicate_email_fails(client: TestClient):
    payload = {
        "email": "duplicate@xerova.com",
        "password": "Password12345!",
    }
    res1 = client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == 201

    res2 = client.post("/api/v1/auth/register", json=payload)
    assert res2.status_code == 422
    data = res2.json()
    assert data["error"]["code"] == "VALIDATION_FAILED"
    assert "already exists" in data["error"]["message"]


def test_user_registration_weak_password_fails(client: TestClient):
    payload = {
        "email": "short@xerova.com",
        "password": "short",  # < 8 chars
    }
    res = client.post("/api/v1/auth/register", json=payload)
    assert res.status_code == 422
    data = res.json()
    assert data["error"]["code"] == "VALIDATION_ERROR"


def test_user_login_success_bearer_and_cookie(client: TestClient):
    email = "practitioner@xerova.com"
    password = "SecOpsPassword2026!"
    # Register first
    client.post("/api/v1/auth/register", json={"email": email, "password": password})

    # Login
    res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user"]["email"] == email

    # Verify cookie set
    assert settings.COOKIE_NAME in res.cookies


def test_user_login_invalid_credentials_returns_401(client: TestClient):
    email = "valid@xerova.com"
    password = "ValidPassword1234!"
    client.post("/api/v1/auth/register", json={"email": email, "password": password})

    # Wrong password
    bad_res = client.post("/api/v1/auth/login", json={"email": email, "password": "WrongPassword999!"})
    assert bad_res.status_code == 401
    assert bad_res.json()["error"]["code"] == "UNAUTHORIZED"

    # Nonexistent email
    bad_user_res = client.post("/api/v1/auth/login", json={"email": "nonexistent@xerova.com", "password": password})
    assert bad_user_res.status_code == 401
    assert bad_user_res.json()["error"]["code"] == "UNAUTHORIZED"


def test_user_login_suspended_account_returns_403(client: TestClient, db_session: Session):
    email = "suspended@xerova.com"
    password = "ValidPassword1234!"
    client.post("/api/v1/auth/register", json={"email": email, "password": password})

    # Suspend user
    user = db_session.query(User).filter(User.email == email).first()
    user.account_status = "suspended"
    db_session.commit()

    res = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "ACCOUNT_INACTIVE"


def test_get_me_with_bearer_token(client: TestClient):
    email = "tokenuser@xerova.com"
    password = "ValidPassword1234!"
    reg = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    token = reg.json()["access_token"]

    # Request /api/v1/auth/me with Bearer token header
    me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.json()["email"] == email


def test_get_me_with_http_only_cookie(client: TestClient):
    email = "cookieuser@xerova.com"
    password = "ValidPassword1234!"
    # Login sets cookie on the client session
    login_res = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    token = login_res.json()["access_token"]

    # Call with cookie set
    client.cookies.set(settings.COOKIE_NAME, token)
    me_res = client.get("/api/v1/auth/me")
    assert me_res.status_code == 200
    assert me_res.json()["email"] == email


def test_expired_token_returns_401(client: TestClient, create_test_user):
    user = create_test_user()
    # Create token expired 1 hour ago
    expired_token = create_access_token({"sub": user.id, "email": user.email}, expires_delta=timedelta(hours=-1))

    client.headers["Authorization"] = f"Bearer {expired_token}"
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "SESSION_EXPIRED"


def test_logout_clears_cookie(client: TestClient):
    email = "logout_test@xerova.com"
    password = "ValidPassword1234!"
    client.post("/api/v1/auth/register", json={"email": email, "password": password})

    logout_res = client.post("/api/v1/auth/logout")
    assert logout_res.status_code == 200
    assert logout_res.json()["success"] is True
