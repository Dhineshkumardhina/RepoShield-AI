"""Centralized API error handling tests."""
from fastapi.testclient import TestClient


def test_401_unauthorized_when_no_credentials_provided(client: TestClient):
    response = client.get("/api/v1/repositories")
    assert response.status_code == 401
    data = response.json()

    assert data["success"] is False
    assert "error" in data
    assert data["error"]["code"] == "UNAUTHORIZED"
    assert "Authentication credentials were not provided" in data["error"]["message"]
    assert "request_id" in data
    assert "timestamp" in data


def test_404_not_found_returns_standard_error_envelope(auth_client: TestClient):
    response = auth_client.get("/api/v1/repositories/non-existent-repo-999")
    assert response.status_code == 404
    data = response.json()

    assert data["success"] is False
    assert "error" in data
    assert data["error"]["code"] == "RESOURCE_NOT_FOUND"
    assert "non-existent-repo-999" in data["error"]["message"]
    assert "request_id" in data
    assert "timestamp" in data
    # Security header verified
    assert "X-Request-ID" in response.headers
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_422_validation_error_returns_standard_envelope(auth_client: TestClient):
    # Missing required fields when posting to /api/v1/repositories
    response = auth_client.post("/api/v1/repositories", json={})
    assert response.status_code == 422
    data = response.json()

    assert data["success"] is False
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert len(data["error"]["details"]) > 0
    assert "request_id" in data


def test_security_policy_violation_returns_403(auth_client: TestClient):
    # Analyzer endpoint without user authorization
    unauth_payload = {
        "finding_id": "FIND-UNAUTH-01",
        "scanner_name": "Semgrep",
        "vulnerability_category": "CWE-89: SQL Injection",
        "file_path": "auth.py",
        "line_number": 10,
        "scanner_severity": "CRITICAL",
        "scanner_message": "Vulnerability detected",
        "code_excerpt": "select * from test",
        "user_authorized_analysis": False,  # Violates rule #8
    }
    response = auth_client.post("/api/v1/analyze-finding", json=unauth_payload)
    assert response.status_code == 403
    data = response.json()
    assert data["success"] is False
    assert data["error"]["code"] == "SECURITY_POLICY_VIOLATION"


def test_invalid_bearer_token_returns_401(client: TestClient):
    client.headers["Authorization"] = "Bearer completely-invalid-fake-token"
    response = client.get("/api/v1/repositories")
    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "UNAUTHORIZED"
