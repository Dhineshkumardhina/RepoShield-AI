"""Cross-tenant authorization tests verifying complete isolation between users."""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.audit import AuditEvent


def test_cross_tenant_repository_isolation(client_a: TestClient, client_b: TestClient):
    # 1. Alice creates repository A
    repo_payload = {
        "name": "alice/microservice-auth",
        "git_url": "https://github.com/alice/microservice-auth",
        "default_branch": "main",
        "health_score": 90,
    }
    create_res = client_a.post("/api/v1/repositories", json=repo_payload)
    assert create_res.status_code == 201
    repo_a = create_res.json()
    repo_a_id = repo_a["id"]

    # 2. Alice lists repositories -> repo_a is visible
    alice_repos = client_a.get("/api/v1/repositories").json()
    assert any(r["id"] == repo_a_id for r in alice_repos)

    # 3. Bob lists repositories -> repo_a MUST NOT be visible to Bob
    bob_repos = client_b.get("/api/v1/repositories").json()
    assert not any(r["id"] == repo_a_id for r in bob_repos)

    # 4. Bob attempts to access repo_a directly by ID -> MUST return 403 Forbidden
    cross_access_res = client_b.get(f"/api/v1/repositories/{repo_a_id}")
    assert cross_access_res.status_code == 403
    err = cross_access_res.json()
    assert err["success"] is False
    assert err["error"]["code"] == "FORBIDDEN"
    assert "permission" in err["error"]["message"].lower()


def test_cross_tenant_finding_access_prevention(client_a: TestClient, client_b: TestClient, db_session: Session):
    # 1. Alice registers repo
    repo_res = client_a.post(
        "/api/v1/repositories",
        json={"name": "alice/payment-gateway", "git_url": "https://github.com/alice/payment"},
    )
    repo_id = repo_res.json()["id"]

    # 2. Bob attempts to ingest finding into Alice's repository -> MUST be denied with 403
    bob_inject_res = client_b.post(
        "/api/v1/findings",
        json={
            "repo_id": repo_id,
            "cwe": "CWE-89: SQL Injection",
            "title": "Unauthorized finding injection attempt",
            "severity": "CRITICAL",
            "scanner_name": "Trufflehog",
            "file_path": "main.py",
            "line_number": 1,
        },
    )
    assert bob_inject_res.status_code == 403
    assert bob_inject_res.json()["error"]["code"] == "FORBIDDEN"

    # 3. Alice ingests legitimate finding
    alice_finding_res = client_a.post(
        "/api/v1/findings",
        json={
            "repo_id": repo_id,
            "cwe": "CWE-89: SQL Injection",
            "title": "SQL Injection in query builder",
            "severity": "CRITICAL",
            "scanner_name": "Semgrep OSS",
            "file_path": "backend/dao/user.py",
            "line_number": 34,
        },
    )
    assert alice_finding_res.status_code == 201
    finding_id = alice_finding_res.json()["id"]

    # 4. Bob queries list of findings -> Alice's finding is NOT returned
    bob_findings = client_b.get("/api/v1/findings").json()
    assert not any(f["id"] == finding_id for f in bob_findings)

    # 5. Bob queries Alice's finding directly by ID -> MUST return 403 Forbidden
    bob_get_res = client_b.get(f"/api/v1/findings/{finding_id}")
    assert bob_get_res.status_code == 403
    assert bob_get_res.json()["error"]["code"] == "FORBIDDEN"

    # 6. Verify security audit event logged the blocked unauthorized access
    blocked_event = db_session.query(AuditEvent).filter(
        AuditEvent.action == "UNAUTHORIZED_FINDING_ACCESS_BLOCKED",
        AuditEvent.actor_id == client_b.user.id,
    ).first()
    assert blocked_event is not None
    assert blocked_event.resource_identifier == finding_id


def test_cross_tenant_scan_isolation(client_a: TestClient, client_b: TestClient):
    # 1. Alice creates repository
    repo_res = client_a.post(
        "/api/v1/repositories",
        json={"name": "alice/crypto-service", "git_url": "https://github.com/alice/crypto"},
    )
    repo_id = repo_res.json()["id"]

    # 2. Bob attempts to initiate a scan on Alice's repository -> 403 Forbidden
    bob_scan_res = client_b.post(
        "/api/v1/scans",
        json={"repository_id": repo_id, "summary": "Malicious scan trigger"},
    )
    assert bob_scan_res.status_code == 403
    assert bob_scan_res.json()["error"]["code"] == "FORBIDDEN"

    # 3. Alice initiates scan successfully
    alice_scan_res = client_a.post(
        "/api/v1/scans",
        json={"repository_id": repo_id, "summary": "Authorized audit scan"},
    )
    assert alice_scan_res.status_code == 201
    scan_id = alice_scan_res.json()["id"]

    # 4. Bob cannot list Alice's scan
    bob_scans = client_b.get("/api/v1/scans").json()
    assert not any(s["id"] == scan_id for s in bob_scans)

    # 5. Bob cannot fetch Alice's scan by ID -> 403 Forbidden
    bob_get_scan = client_b.get(f"/api/v1/scans/{scan_id}")
    assert bob_get_scan.status_code == 403
    assert bob_get_scan.json()["error"]["code"] == "FORBIDDEN"


def test_cross_tenant_repository_deletion_and_isolation(client_a: TestClient, client_b: TestClient, db_session: Session):
    # 1. Alice creates repository
    repo_res = client_a.post(
        "/api/v1/repositories",
        json={"name": "alice/vault-service", "git_url": "https://github.com/alice/vault"},
    )
    repo_id = repo_res.json()["id"]

    # 2. Bob attempts to delete Alice's repository -> MUST return 403 Forbidden
    bob_del_res = client_b.delete(f"/api/v1/repositories/{repo_id}")
    assert bob_del_res.status_code == 403
    assert bob_del_res.json()["error"]["code"] == "FORBIDDEN"

    # Verify repository still exists
    assert client_a.get(f"/api/v1/repositories/{repo_id}").status_code == 200

    # 3. Alice deletes her repository -> MUST return 204 No Content
    alice_del_res = client_a.delete(f"/api/v1/repositories/{repo_id}")
    assert alice_del_res.status_code == 204

    # 4. Verify repository is deleted
    assert client_a.get(f"/api/v1/repositories/{repo_id}").status_code == 404

    # 5. Verify audit event was recorded
    audit_evt = db_session.query(AuditEvent).filter(
        AuditEvent.action == "REPOSITORY_DELETED",
        AuditEvent.resource_identifier == repo_id,
        AuditEvent.actor_id == client_a.user.id,
    ).first()
    assert audit_evt is not None

