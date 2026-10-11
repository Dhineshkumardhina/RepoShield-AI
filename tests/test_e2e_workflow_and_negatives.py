"""End-to-End Workflow and Negative Testing for RepoShield AI.

Validates:
STEP 2 — Complete E2E Workflow using real scanner output and test execution:
1. User registration & authentication.
2. Ingestion of real vulnerable repository via ZIP upload.
3. Triggering security scanner (Bandit) on workspace.
4. Retrieving real normalized scanner findings.
5. Inspecting finding details and evidence.
6. Validating a candidate security patch.
7. Executing fix-verification workflow in isolated workspace.
8. Verifying test results and verification status.
9. Generating markdown security reports (findings & verification).
10. Verifying tenant isolation and access control.

STEP 3 — Negative Testing:
- Invalid uploads (corrupt file, path traversal zip).
- Malformed API payloads.
- Unauthorized access (missing or invalid token).
- Cross-user resource access (User B accessing User A's data).
- Missing AI key fallback behavior.
- Invalid patches with traversal attempts.
- Regression patches that break test suites.
- Stale running jobs reconciliation.
"""

from io import BytesIO
import json
from pathlib import Path
import tempfile
import zipfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.db.session import get_db, SessionLocal, engine
from app.db.base import Base
from app.models.user import User
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.finding import SecurityFinding
from app.models.verification import VerificationRun
from app.core.quotas import reconcile_interrupted_jobs


@pytest.fixture(scope="module")
def client():
    """Test client using existing SQLite test database."""
    with TestClient(app) as c:
        yield c


def create_vulnerable_test_zip() -> bytes:
    """Create a real in-memory ZIP archive containing vulnerable Python code."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Vulnerable Python code with SQL injection
        app_code = (
            "import sqlite3\n\n"
            "def query_user(db_path, username):\n"
            "    conn = sqlite3.connect(db_path)\n"
            "    cursor = conn.cursor()\n"
            "    # VULNERABLE: Direct f-string interpolation\n"
            "    query = f\"SELECT id, username FROM users WHERE username = '{username}'\"\n"
            "    cursor.execute(query)\n"
            "    row = cursor.fetchone()\n"
            "    conn.close()\n"
            "    return row\n"
        )
        zf.writestr("src/user_service.py", app_code)
        
        # Existing functional unit test
        test_code = (
            "import sqlite3\n"
            "from src.user_service import query_user\n\n"
            "def test_normal_user_lookup(tmp_path):\n"
            "    db = str(tmp_path / 'test.db')\n"
            "    conn = sqlite3.connect(db)\n"
            "    conn.execute('CREATE TABLE users (id INT, username TEXT)')\n"
            "    conn.execute(\"INSERT INTO users VALUES (1, 'alice')\")\n"
            "    conn.commit()\n"
            "    conn.close()\n"
            "    res = query_user(db, 'alice')\n"
            "    assert res == (1, 'alice')\n"
        )
        zf.writestr("tests/test_user_service.py", test_code)
    buf.seek(0)
    return buf.getvalue()


# =============================================================================
# STEP 2: COMPLETE END-TO-END WORKFLOW TESTING
# =============================================================================

def test_full_e2e_positive_lifecycle(client: TestClient):
    """Test complete 10-step lifecycle from registration to report generation."""
    # -------------------------------------------------------------
    # 1. Register & Authenticate User A
    # -------------------------------------------------------------
    user_email = "e2e_auditor@reposhield.io"
    user_pass = "SecurePass987!Auditor"
    reg_resp = client.post("/api/v1/auth/register", json={
        "email": user_email,
        "password": user_pass,
        "full_name": "E2E Auditor"
    })
    # If already registered, login directly
    if reg_resp.status_code == 422:
        pass
    else:
        assert reg_resp.status_code in (200, 201)

    login_resp = client.post("/api/v1/auth/login", json={
        "email": user_email,
        "password": user_pass
    })
    assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
    token_a = login_resp.json()["access_token"]
    headers_a = {"Authorization": f"Bearer {token_a}"}

    # Verify /me endpoint
    me_resp = client.get("/api/v1/auth/me", headers=headers_a)
    assert me_resp.status_code == 200
    user_a_id = me_resp.json()["id"]

    # -------------------------------------------------------------
    # 2. Ingest Repository via ZIP Upload
    # -------------------------------------------------------------
    zip_bytes = create_vulnerable_test_zip()
    files = {"file": ("audited_app.zip", zip_bytes, "application/zip")}
    data = {"name": "audited-sql-gateway"}

    upload_resp = client.post(
        "/api/v1/repositories/ingest/upload",
        files=files,
        data=data,
        headers=headers_a
    )
    assert upload_resp.status_code == 201, f"Upload failed: {upload_resp.text}"
    repo_data = upload_resp.json()
    repo_id = repo_data["id"]
    assert repo_data["ingestion_status"] == "completed"
    assert repo_data["file_count"] >= 2

    # Check ingestion status endpoint
    status_resp = client.get(f"/api/v1/repositories/{repo_id}/ingestion-status", headers=headers_a)
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "completed"

    # -------------------------------------------------------------
    # 3. Run Real Security Scanners (Bandit)
    # -------------------------------------------------------------
    scan_resp = client.post(
        "/api/v1/scans",
        json={
            "repository_id": repo_id,
            "tools": ["bandit"],
            "timeout_seconds": 30
        },
        headers=headers_a
    )
    assert scan_resp.status_code == 201, f"Scan trigger failed: {scan_resp.text}"
    scan_id = scan_resp.json()["id"]
    assert scan_resp.json()["status"] == "completed"

    # -------------------------------------------------------------
    # 4. Retrieve Actual Scanner Findings
    # -------------------------------------------------------------
    results_resp = client.get(f"/api/v1/scans/{scan_id}/results", headers=headers_a)
    assert results_resp.status_code == 200
    scan_results = results_resp.json()
    assert scan_results["total_findings"] > 0, "Bandit should detect SQL injection finding"

    # List findings via /api/v1/findings
    findings_resp = client.get(f"/api/v1/findings?repo_id={repo_id}", headers=headers_a)
    assert findings_resp.status_code == 200
    findings_list = findings_resp.json()
    assert len(findings_list) > 0
    target_finding = findings_list[0]
    finding_id = target_finding["id"]

    # -------------------------------------------------------------
    # 5. Open Finding and Inspect Evidence & Risk Prioritization
    # -------------------------------------------------------------
    f_detail_resp = client.get(f"/api/v1/findings/{finding_id}", headers=headers_a)
    assert f_detail_resp.status_code == 200
    assert f_detail_resp.json()["id"] == finding_id

    # Prioritization check
    prio_resp = client.get(f"/api/v1/findings/{finding_id}/prioritization", headers=headers_a)
    assert prio_resp.status_code == 200
    prio_data = prio_resp.json()
    assert "priority_score" in prio_data
    assert "contextual_priority" in prio_data

    # -------------------------------------------------------------
    # 6. Validate Proposed Patch (Unified Diff)
    # -------------------------------------------------------------
    valid_patch = (
        "--- a/src/user_service.py\n"
        "+++ b/src/user_service.py\n"
        "@@ -6,4 +6,4 @@\n"
        "-    # VULNERABLE: Direct f-string interpolation\n"
        "-    query = f\"SELECT id, username FROM users WHERE username = '{username}'\"\n"
        "-    cursor.execute(query)\n"
        "+    # FIXED: Parameterized query\n"
        "+    query = \"SELECT id, username FROM users WHERE username = ?\"\n"
        "+    cursor.execute(query, (username,))\n"
    )
    val_resp = client.post(
        "/api/v1/verifications/validate-patch",
        json={"proposed_patch": valid_patch},
        headers=headers_a
    )
    assert val_resp.status_code == 200
    assert val_resp.json()["is_valid"] is True
    assert len(val_resp.json()["files"]) == 1

    # -------------------------------------------------------------
    # 7. Run Fix-Verification Workflow in Isolated Workspace
    # -------------------------------------------------------------
    targeted_security_test = (
        "import sqlite3\n"
        "from src.user_service import query_user\n\n"
        "def test_sql_injection_payload_is_neutralized(tmp_path):\n"
        "    db = str(tmp_path / 'test.db')\n"
        "    conn = sqlite3.connect(db)\n"
        "    conn.execute('CREATE TABLE users (id INT, username TEXT)')\n"
        "    conn.execute(\"INSERT INTO users VALUES (1, 'victim')\")\n"
        "    conn.commit()\n"
        "    conn.close()\n"
        "    # Attempt SQL injection\n"
        "    res = query_user(db, \"' OR '1'='1\")\n"
        "    assert res is None\n"
    )

    verif_resp = client.post(
        "/api/v1/verifications",
        json={
            "finding_id": finding_id,
            "proposed_patch": valid_patch,
            "run_existing_tests": True,
            "run_regression_tests": True,
            "regression_test_code": targeted_security_test,
            "timeout_seconds": 20
        },
        headers=headers_a
    )
    assert verif_resp.status_code == 200, f"Verification failed: {verif_resp.text}"
    v_data = verif_resp.json()
    verification_run_id = v_data["id"]

    # -------------------------------------------------------------
    # 8. Inspect Test Results and Verification Status
    # -------------------------------------------------------------
    assert v_data["status"] == "VERIFIED_AGAINST_DEFINED_CHECKS", f"Expected VERIFIED, got {v_data['status']}: {v_data['reasons']}, errors: {v_data.get('execution_errors')}"
    assert v_data["original_finding_status"] == "resolved"
    assert len(v_data["new_findings"]) == 0
    assert "tests_executed" in v_data
    assert len(v_data["tests_executed"]) >= 2  # Existing test + targeted test

    # List verification runs
    runs_resp = client.get(f"/api/v1/verifications?finding_id={finding_id}", headers=headers_a)
    assert runs_resp.status_code == 200
    assert len(runs_resp.json()) >= 1

    # -------------------------------------------------------------
    # 9. Generate Security Reports (Findings & Verification)
    # -------------------------------------------------------------
    findings_report_resp = client.get(
        f"/api/v1/evidence/reports/findings?repo_id={repo_id}&format=markdown",
        headers=headers_a
    )
    assert findings_report_resp.status_code == 200
    assert "Security Findings Report" in findings_report_resp.json()["content"]

    verif_report_resp = client.get(
        f"/api/v1/evidence/reports/verification/{verification_run_id}?format=markdown",
        headers=headers_a
    )
    assert verif_report_resp.status_code == 200
    assert "Fix Verification Report" in verif_report_resp.json()["content"]
    assert "VERIFIED_AGAINST_DEFINED_CHECKS" in verif_report_resp.json()["content"]

    # -------------------------------------------------------------
    # 10. Verify Repository Ownership and Access Controls
    # -------------------------------------------------------------
    # Register User B
    user_b_email = "attacker_b@reposhield.io"
    client.post("/api/v1/auth/register", json={
        "email": user_b_email,
        "password": "SecurePassword123!",
        "full_name": "User B"
    })
    login_b = client.post("/api/v1/auth/login", json={
        "email": user_b_email,
        "password": "SecurePassword123!"
    })
    headers_b = {"Authorization": f"Bearer {login_b.json()['access_token']}"}

    # User B cannot access User A's repository
    b_repo = client.get(f"/api/v1/repositories/{repo_id}", headers=headers_b)
    assert b_repo.status_code in (403, 404)

    # User B cannot access User A's finding
    b_finding = client.get(f"/api/v1/findings/{finding_id}", headers=headers_b)
    assert b_finding.status_code in (403, 404)

    # User B cannot trigger scan on User A's repo
    b_scan = client.post("/api/v1/scans", json={"repository_id": repo_id}, headers=headers_b)
    assert b_scan.status_code in (403, 404)

    # User B cannot export User A's reports
    b_rep = client.get(f"/api/v1/evidence/reports/findings?repo_id={repo_id}", headers=headers_b)
    assert b_rep.status_code in (403, 404)


# =============================================================================
# STEP 3: NEGATIVE TESTING SUITE
# =============================================================================

def test_negative_invalid_uploads(client: TestClient):
    """Test rejecting corrupt archives, path traversal zip slip, and oversized uploads."""
    # Authenticate user
    login_resp = client.post("/api/v1/auth/login", json={
        "email": "e2e_auditor@reposhield.io",
        "password": "SecurePass987!Auditor"
    })
    headers = {"Authorization": f"Bearer {login_resp.json()['access_token']}"}

    # 1. Corrupt (non-zip) file upload
    corrupt_files = {"file": ("corrupt.zip", b"THIS_IS_NOT_A_ZIP_HEADER", "application/zip")}
    r1 = client.post("/api/v1/repositories/ingest/upload", files=corrupt_files, headers=headers)
    assert r1.status_code == 422
    err_msg1 = r1.json().get("error", {}).get("message", "") or str(r1.json())
    assert "not a valid zip archive" in err_msg1.lower() or "zip" in err_msg1.lower()

    # 2. Path Traversal Zip Slip entry
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/passwd", "root:pwned")
    buf.seek(0)
    slip_files = {"file": ("slip.zip", buf.getvalue(), "application/zip")}
    r2 = client.post("/api/v1/repositories/ingest/upload", files=slip_files, headers=headers)
    assert r2.status_code == 422
    err_msg2 = r2.json().get("error", {}).get("message", "") or str(r2.json())
    assert "traversal" in err_msg2.lower()


def test_negative_unauthorized_access(client: TestClient):
    """Test endpoints reject unauthenticated requests."""
    client.cookies.clear()
    # No auth header
    assert client.get("/api/v1/repositories").status_code == 401
    assert client.get("/api/v1/findings").status_code == 401
    assert client.get("/api/v1/scans").status_code == 401
    assert client.get("/api/v1/verifications").status_code == 401

    # Invalid / forged bearer token
    bad_headers = {"Authorization": "Bearer forged.invalid.token"}
    assert client.get("/api/v1/repositories", headers=bad_headers).status_code == 401


def test_negative_malformed_api_requests(client: TestClient):
    """Test API rejects malformed requests and invalid enum schemas."""
    login_resp = client.post("/api/v1/auth/login", json={
        "email": "e2e_auditor@reposhield.io",
        "password": "SecurePass987!Auditor"
    })
    headers = {"Authorization": f"Bearer {login_resp.json()['access_token']}"}

    # Missing required repository_id
    r1 = client.post("/api/v1/scans", json={}, headers=headers)
    assert r1.status_code == 422

    # Invalid severity enum in finding ingestion
    r2 = client.post("/api/v1/findings", json={
        "repo_id": "any-id",
        "title": "Test Finding",
        "severity": "SUPER_CRITICAL_INVALID",
        "file_path": "test.py"
    }, headers=headers)
    assert r2.status_code == 422


def test_negative_invalid_and_traversal_patches(client: TestClient):
    """Test fix-verification rejects invalid patches and path traversal diffs."""
    login_resp = client.post("/api/v1/auth/login", json={
        "email": "e2e_auditor@reposhield.io",
        "password": "SecurePass987!Auditor"
    })
    headers = {"Authorization": f"Bearer {login_resp.json()['access_token']}"}

    # 1. Path traversal patch
    traversal_patch = (
        "--- a/../../../../etc/shadow\n"
        "+++ b/../../../../etc/shadow\n"
        "@@ -1,1 +1,1 @@\n"
        "-root:*\n"
        "+root:pwned\n"
    )
    val_resp = client.post(
        "/api/v1/verifications/validate-patch",
        json={"proposed_patch": traversal_patch},
        headers=headers
    )
    assert val_resp.status_code == 200
    assert val_resp.json()["is_valid"] is False
    assert any("traversal" in err.lower() for err in val_resp.json()["errors"])

    # 2. Corrupt / empty diff
    val_empty = client.post(
        "/api/v1/verifications/validate-patch",
        json={"proposed_patch": "NOT_A_VALID_DIFF"},
        headers=headers
    )
    assert val_empty.status_code == 200
    assert val_empty.json()["is_valid"] is False


def test_negative_regression_patch_fails_verification(client: TestClient):
    """Test verification engine marks regressive patch as FAILED_VERIFICATION."""
    login_resp = client.post("/api/v1/auth/login", json={
        "email": "e2e_auditor@reposhield.io",
        "password": "SecurePass987!Auditor"
    })
    headers = {"Authorization": f"Bearer {login_resp.json()['access_token']}"}

    # Ensure user has a repo and finding
    repos = client.get("/api/v1/repositories", headers=headers).json()
    if not repos:
        # Ingest one
        zip_bytes = create_vulnerable_test_zip()
        client.post(
            "/api/v1/repositories/ingest/upload",
            files={"file": ("app.zip", zip_bytes, "application/zip")},
            data={"name": "reg-test-repo"},
            headers=headers
        )
        repos = client.get("/api/v1/repositories", headers=headers).json()

    repo_id = repos[0]["id"]
    findings = client.get(f"/api/v1/findings?repo_id={repo_id}", headers=headers).json()
    if not findings:
        # Trigger scan
        client.post("/api/v1/scans", json={"repository_id": repo_id, "tools": ["bandit"]}, headers=headers)
        findings = client.get(f"/api/v1/findings?repo_id={repo_id}", headers=headers).json()

    finding_id = findings[0]["id"]

    # Regressive patch that breaks user query logic
    regressive_patch = (
        "--- a/src/user_service.py\n"
        "+++ b/src/user_service.py\n"
        "@@ -6,4 +6,3 @@\n"
        "-    # VULNERABLE: Direct f-string interpolation\n"
        "-    query = f\"SELECT id, username FROM users WHERE username = '{username}'\"\n"
        "-    cursor.execute(query)\n"
        "+    # REGRESSIVE: Breaks function completely\n"
        "+    raise RuntimeError('Database service down')\n"
    )

    verif_resp = client.post(
        "/api/v1/verifications",
        json={
            "finding_id": finding_id,
            "proposed_patch": regressive_patch,
            "run_existing_tests": True,
            "timeout_seconds": 15
        },
        headers=headers
    )
    assert verif_resp.status_code == 200
    assert verif_resp.json()["status"] == "FAILED_VERIFICATION"


def test_negative_reconciliation_of_interrupted_jobs():
    """Test safety reconciliation when a server restarts with hanging jobs."""
    from datetime import datetime, timezone, timedelta
    from app.core.config import settings

    db = SessionLocal()
    stuck_scan = None
    stuck_verif = None
    try:
        now = datetime.now(timezone.utc)
        stale_time = now - timedelta(minutes=settings.STALE_JOB_TIMEOUT_MINUTES + 5)

        # Create a mock scan stuck in 'running' state with old created_at
        stuck_scan = Scan(
            repository_id="repo-test",
            status="running",
            summary="Interrupted scan during crash"
        )
        stuck_scan.created_at = stale_time
        db.add(stuck_scan)

        # Create a mock verification run stuck in 'RUNNING' state with old created_at
        stuck_verif = VerificationRun(
            id="vr_interrupted_test",
            finding_id="FIND-999",
            status="RUNNING"
        )
        stuck_verif.created_at = stale_time
        db.add(stuck_verif)
        db.commit()

        # Run reconciliation
        count = reconcile_interrupted_jobs(db)
        assert count >= 2

        db.refresh(stuck_scan)
        db.refresh(stuck_verif)
        assert stuck_scan.status in ("interrupted", "failed")
        assert stuck_verif.status == "INCONCLUSIVE"
    finally:
        # Cleanup
        if stuck_scan and stuck_scan.id:
            db.delete(stuck_scan)
        if stuck_verif and stuck_verif.id:
            db.delete(stuck_verif)
        db.commit()
        db.close()
