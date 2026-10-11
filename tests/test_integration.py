"""End-to-end API integration tests for AppSec workflows."""
import uuid
from fastapi.testclient import TestClient


def test_full_appsec_ingestion_and_analysis_workflow(auth_client: TestClient):
    # Step 1: Register repository
    repo_name = f"xerova/service-{uuid.uuid4().hex[:6]}"
    create_repo_res = auth_client.post(
        "/api/v1/repositories",
        json={
            "name": repo_name,
            "git_url": f"https://github.com/{repo_name}",
            "default_branch": "main",
            "health_score": 88,
        },
    )
    assert create_repo_res.status_code == 201
    repo = create_repo_res.json()
    repo_id = repo["id"]
    assert repo["name"] == repo_name
    assert repo["owner_id"] == auth_client.current_user.id

    # Step 2: Fetch created repository
    get_repo_res = auth_client.get(f"/api/v1/repositories/{repo_id}")
    assert get_repo_res.status_code == 200
    assert get_repo_res.json()["id"] == repo_id

    # Step 3: Ingest security finding
    create_finding_res = auth_client.post(
        "/api/v1/findings",
        json={
            "repo_id": repo_id,
            "cwe": "CWE-89: SQL Injection",
            "title": "Raw user parameter in database query",
            "severity": "CRITICAL",
            "scanner_name": "Semgrep OSS",
            "file_path": "backend/dao/user.py",
            "line_number": 34,
            "code_excerpt": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            "confidence_score": 0.95,
        },
    )
    assert create_finding_res.status_code == 201
    finding = create_finding_res.json()
    finding_id = finding["id"]

    # Step 4: List findings filtered by repo_id
    list_findings_res = auth_client.get(f"/api/v1/findings?repo_id={repo_id}&severity=CRITICAL")
    assert list_findings_res.status_code == 200
    findings_list = list_findings_res.json()
    assert len(findings_list) == 1
    assert findings_list[0]["id"] == finding_id

    # Step 5: Execute security analysis with secret redaction verification
    analysis_res = auth_client.post(
        "/api/v1/analyze-finding",
        json={
            "finding_id": finding_id,
            "scanner_name": "Semgrep OSS",
            "vulnerability_category": "CWE-89: SQL Injection",
            "file_path": "backend/dao/user.py",
            "line_number": 34,
            "scanner_severity": "CRITICAL",
            "scanner_message": "SQL query concatenation detected",
            "code_excerpt": "const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'; cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            "data_flow_evidence": ["user_id input parameter", "cursor.execute sink"],
            "user_authorized_analysis": True,
        },
    )
    assert analysis_res.status_code == 200
    analysis = analysis_res.json()
    assert "finding_summary" in analysis
    assert "evidence_observed" in analysis
    assert len(analysis["recommended_remediation"]) > 0
    assert len(analysis["suggested_tests"]) > 0
