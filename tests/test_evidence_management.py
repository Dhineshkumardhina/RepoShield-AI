"""Tests for Security Evidence Management and Auditable Report Generation."""
import json
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.evidence.sanitizer import (
    compute_evidence_hash,
    sanitize_evidence_text,
    sanitize_payload,
)
from backend.app.evidence.service import (
    generate_findings_report,
    generate_verification_report,
    record_security_evidence,
)
from backend.app.models.evidence import SecurityEvidence
from backend.app.models.finding import SecurityFinding
from backend.app.models.repository import Repository
from backend.app.models.scan import Scan
from backend.app.models.user import User
from backend.app.models.verification import VerificationRun


def test_evidence_secret_scrubbing_and_line_bounding():
    """Verifies private keys, AWS tokens, passwords, and excessive lines are scrubbed and bounded."""
    raw_sensitive_snippet = (
        "def connect_db():\n"
        "    aws_key = 'AKIAIOSFODNN7EXAMPLE'\n"
        "    db_url = 'postgres://admin:SuperSecretPassword123@prod-db.internal:5432/main'\n"
        "    jwt_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak'\n"
        "    return db_url\n"
    )
    scrubbed = sanitize_evidence_text(raw_sensitive_snippet)

    assert "AKIAIOSFODNN7EXAMPLE" not in scrubbed
    assert "[REDACTED_AWS_KEY]" in scrubbed
    assert "SuperSecretPassword123" not in scrubbed
    assert "[REDACTED_DB_PASSWORD]" in scrubbed
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in scrubbed
    assert "[REDACTED_JWT_TOKEN]" in scrubbed

    # Test line bounding (exceeding 50 lines)
    large_file = "\n".join([f"line_{i} = {i}" for i in range(120)])
    bounded = sanitize_evidence_text(large_file)
    assert "[TRUNCATED:" in bounded
    assert len(bounded.splitlines()) <= 55


def test_evidence_record_association_and_content_hashing(db_session: Session):
    """Verifies evidence is associated with repository, scan, finding, and has SHA-256 content hash."""
    user = User(
        id=f"usr_ev_{uuid.uuid4().hex[:8]}",
        email=f"evidence_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash="mock_hash",
        account_status="active",
    )
    db_session.add(user)
    db_session.flush()

    repo = Repository(
        id=f"repo_ev_{uuid.uuid4().hex[:8]}",
        owner_id=user.id,
        name="xerova/crypto-core",
        default_branch="main",
    )
    db_session.add(repo)
    db_session.flush()

    scan = Scan(
        id=f"scan_ev_{uuid.uuid4().hex[:8]}",
        repository_id=repo.id,
        status="completed",
    )
    db_session.add(scan)
    db_session.flush()

    finding = SecurityFinding(
        id=f"FIND_EV_{uuid.uuid4().hex[:6]}",
        repo_id=repo.id,
        scan_id=scan.id,
        scanner_name="Semgrep OSS",
        rule_identifier="python.lang.security.deserialization",
        cwe="CWE-502",
        title="Insecure deserialization via pickle.loads",
        severity="HIGH",
        confidence="HIGH",
        file_path="src/utils/serializer.py",
        line_number=22,
    )
    db_session.add(finding)
    db_session.flush()

    payload_data = {"tool": "Semgrep", "rule": "python.lang.security.deserialization", "match": "pickle.loads(user_input)"}
    evidence = record_security_evidence(
        db=db_session,
        repository_id=repo.id,
        evidence_category="scanner_output",
        title="Raw AST Deserialization Match",
        tool_name="Semgrep OSS",
        tool_version="1.78.0",
        raw_payload=payload_data,
        scan_id=scan.id,
        finding_id=finding.id,
        provenance="scanner_observed",
        checks_not_performed=["Runtime memory corruption testing", "Live remote shell execution"],
    )

    assert evidence.id is not None
    assert evidence.repository_id == repo.id
    assert evidence.scan_id == scan.id
    assert evidence.finding_id == finding.id
    assert evidence.content_hash == compute_evidence_hash(evidence.sanitized_payload)
    assert evidence.provenance == "scanner_observed"
    assert "Live remote shell execution" in evidence.checks_not_performed
    assert evidence.recorded_at is not None


def test_multi_tenant_authorization_boundary_enforcement(client: TestClient, db_session: Session):
    """Verifies cross-tenant evidence inspection and report generation is rejected with 403."""
    user_alice = User(
        id=f"usr_alice_{uuid.uuid4().hex[:8]}",
        email=f"alice_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash="mock_hash",
        account_status="active",
    )
    user_mallory = User(
        id=f"usr_mallory_{uuid.uuid4().hex[:8]}",
        email=f"mallory_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash="mock_hash",
        account_status="active",
    )
    db_session.add_all([user_alice, user_mallory])
    db_session.flush()

    repo_alice = Repository(
        id=f"repo_alice_{uuid.uuid4().hex[:8]}",
        owner_id=user_alice.id,
        name="alice/vault-service",
        default_branch="main",
    )
    db_session.add(repo_alice)
    db_session.flush()

    evidence_alice = record_security_evidence(
        db=db_session,
        repository_id=repo_alice.id,
        evidence_category="scanner_output",
        title="Alice Private AST Finding Evidence",
        tool_name="Bandit",
        raw_payload="private_code = 1",
    )

    from backend.app.core.security import create_access_token

    token_alice = create_access_token({"sub": user_alice.id, "email": user_alice.email})
    token_mallory = create_access_token({"sub": user_mallory.id, "email": user_mallory.email})

    # Alice lists own evidence -> 200 OK
    res_alice = client.get(
        f"/api/v1/evidence?repo_id={repo_alice.id}",
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert res_alice.status_code == 200
    assert len(res_alice.json()) == 1

    # Mallory tries to list Alice's evidence -> 403 Forbidden
    res_mallory = client.get(
        f"/api/v1/evidence?repo_id={repo_alice.id}",
        headers={"Authorization": f"Bearer {token_mallory}"},
    )
    assert res_mallory.status_code == 403

    # Mallory tries to view Alice's evidence by ID -> 403 Forbidden
    res_mallory_detail = client.get(
        f"/api/v1/evidence/{evidence_alice.id}",
        headers={"Authorization": f"Bearer {token_mallory}"},
    )
    assert res_mallory_detail.status_code == 403

    # Mallory tries to export findings report for Alice's repo -> 403 Forbidden
    res_mallory_report = client.get(
        f"/api/v1/evidence/reports/findings?repo_id={repo_alice.id}",
        headers={"Authorization": f"Bearer {token_mallory}"},
    )
    assert res_mallory_report.status_code == 403


def test_findings_report_generation_markdown_and_json(db_session: Session):
    """Verifies report generation identifies checks not performed, separates AI vs scanner, and includes limitations."""
    user = User(
        id=f"usr_rep_{uuid.uuid4().hex[:8]}",
        email=f"reporter_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash="mock_hash",
        account_status="active",
    )
    db_session.add(user)
    db_session.flush()

    repo = Repository(
        id=f"repo_rep_{uuid.uuid4().hex[:8]}",
        owner_id=user.id,
        name="xerova/payments-api",
        default_branch="main",
    )
    db_session.add(repo)
    db_session.flush()

    finding = SecurityFinding(
        id=f"FIND_REP_{uuid.uuid4().hex[:6]}",
        repo_id=repo.id,
        scanner_name="Semgrep OSS",
        rule_identifier="python.lang.security.audit.sqli",
        cwe="CWE-89",
        title="SQL injection in merchant transactions query",
        severity="CRITICAL",
        confidence="HIGH",
        file_path="src/controllers/merchant.py",
        line_number=38,
        code_excerpt="cursor.execute(f'SELECT * FROM tx WHERE merchant_id = {m_id}')",
    )
    db_session.add(finding)
    db_session.commit()

    # Markdown report
    md_report = generate_findings_report(db_session, repo.id, user, format="markdown")
    assert "RepoShield AI — Security Findings Report" in md_report.content
    assert "Checks Not Performed" in md_report.content
    assert "[SCANNER EVIDENCE EXCERPT]" in md_report.content
    assert "Content hashes assist in detecting accidental alterations" in md_report.content
    assert "Numerical priority scores represent contextual triage indices" in md_report.content
    assert "Never claim universal security or mathematically proven correctness" in md_report.content

    # JSON report
    json_report = generate_findings_report(db_session, repo.id, user, format="json")
    parsed = json.loads(json_report.content)
    assert parsed["repository_id"] == repo.id
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["original_scanner_severity"] == "CRITICAL"
    assert parsed["findings"][0]["repshield_contextual_priority"] == "CRITICAL"
    assert len(parsed["checks_not_performed"]) > 0


def test_fix_verification_report_generation_preserves_failures(db_session: Session):
    """Verifies fix-verification reports preserve failed and inconclusive runs with traceable rationale."""
    user = User(
        id=f"usr_vf_{uuid.uuid4().hex[:8]}",
        email=f"verifier_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash="mock_hash",
        account_status="active",
    )
    db_session.add(user)
    db_session.flush()

    repo = Repository(
        id=f"repo_vf_{uuid.uuid4().hex[:8]}",
        owner_id=user.id,
        name="xerova/auth-service",
        default_branch="main",
    )
    db_session.add(repo)
    db_session.flush()

    finding = SecurityFinding(
        id=f"FIND_VF_{uuid.uuid4().hex[:6]}",
        repo_id=repo.id,
        scanner_name="Semgrep OSS",
        rule_identifier="python.lang.security.audit.sqli",
        cwe="CWE-89",
        title="SQL injection in auth dao",
        severity="CRITICAL",
        confidence="HIGH",
        file_path="src/dao/auth.py",
        line_number=19,
    )
    db_session.add(finding)
    db_session.flush()

    # Record a FAILED verification run
    run = VerificationRun(
        id=f"vr_fail_{uuid.uuid4().hex[:8]}",
        finding_id=finding.id,
        status="FAILED_VERIFICATION",
        baseline_hash="sha256:baseline_abc123",
        patched_hash="sha256:patched_def456",
        original_finding_status="persisting",
        scanner_metadata=json.dumps({"Semgrep OSS": "1.78.0"}),
        tests_executed=json.dumps(["test_sqli_payload_neutralized"]),
        reasons=json.dumps(["Original finding still reported by Semgrep under recorded ruleset."]),
        missing_evidence=json.dumps(["Dynamic database taint tracing unperformed."]),
        patch_diff="--- a/src/dao/auth.py\n+++ b/src/dao/auth.py\n@@ -19,1 +19,1 @@\n- bad\n+ still_bad",
    )
    db_session.add(run)
    db_session.commit()

    report = generate_verification_report(db_session, run.id, user, format="markdown")
    assert "Verdict:** **FAILED_VERIFICATION**" in report.content
    assert "Original Finding Persistence:** `PERSISTING`" in report.content
    assert "sha256:baseline_abc123" in report.content
    assert "Original finding still reported by Semgrep" in report.content
    assert "Dynamic database taint tracing unperformed" in report.content
    assert "A scanner finding disappearing does not prove that the vulnerability is impossible" in report.content
