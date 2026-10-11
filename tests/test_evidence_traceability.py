"""Comprehensive test suite for RepoShield AI Security Assurance & Evidence Traceability.

Covers:
1. Evidence association & access control (multi-tenant boundaries).
2. Stable identifiers for scans, verification runs, and evidence.
3. Source revision and content-hash tracking.
4. Record of configuration changes.
5. Audit events for sensitive operations.
6. Downloadable reports in Markdown, JSON, and SARIF formats.
7. Clear separation between raw evidence and AI-generated interpretation.
8. Redaction of secrets in reports and logs.
9. Detection of accidental evidence modification (tamper detection) with authenticity disclaimers.
10. Preservation of failed and inconclusive verification runs.
11. All 14 mandatory fields in verification reports.
"""
import json
import uuid
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.core.security import create_access_token
from backend.app.evidence.sanitizer import (
    compute_evidence_hash,
    sanitize_evidence_text,
    sanitize_payload,
    verify_evidence_integrity,
)
from backend.app.evidence.schemas import (
    AUTHENTICITY_DISCLAIMER,
    EvidenceCategory,
    EvidenceIntegrityStatus,
    ReportExportFormat,
)
from backend.app.evidence.service import (
    generate_verification_report,
    record_security_evidence,
    verify_evidence_record_integrity,
    verify_verification_run_integrity,
)
from backend.app.models.audit import AuditEvent
from backend.app.models.evidence import SecurityEvidence
from backend.app.models.finding import SecurityFinding
from backend.app.models.repository import Repository
from backend.app.models.scan import Scan
from backend.app.models.user import User
from backend.app.models.verification import VerificationRun
from backend.app.schemas.verification import VerificationRunRequest, VerificationStatus
from backend.app.verification.service import execute_fix_verification


@pytest.fixture
def test_setup(db_session: Session):
    """Sets up primary user Alice, secondary user Mallory, repository, finding, and scan."""
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
        name="alice/crypto-vault",
        default_branch="main",
    )
    db_session.add(repo_alice)
    db_session.flush()

    scan_alice = Scan(
        id=f"scan_{uuid.uuid4().hex[:8]}",
        repository_id=repo_alice.id,
        commit_sha="a1b2c3d4e5f678901234567890abcdef12345678",
        status="completed",
    )
    db_session.add(scan_alice)
    db_session.flush()

    finding_alice = SecurityFinding(
        id=f"FIND_AUTH_{uuid.uuid4().hex[:6]}",
        repo_id=repo_alice.id,
        scanner_name="Semgrep OSS",
        rule_identifier="python.jwt.weak-secret",
        cwe="CWE-327",
        title="Hardcoded JWT Secret Key",
        severity="HIGH",
        confidence="HIGH",
        file_path="src/security/jwt.py",
        line_number=42,
        code_excerpt="secret = 'supersecret123'\ntoken = jwt.encode(payload, secret)\n",
    )
    db_session.add(finding_alice)
    db_session.commit()

    token_alice = create_access_token({"sub": user_alice.id, "email": user_alice.email})
    token_mallory = create_access_token({"sub": user_mallory.id, "email": user_mallory.email})

    return {
        "user_alice": user_alice,
        "user_mallory": user_mallory,
        "token_alice": token_alice,
        "token_mallory": token_mallory,
        "repo": repo_alice,
        "scan": scan_alice,
        "finding": finding_alice,
    }


def test_secret_redaction_comprehensive():
    """Requirement 8: Redaction of secrets in reports, payloads, and logs."""
    raw_snippet = """
    # Leaked AWS Key
    aws_key = AKIAIOSFODNN7EXAMPLE
    # Leaked GitHub Classic PAT
    gh_pat = ghp_123456789012345678901234567890123456
    # Leaked GitHub Fine-Grained Token
    gh_fine = github_pat_11AEXAMPLE0123456789abcdefghijklmnopqrstuvwxyz0123456789
    # Leaked Stripe API Key
    stripe_key = FAKE_STRIPE_KEY_FOR_TESTING_ONLY
    # Leaked Bearer Header
    auth_header = Bearer mysecrettoken1234567890abcdef
    # Standalone JWT Token
    jwt_token = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMC6Y9ncOckeNjfw
    # Leaked Webhook Secret
    wh_secret = whsec_abcdefghijklmnopqrstuvwxyz012345
    # Database connection string
    db_uri = postgres://admin:SuperSecretPassword123@db.prod.internal:5432/core
    """
    sanitized = sanitize_evidence_text(raw_snippet)

    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
    assert "[REDACTED_AWS_KEY]" in sanitized
    assert "ghp_123456789012345678901234567890123456" not in sanitized
    assert "[REDACTED_GITHUB_TOKEN]" in sanitized
    assert "github_pat_11AEXAMPLE" not in sanitized
    assert "[REDACTED_GITHUB_PAT]" in sanitized
    assert "FAKE_STRIPE_KEY_FOR_TESTING_ONLY" not in sanitized
    assert "[REDACTED_API_KEY]" in sanitized
    assert "[REDACTED_BEARER_TOKEN]" in sanitized
    assert "[REDACTED_JWT_TOKEN]" in sanitized
    assert "whsec_abcdef" not in sanitized
    assert "[REDACTED_WEBHOOK_SECRET]" in sanitized
    assert "SuperSecretPassword123" not in sanitized
    assert "[REDACTED_DB_PASSWORD]" in sanitized



def test_cross_user_access_control(client: TestClient, test_setup, db_session: Session):
    """Requirement 1 & 10: Multi-tenant authorization boundaries prevent cross-user inspection."""
    token_alice = test_setup["token_alice"]
    token_mallory = test_setup["token_mallory"]
    repo = test_setup["repo"]

    # Alice records evidence
    ev = record_security_evidence(
        db=db_session,
        repository_id=repo.id,
        evidence_category="patch_diff",
        title="Sanitized Diff",
        tool_name="git",
        raw_payload="diff --git a/src.py b/src.py\n+ safe_code()",
    )

    # Mallory attempts to retrieve Alice's evidence
    # 1. Direct GET evidence
    resp = client.get(
        f"/api/v1/evidence/{ev.id}",
        headers={"Authorization": f"Bearer {token_mallory}"},
    )
    assert resp.status_code == 403

    # 2. Check evidence integrity
    resp = client.get(
        f"/api/v1/evidence/{ev.id}/verify-integrity",
        headers={"Authorization": f"Bearer {token_mallory}"},
    )
    assert resp.status_code == 403

    # 3. List repository evidence
    resp = client.get(
        f"/api/v1/evidence?repo_id={repo.id}",
        headers={"Authorization": f"Bearer {token_mallory}"},
    )
    assert resp.status_code == 403

    # Alice accessing her own evidence succeeds
    resp_alice = client.get(
        f"/api/v1/evidence/{ev.id}",
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert resp_alice.status_code == 200
    assert resp_alice.json()["id"] == ev.id


def test_evidence_integrity_and_tamper_detection(client: TestClient, test_setup, db_session: Session):
    """Requirement 9: Detection of accidental evidence modification with authenticity disclaimer."""
    token_alice = test_setup["token_alice"]
    repo = test_setup["repo"]

    # Record evidence
    ev = record_security_evidence(
        db=db_session,
        repository_id=repo.id,
        evidence_category="test_result",
        title="Unit Test Results",
        tool_name="pytest",
        raw_payload={"status": "passed", "duration_ms": 142},
    )

    # 1. Verify intact evidence
    resp = client.get(
        f"/api/v1/evidence/{ev.id}/verify-integrity",
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_intact"] is True
    assert data["status"] == "VALID"
    assert data["stored_hash"] == ev.content_hash
    assert data["computed_hash"] == ev.content_hash
    assert AUTHENTICITY_DISCLAIMER in data["disclaimer"]

    # 2. Simulate accidental in-place modification/corruption
    ev_row = db_session.query(SecurityEvidence).filter(SecurityEvidence.id == ev.id).first()
    ev_row.sanitized_payload = json.dumps({"status": "passed", "duration_ms": 99999})
    db_session.commit()

    resp_corrupt = client.get(
        f"/api/v1/evidence/{ev.id}/verify-integrity",
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert resp_corrupt.status_code == 200
    corrupt_data = resp_corrupt.json()
    assert corrupt_data["is_intact"] is False
    assert corrupt_data["status"] == "MODIFIED"
    assert corrupt_data["stored_hash"] != corrupt_data["computed_hash"]

    # 3. Verify audit log captures tamper detection
    tamper_audit = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.action == "EVIDENCE_TAMPER_DETECTED", AuditEvent.resource_identifier == ev.id)
        .first()
    )
    assert tamper_audit is not None


def test_verification_report_14_mandatory_fields_and_formats(client: TestClient, test_setup, db_session: Session):
    """Requirement 6 & All 14 Verification Report Mandatory Identifiers."""
    alice = test_setup["user_alice"]
    token_alice = test_setup["token_alice"]
    repo = test_setup["repo"]
    finding = test_setup["finding"]

    patch_diff = (
        "--- a/src/security/jwt.py\n"
        "+++ b/src/security/jwt.py\n"
        "@@ -42,2 +42,2 @@\n"
        "-secret = 'supersecret123'\n"
        "+secret = os.environ.get('JWT_SECRET')\n"
    )
    req = VerificationRunRequest(
        finding_id=finding.id,
        proposed_patch=patch_diff,
        scanner_names=["semgrep"],
        scanner_config={"rules": ["python.jwt"]},
        run_existing_tests=False,
        run_regression_tests=False,
    )

    with patch("backend.app.verification.service.run_scanners_on_directory") as mock_scan:
        mock_scan.side_effect = [
            ([finding], {"semgrep": {"version": "1.78.0"}}, []),  # baseline
            ([], {"semgrep": {"version": "1.78.0"}}, [])             # patched
        ]
        vr_res = execute_fix_verification(request=req, db=db_session, user_id=alice.id)

    assert vr_res.id.startswith("vr_")

    # 1. Test Markdown Report
    md_resp = client.get(
        f"/api/v1/evidence/reports/verification/{vr_res.id}?format=markdown",
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert md_resp.status_code == 200
    md_content = md_resp.json()["content"]

    # Verify all 14 mandatory fields in Markdown:
    assert finding.id in md_content  # 1. Original finding
    assert repo.name in md_content  # 2. Repository & source revision
    assert "jwt.py" in md_content  # 3. Proposed patch
    assert "semgrep" in md_content.lower() or "scanner" in md_content.lower()  # 4. Scanner names & versions
    assert "active_config" in md_content  # 5. Scanner configuration
    assert "Suites Executed" in md_content  # 6. Tests executed
    assert "Test Results Breakdown" in md_content  # 7. Test results
    assert "Baseline Findings Observed" in md_content  # 8. Findings before and after patch
    assert "New Findings Detected" in md_content  # 9. New findings detected
    assert "Missing or Unavailable Checks" in md_content  # 10. Missing or unavailable checks
    assert vr_res.status.value in md_content  # 11. Final verification status
    assert "Status Explanation & Rationale" in md_content  # 12. Explanation supporting status
    assert "Report Generated At" in md_content  # 13. Timestamp
    assert "Relevant Evidence References" in md_content  # 14. Relevant evidence references

    # Strict separation between raw tool evidence and AI-generated interpretation
    assert "## 6. Authoritative Raw Tool Evidence" in md_content
    assert "## 7. AI-Generated Interpretation (Advisory Only - Non-Authoritative)" in md_content
    assert AUTHENTICITY_DISCLAIMER in md_content

    # 2. Test JSON Report format
    json_resp = client.get(
        f"/api/v1/evidence/reports/verification/{vr_res.id}?format=json",
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert json_resp.status_code == 200
    json_data = json.loads(json_resp.json()["content"])

    assert "1_original_finding" in json_data
    assert "2_repository_and_source_revision" in json_data
    assert "3_proposed_patch" in json_data
    assert "4_scanner_names_and_versions" in json_data
    assert "5_scanner_configuration" in json_data
    assert "6_tests_executed" in json_data
    assert "7_test_results" in json_data
    assert "8_findings_before_and_after_patch" in json_data
    assert "9_new_findings_detected" in json_data
    assert "10_missing_or_unavailable_checks" in json_data
    assert "11_final_verification_status" in json_data
    assert "12_explanation_supporting_status" in json_data
    assert "13_timestamp" in json_data
    assert "14_relevant_evidence_references" in json_data
    assert "raw_evidence" in json_data
    assert "ai_interpretation" in json_data
    assert AUTHENTICITY_DISCLAIMER in json_data["authenticity_disclaimer"]

    # 3. Test SARIF 2.1.0 Report format
    sarif_resp = client.get(
        f"/api/v1/evidence/reports/verification/{vr_res.id}?format=sarif",
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert sarif_resp.status_code == 200
    sarif_data = json.loads(sarif_resp.json()["content"])
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"]) > 0
    run_props = sarif_data["runs"][0]["properties"]
    assert run_props["verification_run_id"] == vr_res.id
    assert run_props["final_verification_status"] == vr_res.status.value
    assert AUTHENTICITY_DISCLAIMER in run_props["authenticity_disclaimer"]


def test_downloadable_report_attachments(client: TestClient, test_setup, db_session: Session):
    """Requirement 6: Downloadable reports with Content-Disposition attachment header."""
    token_alice = test_setup["token_alice"]
    repo = test_setup["repo"]
    finding = test_setup["finding"]

    # Create a verification run
    vr = VerificationRun(
        id=f"vr_down_{uuid.uuid4().hex[:8]}",
        finding_id=finding.id,
        status="VERIFIED_AGAINST_DEFINED_CHECKS",
        baseline_hash="sha256:baseline123",
        patched_hash="sha256:patched456",
        source_revision="main",
        original_finding_status="resolved",
        patch_diff="--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n- bad\n+ good",
    )
    db_session.add(vr)
    db_session.commit()

    # 1. Download Markdown
    resp_md = client.get(
        f"/api/v1/evidence/reports/verification/{vr.id}/download?format=markdown",
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert resp_md.status_code == 200
    assert "attachment;" in resp_md.headers["Content-Disposition"]
    assert f"verification_report_{vr.id}.md" in resp_md.headers["Content-Disposition"]
    assert "text/markdown" in resp_md.headers["Content-Type"]

    # 2. Download JSON
    resp_json = client.get(
        f"/api/v1/evidence/reports/verification/{vr.id}/download?format=json",
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert resp_json.status_code == 200
    assert "attachment;" in resp_json.headers["Content-Disposition"]
    assert f"verification_report_{vr.id}.json" in resp_json.headers["Content-Disposition"]
    assert "application/json" in resp_json.headers["Content-Type"]

    # 3. Download SARIF
    resp_sarif = client.get(
        f"/api/v1/evidence/reports/verification/{vr.id}/download?format=sarif",
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert resp_sarif.status_code == 200
    assert "attachment;" in resp_sarif.headers["Content-Disposition"]
    assert f"verification_report_{vr.id}.sarif" in resp_sarif.headers["Content-Disposition"]
    assert "application/sarif+json" in resp_sarif.headers["Content-Type"]

    # 4. Download Findings Report
    resp_find = client.get(
        f"/api/v1/evidence/reports/findings/download?repo_id={repo.id}&format=markdown",
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert resp_find.status_code == 200
    assert "attachment;" in resp_find.headers["Content-Disposition"]
    assert f"findings_report_{repo.id}.md" in resp_find.headers["Content-Disposition"]


def test_preservation_of_failed_and_inconclusive_verification_runs(test_setup, db_session: Session):
    """Core Axiom: Preserve failed and inconclusive runs rather than replacing with a later result."""
    alice = test_setup["user_alice"]
    finding = test_setup["finding"]

    # 1. First run: Fails due to invalid patch syntax
    req_bad = VerificationRunRequest(
        finding_id=finding.id,
        proposed_patch="INVALID MALFORMED DIFF",
        scanner_names=["semgrep"],
    )
    res_bad = execute_fix_verification(request=req_bad, db=db_session, user_id=alice.id)
    assert res_bad.status == VerificationStatus.INCONCLUSIVE

    # 2. Second run: Ineffective fix that still leaves the vulnerability
    ineffective_diff = (
        "--- a/src/security/jwt.py\n"
        "+++ b/src/security/jwt.py\n"
        "@@ -42,2 +42,2 @@\n"
        "-secret = 'supersecret123'\n"
        "+secret = 'supersecret456'\n"
    )
    req_ineffective = VerificationRunRequest(
        finding_id=finding.id,
        proposed_patch=ineffective_diff,
        scanner_names=["semgrep"],
        run_existing_tests=False,
        run_regression_tests=False,
    )
    with patch("backend.app.verification.service.run_scanners_on_directory") as mock_scan:
        mock_scan.side_effect = [
            ([finding], {"semgrep": {"version": "1.78.0"}}, []),
            ([finding], {"semgrep": {"version": "1.78.0"}}, []),
        ]
        res_ineffective = execute_fix_verification(request=req_ineffective, db=db_session, user_id=alice.id)

    # The run has distinct ID
    assert res_ineffective.id != res_bad.id

    # 3. Third run: Effective fix
    effective_diff = (
        "--- a/src/security/jwt.py\n"
        "+++ b/src/security/jwt.py\n"
        "@@ -42,2 +42,2 @@\n"
        "-secret = 'supersecret123'\n"
        "+secret = os.environ.get('JWT_SECRET_KEY')\n"
    )
    req_effective = VerificationRunRequest(
        finding_id=finding.id,
        proposed_patch=effective_diff,
        scanner_names=["semgrep"],
        run_existing_tests=False,
        run_regression_tests=False,
    )
    with patch("backend.app.verification.service.run_scanners_on_directory") as mock_scan:
        mock_scan.side_effect = [
            ([finding], {"semgrep": {"version": "1.78.0"}}, []),
            ([], {"semgrep": {"version": "1.78.0"}}, []),
        ]
        res_effective = execute_fix_verification(request=req_effective, db=db_session, user_id=alice.id)

    assert res_effective.id != res_ineffective.id
    assert res_effective.id != res_bad.id

    # Query all verification runs for finding: All 3 runs MUST be preserved!
    all_runs = (
        db_session.query(VerificationRun)
        .filter(VerificationRun.finding_id == finding.id)
        .order_by(VerificationRun.started_at.asc())
        .all()
    )
    run_ids = [r.id for r in all_runs]
    assert res_bad.id in run_ids
    assert res_ineffective.id in run_ids
    assert res_effective.id in run_ids
    assert len(all_runs) >= 3


def test_verification_run_integrity_check(client: TestClient, test_setup, db_session: Session):
    """Requirement 9: Verification run record integrity check endpoint."""
    alice = test_setup["user_alice"]
    token_alice = test_setup["token_alice"]
    finding = test_setup["finding"]

    req = VerificationRunRequest(
        finding_id=finding.id,
        proposed_patch="--- a/src/security/jwt.py\n+++ b/src/security/jwt.py\n@@ -1 +1 @@\n- a\n+ b",
        run_existing_tests=False,
        run_regression_tests=False,
    )
    with patch("backend.app.verification.service.run_scanners_on_directory") as mock_scan:
        mock_scan.side_effect = [
            ([finding], {"semgrep": {"version": "1.78.0"}}, []),
            ([], {"semgrep": {"version": "1.78.0"}}, []),
        ]
        vr_res = execute_fix_verification(request=req, db=db_session, user_id=alice.id)

    # Verify run integrity via endpoint
    resp = client.get(
        f"/api/v1/evidence/verification-runs/{vr_res.id}/verify-integrity",
        headers={"Authorization": f"Bearer {token_alice}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_intact"] is True
    assert data["status"] == "VALID"
    assert AUTHENTICITY_DISCLAIMER in data["disclaimer"]
