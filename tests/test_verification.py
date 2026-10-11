"""Comprehensive Automated Test Suite for Fix Verification Engine.

Tests:
1. Safe patch parsing, file/line calculation, and path traversal rejection.
2. Isolated disposable workspace creation, secret sanitization, and cleanup.
3. Baseline establishment (SHA-256 hashes, scanner configurations).
4. Successful verification with real test pass (VERIFIED_AGAINST_DEFINED_CHECKS).
5. Failed verification when original finding persists (FAILED_VERIFICATION).
6. Failed verification when patch introduces new findings / regressions (FAILED_VERIFICATION).
7. Failed verification when unit or regression tests fail (FAILED_VERIFICATION).
8. Inconclusive status when patch is invalid or context lines mismatch (INCONCLUSIVE).
9. Rule invariant: "VERIFIED_AGAINST_DEFINED_CHECKS" is NEVER used if checks fail or are skipped.
10. Limitations and missing evidence explicitly recorded.
11. Audit logging and immutable preservation of original scanner finding.
"""
from datetime import datetime
import json
from pathlib import Path
import pytest
from unittest.mock import MagicMock, patch

from app.models.finding import SecurityFinding
from app.models.repository import Repository
from app.models.user import User
from app.models.verification import VerificationRun, VerificationEvidence
from app.core.security import create_access_token, hash_password
from app.schemas.verification import (
    ClassifiedFinding,
    FindingRegressionClassification,
    VerificationRunRequest,
    VerificationStatus,
)
from app.verification.patch_parser import parse_unified_diff, sanitize_patch_path
from app.verification.patch_applier import apply_patch_to_workspace
from app.verification.workspace import (
    create_verification_workspace,
    calculate_directory_hash,
    get_sanitized_runner_env,
)
from app.verification.comparator import compare_verification_findings
from app.verification.service import execute_fix_verification
from app.scanner.base import NormalizedFinding


# Sample patch fixtures
VALID_SQLI_PATCH = """--- a/auth_gateway/dao/user_query.py
+++ b/auth_gateway/dao/user_query.py
@@ -1,5 +1,5 @@
 def get_user_by_tenant(cursor, tenant_id: str, email: str):
-    cursor.execute(f"SELECT * FROM users WHERE tenant_id = '{tenant_id}' AND email = '{email}'")
+    cursor.execute("SELECT * FROM users WHERE tenant_id = %s AND email = %s", (tenant_id, email))
     return cursor.fetchone()
"""

INEFFECTIVE_SQLI_PATCH = """--- a/auth_gateway/dao/user_query.py
+++ b/auth_gateway/dao/user_query.py
@@ -1,5 +1,6 @@
 def get_user_by_tenant(cursor, tenant_id: str, email: str):
-    cursor.execute(f"SELECT * FROM users WHERE tenant_id = '{tenant_id}' AND email = '{email}'")
+    tid = str(tenant_id)
+    cursor.execute(f"SELECT * FROM users WHERE tenant_id = '{tid}' AND email = '{email}'")
     return cursor.fetchone()
"""

REGRESSION_PATCH = """--- a/auth_gateway/dao/user_query.py
+++ b/auth_gateway/dao/user_query.py
@@ -1,5 +1,7 @@
+API_KEY = "AKIAIOSFODNN7EXAMPLE"
 def get_user_by_tenant(cursor, tenant_id: str, email: str):
-    cursor.execute(f"SELECT * FROM users WHERE tenant_id = '{tenant_id}' AND email = '{email}'")
+    cursor.execute("SELECT * FROM users WHERE tenant_id = %s AND email = %s", (tenant_id, email))
     return cursor.fetchone()
"""

TRAVERSAL_PATCH = """--- a/../../../../etc/passwd
+++ b/../../../../etc/passwd
@@ -1,1 +1,1 @@
-root:x:0:0
+root:pwned:0:0
"""


# -------------------------------------------------------------------------
# 1. Patch Parsing & Security Guardrail Tests
# -------------------------------------------------------------------------
def test_patch_parsing_valid():
    """Verify clean unified diff parsing and accurate line modifications."""
    res = parse_unified_diff(VALID_SQLI_PATCH)
    assert res.is_valid is True
    assert len(res.files) == 1
    assert res.files[0].new_path == "auth_gateway/dao/user_query.py"
    assert res.total_added == 1
    assert res.total_deleted == 1
    assert "L1-" in res.files[0].modified_lines_range


def test_patch_parsing_rejects_path_traversal():
    """Verify rejection of directory traversal attempts in patch headers."""
    res = parse_unified_diff(TRAVERSAL_PATCH)
    assert res.is_valid is False
    assert any("traversal" in err.lower() for err in res.errors)

    # Direct sanitizer check
    path, err = sanitize_patch_path("../../var/secret.key")
    assert path is None
    assert "traversal" in err.lower()

    path_abs, err_abs = sanitize_patch_path("/etc/shadow")
    assert path_abs is None
    assert "traversal" in err_abs.lower() or "absolute" in err_abs.lower()


def test_patch_parsing_empty_or_corrupt():
    """Verify rejection of empty or malformed diffs."""
    res_empty = parse_unified_diff("   \n  ")
    assert res_empty.is_valid is False
    assert "empty" in res_empty.errors[0].lower()

    res_corrupt = parse_unified_diff("random unformatted text without diff headers")
    assert res_corrupt.is_valid is False


# -------------------------------------------------------------------------
# 2. Workspace Isolation & Secret Stripping Tests
# -------------------------------------------------------------------------
def test_workspace_isolation_and_secret_stripping(monkeypatch):
    """Verify runner environment strips secrets and isolates directories."""
    monkeypatch.setenv("GEMINI_API_KEY", "secret-gemini-key")
    monkeypatch.setenv("SECRET_KEY", "appsec-top-secret")
    monkeypatch.setenv("NORMAL_VAR", "safe_val")

    clean_env = get_sanitized_runner_env()
    assert "GEMINI_API_KEY" not in clean_env
    assert "SECRET_KEY" not in clean_env
    assert clean_env.get("NORMAL_VAR") == "safe_val"
    assert clean_env.get("PIP_NO_INDEX") == "1"

    # Workspace creation and cleanup
    files = {"src/app.py": "print('hello')\n"}
    ws = create_verification_workspace(synthetic_files=files)
    assert ws.workspace_dir.exists()
    assert (ws.workspace_dir / "src" / "app.py").exists()
    assert len(ws.baseline_hash) == 64

    ws_dir = ws.workspace_dir
    ws.cleanup()
    assert not ws_dir.exists()


# -------------------------------------------------------------------------
# 3. Patch Application in Isolated Workspace
# -------------------------------------------------------------------------
def test_patch_application_safe():
    """Verify patch applies cleanly inside isolated workspace without escaping."""
    original_code = (
        'def get_user_by_tenant(cursor, tenant_id: str, email: str):\n'
        '    cursor.execute(f"SELECT * FROM users WHERE tenant_id = \'{tenant_id}\' AND email = \'{email}\'")\n'
        '    return cursor.fetchone()\n'
    )
    ws = create_verification_workspace(synthetic_files={"auth_gateway/dao/user_query.py": original_code})
    try:
        parsed = parse_unified_diff(VALID_SQLI_PATCH)
        success, errors = apply_patch_to_workspace(ws.workspace_dir, parsed)
        assert success is True
        assert len(errors) == 0

        # Read modified code
        patched_code = (ws.workspace_dir / "auth_gateway" / "dao" / "user_query.py").read_text(encoding="utf-8")
        assert "%s" in patched_code
        assert "f\"SELECT" not in patched_code

        # Hash must have changed
        patched_hash = calculate_directory_hash(ws.workspace_dir)
        assert patched_hash != ws.baseline_hash
    finally:
        ws.cleanup()


# -------------------------------------------------------------------------
# 4. End-to-End Fix Verification Workflow Tests
# -------------------------------------------------------------------------
@pytest.fixture
def test_finding(db_session):
    """Fixture providing a persistent SecurityFinding."""
    repo = db_session.query(Repository).filter(Repository.id == "repo-verify-test-01").first()
    if not repo:
        repo = Repository(
            id="repo-verify-test-01",
            owner_id="usr-dev-seed-001",
            name="xerova/test-gateway",
            default_branch="main",
            health_score=80,
        )
        db_session.add(repo)
        db_session.commit()

    f = db_session.query(SecurityFinding).filter(SecurityFinding.id == "FIND-VERIFY-101").first()
    if not f:
        f = SecurityFinding(
            id="FIND-VERIFY-101",
            repo_id=repo.id,
            cwe="CWE-89: SQL Injection",
            title="Raw string formatting in SQL query",
            severity="HIGH",
            scanner_name="Semgrep OSS",
            file_path="auth_gateway/dao/user_query.py",
            line_number=2,
            rule_identifier="python.sqlalchemy.security.audit.raw-sql-format",
            code_excerpt=(
                'def get_user_by_tenant(cursor, tenant_id: str, email: str):\n'
                '    cursor.execute(f"SELECT * FROM users WHERE tenant_id = \'{tenant_id}\' AND email = \'{email}\'")\n'
                '    return cursor.fetchone()\n'
            )
        )
        db_session.add(f)
        db_session.commit()
    db_session.refresh(f)
    return f


def test_successful_fix_verification(db_session, test_finding):
    """Verify successful verification produces VERIFIED_AGAINST_DEFINED_CHECKS."""
    req = VerificationRunRequest(
        finding_id=test_finding.id,
        proposed_patch=VALID_SQLI_PATCH,
        run_existing_tests=False,
        run_regression_tests=False,
        timeout_seconds=30
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        # Baseline scan has finding; patched scan has NO findings
        baseline_f = NormalizedFinding(
            scanner_name="Semgrep OSS",
            scanner_rule_id="python.sqlalchemy.security.audit.raw-sql-format",
            vulnerability_category="CWE-89: SQL Injection",
            file_path="auth_gateway/dao/user_query.py",
            start_line=2,
            severity="HIGH"
        )
        mock_scan.side_effect = [
            ([baseline_f], {"semgrep": {"version": "1.78.0"}}, []),  # baseline
            ([], {"semgrep": {"version": "1.78.0"}}, [])             # patched
        ]

        result = execute_fix_verification(req, db=db_session)

        assert result.status == VerificationStatus.VERIFIED_AGAINST_DEFINED_CHECKS
        assert result.original_finding_status == "resolved"
        assert len(result.new_findings) == 0
        assert result.baseline_hash is not None
        assert result.patched_hash is not None
        assert result.baseline_hash != result.patched_hash

        # Standard limitations must be included
        assert len(result.limitations) >= 4
        assert any("disappearing does not prove" in lim for lim in result.limitations)


def test_failed_verification_persisting_finding(db_session, test_finding):
    """Verify ineffective patch that leaves vulnerability intact produces FAILED_VERIFICATION."""
    req = VerificationRunRequest(
        finding_id=test_finding.id,
        proposed_patch=INEFFECTIVE_SQLI_PATCH,
        run_existing_tests=False,
        run_regression_tests=False,
        timeout_seconds=30
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        fnd = NormalizedFinding(
            scanner_name="Semgrep OSS",
            scanner_rule_id="python.sqlalchemy.security.audit.raw-sql-format",
            vulnerability_category="CWE-89: SQL Injection",
            file_path="auth_gateway/dao/user_query.py",
            start_line=3,
            severity="HIGH"
        )
        # Finding is present in both baseline and patched!
        mock_scan.side_effect = [
            ([fnd], {"semgrep": {"version": "1.78.0"}}, []),
            ([fnd], {"semgrep": {"version": "1.78.0"}}, [])
        ]

        result = execute_fix_verification(req, db=db_session)

        assert result.status == VerificationStatus.FAILED_VERIFICATION
        assert result.original_finding_status == "persisting"
        assert any("remains reported" in r for r in result.reasons)


def test_failed_verification_regression_introduced(db_session, test_finding):
    """Verify patch introducing a new finding / regression produces FAILED_VERIFICATION."""
    req = VerificationRunRequest(
        finding_id=test_finding.id,
        proposed_patch=REGRESSION_PATCH,
        run_existing_tests=False,
        run_regression_tests=False,
        timeout_seconds=30
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        old_fnd = NormalizedFinding(
            scanner_name="Semgrep OSS",
            scanner_rule_id="python.sqlalchemy.security.audit.raw-sql-format",
            vulnerability_category="CWE-89: SQL Injection",
            file_path="auth_gateway/dao/user_query.py",
            start_line=2,
            severity="HIGH"
        )
        # Patched resolves SQLi but introduces hardcoded secret
        reg_fnd = NormalizedFinding(
            scanner_name="Gitleaks",
            scanner_rule_id="gitleaks.aws-access-key",
            vulnerability_category="CWE-798: Hardcoded Credentials",
            file_path="auth_gateway/dao/user_query.py",
            start_line=1,
            severity="CRITICAL",
            scanner_message="Hardcoded AWS access key detected"
        )
        mock_scan.side_effect = [
            ([old_fnd], {"semgrep": {"version": "1.78.0"}}, []),
            ([reg_fnd], {"semgrep": {"version": "1.78.0"}, "gitleaks": {"version": "8.18.0"}}, [])
        ]

        result = execute_fix_verification(req, db=db_session)

        assert result.status == VerificationStatus.FAILED_VERIFICATION
        assert len(result.new_findings) == 1
        assert result.new_findings[0]["rule_id"] == "gitleaks.aws-access-key"
        assert any("regression" in r.lower() for r in result.reasons)


def test_failed_verification_when_regression_test_fails(db_session, test_finding):
    """Verify that a failing security regression test prevents verified status."""
    failing_regression_test_code = """
def test_security_regression():
    assert False, "Regression test assertion failed!"
"""
    req = VerificationRunRequest(
        finding_id=test_finding.id,
        proposed_patch=VALID_SQLI_PATCH,
        run_existing_tests=False,
        run_regression_tests=True,
        regression_test_code=failing_regression_test_code,
        timeout_seconds=30
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        # Scanner shows resolved, BUT regression test fails!
        baseline_f = NormalizedFinding(
            scanner_name="Semgrep OSS",
            scanner_rule_id="python.sqlalchemy.security.audit.raw-sql-format",
            vulnerability_category="CWE-89: SQL Injection",
            file_path="auth_gateway/dao/user_query.py",
            start_line=2,
            severity="HIGH"
        )
        mock_scan.side_effect = [
            ([baseline_f], {}, []),
            ([], {}, [])
        ]

        result = execute_fix_verification(req, db=db_session)

        # Invariant: Disappearing scanner finding + FAILING test MUST NOT be VERIFIED!
        assert result.status == VerificationStatus.FAILED_VERIFICATION
        assert "targeted_security_regression_test" in result.tests_executed
        assert result.test_results["targeted_security_regression_test"]["status"] == "failed"


def test_inconclusive_on_path_traversal(db_session, test_finding):
    """Verify that malicious patch diff results in INCONCLUSIVE without executing tests."""
    req = VerificationRunRequest(
        finding_id=test_finding.id,
        proposed_patch=TRAVERSAL_PATCH,
        timeout_seconds=30
    )

    result = execute_fix_verification(req, db=db_session)
    assert result.status == VerificationStatus.INCONCLUSIVE
    assert len(result.execution_errors) > 0
    assert any("traversal" in err.lower() for err in result.execution_errors)


def test_verification_api_endpoints(client, test_finding, db_session):
    """Verify REST API endpoints for verifications including authorization."""
    # Ensure owner user exists in db
    dev_user = db_session.query(User).filter(User.id == "usr-dev-seed-001").first()
    if not dev_user:
        dev_user = User(
            id="usr-dev-seed-001",
            email="dev@xerova.com",
            password_hash=hash_password("DevPassword123!"),
            account_status="active"
        )
        db_session.add(dev_user)
        db_session.commit()

    token = create_access_token({"sub": "usr-dev-seed-001", "email": "dev@xerova.com"})
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Pre-validation endpoint
    val_res = client.post(
        "/api/v1/verifications/validate-patch",
        json={"proposed_patch": VALID_SQLI_PATCH},
        headers=headers,
    )
    assert val_res.status_code == 200
    val_data = val_res.json()
    assert val_data["is_valid"] is True
    assert len(val_data["files"]) == 1

    # 2. Trigger verification endpoint as owner
    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        baseline_f = NormalizedFinding(
            scanner_name="Semgrep OSS",
            scanner_rule_id="python.sqlalchemy.security.audit.raw-sql-format",
            vulnerability_category="CWE-89: SQL Injection",
            file_path="auth_gateway/dao/user_query.py",
            start_line=2,
            severity="HIGH",
        )
        mock_scan.side_effect = [([baseline_f], {"semgrep": {"version": "1.78.0"}}, []), ([], {"semgrep": {"version": "1.78.0"}}, [])]
        trigger_res = client.post(
            "/api/v1/verifications",
            json={
                "finding_id": test_finding.id,
                "proposed_patch": VALID_SQLI_PATCH,
                "run_existing_tests": False,
                "run_regression_tests": False
            },
            headers=headers,
        )
        assert trigger_res.status_code == 200
        run_data = trigger_res.json()
        run_id = run_data["id"]
        assert run_data["finding_id"] == test_finding.id

    # 3. List verifications as owner
    list_res = client.get(f"/api/v1/verifications?finding_id={test_finding.id}", headers=headers)
    assert list_res.status_code == 200
    runs = list_res.json()
    assert len(runs) >= 1
    assert runs[0]["id"] == run_id

    # 4. Get verification details as owner
    get_res = client.get(f"/api/v1/verifications/{run_id}", headers=headers)
    assert get_res.status_code == 200
    detail = get_res.json()
    assert detail["id"] == run_id
    assert "limitations" in detail
    assert len(detail["limitations"]) > 0

    # 5. Security Check: Unauthenticated request rejected with 401
    unauth_res = client.get(f"/api/v1/verifications/{run_id}")
    assert unauth_res.status_code == 401

    # 6. Security Check: Cross-tenant request rejected with 403 Forbidden
    other_user = User(
        id="usr-cross-tenant-attacker",
        email="attacker@external.com",
        password_hash=hash_password("AttackPass123!"),
        account_status="active"
    )
    db_session.add(other_user)
    db_session.commit()
    other_token = create_access_token({"sub": other_user.id, "email": other_user.email})
    other_headers = {"Authorization": f"Bearer {other_token}"}

    cross_get_res = client.get(f"/api/v1/verifications/{run_id}", headers=other_headers)
    assert cross_get_res.status_code == 403

    cross_trigger_res = client.post(
        "/api/v1/verifications",
        json={
            "finding_id": test_finding.id,
            "proposed_patch": VALID_SQLI_PATCH,
            "run_existing_tests": False,
            "run_regression_tests": False
        },
        headers=other_headers,
    )
    assert cross_trigger_res.status_code == 403


def test_inconclusive_when_baseline_vulnerability_not_observed(db_session, test_finding):
    """Verify that if scanner fails to detect baseline finding, result is INCONCLUSIVE (never falsely VERIFIED)."""
    req = VerificationRunRequest(
        finding_id=test_finding.id,
        proposed_patch=VALID_SQLI_PATCH,
        run_existing_tests=False,
        run_regression_tests=False,
        timeout_seconds=30
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        # Scanner reports no findings in baseline and no findings in patched
        mock_scan.side_effect = [
            ([], {"semgrep": {"version": "1.78.0"}}, []),
            ([], {"semgrep": {"version": "1.78.0"}}, [])
        ]

        result = execute_fix_verification(req, db=db_session)

        # Invariant: Must NOT falsely claim VERIFIED_AGAINST_DEFINED_CHECKS!
        assert result.status == VerificationStatus.INCONCLUSIVE
        assert result.original_finding_status == "untested"
        assert len(result.missing_evidence) > 0
        assert any("baseline" in ev.lower() for ev in result.missing_evidence)


def test_pytest_runner_option_injection_and_path_traversal_blocked(tmp_path):
    """Verify that run_pytest_in_workspace rejects malicious test_target flags and traversal."""
    from app.verification.runner import run_pytest_in_workspace
    
    # 1. Option injection starting with '-'
    outcome_opt = run_pytest_in_workspace(tmp_path, test_target="-o log_cli=true")
    assert outcome_opt.status == "error"
    assert "option injection" in outcome_opt.error_message.lower()

    # 2. Path traversal escaping workspace
    outcome_trav = run_pytest_in_workspace(tmp_path, test_target="../../etc/passwd")
    assert outcome_trav.status == "error"
    assert "traversal" in outcome_trav.error_message.lower()


# -------------------------------------------------------------------------
# 4. Regression Analysis & 6-Status Classification Tests
# -------------------------------------------------------------------------
def test_regression_analysis_all_six_finding_classifications():
    """Directly test that compare_verification_findings accurately classifies all 6 statuses:
    NEW, RESOLVED_BY_DEFINED_CHECKS, STILL_PRESENT, UNCHANGED, POTENTIALLY_REGRESSED, INCOMPARABLE.
    """
    target_rule = "python.sqlalchemy.security.audit.raw-sql-format"
    target_category = "CWE-89: SQL Injection"
    target_file = "auth_gateway/dao/user_query.py"
    target_line = 10

    # 1. Baseline Findings:
    # - b1: target finding in modified file
    # - b2: unrelated finding in unmodified file "src/utils.py"
    # - b3: finding in modified file that will shift lines (partial fix / mutation)
    b1 = NormalizedFinding(
        scanner_name="Semgrep OSS",
        scanner_rule_id=target_rule,
        vulnerability_category=target_category,
        file_path=target_file,
        start_line=10,
        severity="HIGH",
        scanner_message="Raw SQL format string detected",
    )
    b2 = NormalizedFinding(
        scanner_name="Bandit",
        scanner_rule_id="B303",
        vulnerability_category="CWE-327: Use of Broken or Risky Cryptographic Algorithm",
        file_path="src/utils.py",
        start_line=45,
        severity="MEDIUM",
        scanner_message="Use of MD5 hash detected",
    )
    b3 = NormalizedFinding(
        scanner_name="Semgrep OSS",
        scanner_rule_id="python.lang.security.audit.exec-used",
        vulnerability_category="CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
        file_path=target_file,
        start_line=25,
        severity="HIGH",
        scanner_message="Dynamic exec used",
    )
    baseline_findings = [b1, b2, b3]

    # 2. Patched Findings:
    # - b1 is resolved (absent in patched) -> RESOLVED_BY_DEFINED_CHECKS
    # - b2 remains in unmodified file -> UNCHANGED
    # - b3 shifted from line 25 to line 40 in modified file -> POTENTIALLY_REGRESSED
    # - p_new: newly introduced hardcoded secret -> NEW
    p_b2 = NormalizedFinding(
        scanner_name="Bandit",
        scanner_rule_id="B303",
        vulnerability_category="CWE-327: Use of Broken or Risky Cryptographic Algorithm",
        file_path="src/utils.py",
        start_line=45,
        severity="MEDIUM",
        scanner_message="Use of MD5 hash detected",
    )
    p_b3_shifted = NormalizedFinding(
        scanner_name="Semgrep OSS",
        scanner_rule_id="python.lang.security.audit.exec-used",
        vulnerability_category="CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
        file_path=target_file,
        start_line=40,  # line shifted significantly
        severity="HIGH",
        scanner_message="Dynamic exec used in patched sink",
    )
    p_new = NormalizedFinding(
        scanner_name="Gitleaks",
        scanner_rule_id="gitleaks.generic-api-key",
        vulnerability_category="CWE-798: Hardcoded Credentials",
        file_path=target_file,
        start_line=2,
        severity="CRITICAL",
        scanner_message="Hardcoded API token detected",
    )
    patched_findings = [p_b2, p_b3_shifted, p_new]

    comp = compare_verification_findings(
        original_finding_rule=target_rule,
        original_finding_category=target_category,
        original_finding_file=target_file,
        original_finding_line=target_line,
        baseline_findings=baseline_findings,
        patched_findings=patched_findings,
        changed_files=[target_file],
    )

    # Validate Target Finding Classification: RESOLVED_BY_DEFINED_CHECKS
    assert comp.original_finding_classification == FindingRegressionClassification.RESOLVED_BY_DEFINED_CHECKS
    assert comp.original_finding_status == "resolved"

    # Validate individual classifications across all findings
    classes = {c.rule_id: c.classification for c in comp.classified_findings}
    assert classes[target_rule] == FindingRegressionClassification.RESOLVED_BY_DEFINED_CHECKS
    assert classes["B303"] == FindingRegressionClassification.UNCHANGED
    assert classes["python.lang.security.audit.exec-used"] == FindingRegressionClassification.POTENTIALLY_REGRESSED
    assert classes["gitleaks.generic-api-key"] == FindingRegressionClassification.NEW

    # Validate counts
    assert comp.resolved_findings_count == 1
    assert comp.unchanged_findings_count == 1
    assert comp.potentially_regressed_findings_count == 1
    assert comp.new_findings_count == 1

    # 3. Test INCOMPARABLE classification when scanner error occurs
    comp_err = compare_verification_findings(
        original_finding_rule=target_rule,
        original_finding_category=target_category,
        original_finding_file=target_file,
        original_finding_line=target_line,
        baseline_findings=baseline_findings,
        patched_findings=patched_findings,
        changed_files=[target_file],
        scanner_errors=["Semgrep OSS timed out after 30s"],
    )
    assert comp_err.original_finding_classification == FindingRegressionClassification.INCOMPARABLE
    assert any(c.classification == FindingRegressionClassification.INCOMPARABLE for c in comp_err.classified_findings)

    # 4. Test STILL_PRESENT classification when target persists untouched
    comp_still = compare_verification_findings(
        original_finding_rule=target_rule,
        original_finding_category=target_category,
        original_finding_file=target_file,
        original_finding_line=target_line,
        baseline_findings=[b1],
        patched_findings=[b1],
        changed_files=[target_file],
    )
    assert comp_still.original_finding_classification == FindingRegressionClassification.STILL_PRESENT
    assert comp_still.persisting_findings_count == 1


def test_effective_fix_verification_with_regression_analysis(db_session, test_finding):
    """Scenario 1: Effective fix.
    Target finding is resolved, targeted test passes, zero regressions introduced -> VERIFIED_AGAINST_DEFINED_CHECKS.
    """
    valid_test_code = """
def test_security_regression():
    assert True
"""
    req = VerificationRunRequest(
        finding_id=test_finding.id,
        proposed_patch=VALID_SQLI_PATCH,
        run_existing_tests=False,
        run_regression_tests=True,
        regression_test_code=valid_test_code,
        timeout_seconds=30
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        fnd = NormalizedFinding(
            scanner_name="Semgrep OSS",
            scanner_rule_id="python.sqlalchemy.security.audit.raw-sql-format",
            vulnerability_category="CWE-89: SQL Injection",
            file_path="auth_gateway/dao/user_query.py",
            start_line=2,
            severity="HIGH"
        )
        # Baseline detects it, Patched does not detect it (resolved)
        mock_scan.side_effect = [
            ([fnd], {"semgrep": {"version": "1.78.0"}}, []),
            ([], {"semgrep": {"version": "1.78.0"}}, [])
        ]

        result = execute_fix_verification(req, db=db_session)

        assert result.status == VerificationStatus.VERIFIED_AGAINST_DEFINED_CHECKS
        assert result.original_finding_status == "resolved"
        assert len(result.new_findings) == 0
        assert len(result.classified_findings) > 0
        assert any(
            cf.classification == FindingRegressionClassification.RESOLVED_BY_DEFINED_CHECKS
            for cf in result.classified_findings
        )
        assert any("RESOLVED_BY_DEFINED_CHECKS" in r for r in result.reasons)


def test_ineffective_fix_classified_as_still_present(db_session, test_finding):
    """Scenario 2: Ineffective fix.
    Target finding persists after patch -> STILL_PRESENT -> FAILED_VERIFICATION.
    """
    req = VerificationRunRequest(
        finding_id=test_finding.id,
        proposed_patch=INEFFECTIVE_SQLI_PATCH,
        run_existing_tests=False,
        run_regression_tests=False,
        timeout_seconds=30
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        fnd = NormalizedFinding(
            scanner_name="Semgrep OSS",
            scanner_rule_id="python.sqlalchemy.security.audit.raw-sql-format",
            vulnerability_category="CWE-89: SQL Injection",
            file_path="auth_gateway/dao/user_query.py",
            start_line=3,
            severity="HIGH"
        )
        mock_scan.side_effect = [
            ([fnd], {"semgrep": {"version": "1.78.0"}}, []),
            ([fnd], {"semgrep": {"version": "1.78.0"}}, [])
        ]

        result = execute_fix_verification(req, db=db_session)

        assert result.status == VerificationStatus.FAILED_VERIFICATION
        assert result.original_finding_status == "persisting"
        assert any(
            cf.classification == FindingRegressionClassification.STILL_PRESENT
            for cf in result.classified_findings
        )


def test_partial_fix_classified_as_potentially_regressed(db_session, test_finding):
    """Scenario 3: Partial fix.
    Target finding rule disappears, but related vulnerability remains in modified file -> POTENTIALLY_REGRESSED.
    """
    req = VerificationRunRequest(
        finding_id=test_finding.id,
        proposed_patch=VALID_SQLI_PATCH,
        run_existing_tests=False,
        run_regression_tests=False,
        timeout_seconds=30
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        orig_fnd = NormalizedFinding(
            scanner_name="Semgrep OSS",
            scanner_rule_id="python.sqlalchemy.security.audit.raw-sql-format",
            vulnerability_category="CWE-89: SQL Injection",
            file_path="auth_gateway/dao/user_query.py",
            start_line=2,
            severity="HIGH"
        )
        # In patched workspace, raw-sql-format disappears, but a related SQL injection rule is triggered in same file
        partial_fnd = NormalizedFinding(
            scanner_name="Semgrep OSS",
            scanner_rule_id="python.sqlalchemy.security.audit.raw-sql-concat",
            vulnerability_category="CWE-89: SQL Injection",
            file_path="auth_gateway/dao/user_query.py",
            start_line=4,
            severity="HIGH",
            scanner_message="Partial fix leaves secondary SQL string concatenation in DAO",
        )
        mock_scan.side_effect = [
            ([orig_fnd], {"semgrep": {"version": "1.78.0"}}, []),
            ([partial_fnd], {"semgrep": {"version": "1.78.0"}}, [])
        ]

        result = execute_fix_verification(req, db=db_session)

        assert result.status == VerificationStatus.FAILED_VERIFICATION
        assert any(
            cf.classification in (FindingRegressionClassification.POTENTIALLY_REGRESSED, FindingRegressionClassification.NEW)
            for cf in result.classified_findings
        )
        assert any("potentially_regressed" in r.lower() or "partial" in r.lower() for r in result.reasons)


def test_test_regression_detected_when_baseline_test_passes_and_patched_fails(db_session, test_finding):
    """Scenario 4: Test regression.
    Existing project test passed in baseline, but fails after applying patch -> FAILED_VERIFICATION with regression log.
    """
    from app.verification.runner import TestExecutionOutcome

    req = VerificationRunRequest(
        finding_id=test_finding.id,
        proposed_patch=VALID_SQLI_PATCH,
        run_existing_tests=True,
        run_regression_tests=False,
        timeout_seconds=30
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan, \
         patch("app.verification.service.run_pytest_in_workspace") as mock_test:
        
        # Scanners report fix clean
        orig_fnd = NormalizedFinding(
            scanner_name="Semgrep OSS",
            scanner_rule_id="python.sqlalchemy.security.audit.raw-sql-format",
            vulnerability_category="CWE-89: SQL Injection",
            file_path="auth_gateway/dao/user_query.py",
            start_line=2,
            severity="HIGH"
        )
        mock_scan.side_effect = [
            ([orig_fnd], {}, []),
            ([], {}, [])
        ]

        # Baseline test run: PASSED. Patched test run: FAILED!
        base_test_out = TestExecutionOutcome(
            test_suite_name="project_tests",
            status="passed",
            passed_count=5,
            failed_count=0
        )
        patched_test_out = TestExecutionOutcome(
            test_suite_name="project_tests",
            status="failed",
            passed_count=4,
            failed_count=1,
            error_message="AssertionError: Expected user record but got None"
        )
        mock_test.side_effect = [base_test_out, patched_test_out]

        result = execute_fix_verification(req, db=db_session)

        assert result.status == VerificationStatus.FAILED_VERIFICATION
        assert len(result.test_regressions) == 1
        assert "regression detected" in result.test_regressions[0].lower()
        assert any("regression" in r.lower() for r in result.reasons)


def test_scanner_failure_leads_to_incomparable_and_inconclusive(db_session, test_finding):
    """Scenario 5: Scanner failure / timeout leads to INCOMPARABLE and INCONCLUSIVE verdict."""
    req = VerificationRunRequest(
        finding_id=test_finding.id,
        proposed_patch=VALID_SQLI_PATCH,
        run_existing_tests=False,
        run_regression_tests=False,
        timeout_seconds=30
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        mock_scan.side_effect = [
            ([], {}, ["Semgrep OSS timed out after 30s"]),
            ([], {}, [])
        ]

        result = execute_fix_verification(req, db=db_session)

        assert result.status == VerificationStatus.INCONCLUSIVE
        assert len(result.execution_errors) > 0
        assert any("timed out" in err for err in result.execution_errors)
        assert any(
            cf.classification == FindingRegressionClassification.INCOMPARABLE
            for cf in result.classified_findings
        )


def test_decision_axiom_disappearing_finding_alone_records_missing_evidence(db_session, test_finding):
    """Scenario 6: Decision Axiom.
    Disappearing scanner finding alone must NOT claim complete security without dynamic/targeted test evidence.
    """
    req = VerificationRunRequest(
        finding_id=test_finding.id,
        proposed_patch=VALID_SQLI_PATCH,
        run_existing_tests=False,
        run_regression_tests=False,  # No dynamic/targeted tests provided!
        timeout_seconds=30
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        fnd = NormalizedFinding(
            scanner_name="Semgrep OSS",
            scanner_rule_id="python.sqlalchemy.security.audit.raw-sql-format",
            vulnerability_category="CWE-89: SQL Injection",
            file_path="auth_gateway/dao/user_query.py",
            start_line=2,
            severity="HIGH"
        )
        mock_scan.side_effect = [
            ([fnd], {"semgrep": {"version": "1.78.0"}}, []),
            ([], {"semgrep": {"version": "1.78.0"}}, [])
        ]

        result = execute_fix_verification(req, db=db_session)

        # Result is against defined checks, BUT explicit missing evidence is recorded
        assert any("disappearing scanner finding alone" in ev.lower() for ev in result.missing_evidence)
        assert any("disappearing does not prove" in lim for lim in result.limitations)


def test_decision_axiom_passing_tests_alone_cannot_verify_with_persisting_finding(db_session, test_finding):
    """Scenario 7: Decision Axiom.
    A passing test suite alone must NOT establish that a patch is secure if scanner finding persists.
    """
    from app.verification.runner import TestExecutionOutcome

    req = VerificationRunRequest(
        finding_id=test_finding.id,
        proposed_patch=INEFFECTIVE_SQLI_PATCH,
        run_existing_tests=True,
        run_regression_tests=False,
        timeout_seconds=30
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan, \
         patch("app.verification.service.run_pytest_in_workspace") as mock_test:
        
        # Scanner reports finding STILL PRESENT in both baseline and patched
        fnd = NormalizedFinding(
            scanner_name="Semgrep OSS",
            scanner_rule_id="python.sqlalchemy.security.audit.raw-sql-format",
            vulnerability_category="CWE-89: SQL Injection",
            file_path="auth_gateway/dao/user_query.py",
            start_line=3,
            severity="HIGH"
        )
        mock_scan.side_effect = [
            ([fnd], {}, []),
            ([fnd], {}, [])
        ]

        # But all unit tests pass with flying colors!
        passing_tests = TestExecutionOutcome(
            test_suite_name="project_tests",
            status="passed",
            passed_count=20,
            failed_count=0
        )
        mock_test.side_effect = [passing_tests, passing_tests]

        result = execute_fix_verification(req, db=db_session)

        # Invariant: PASSING test suite alone CANNOT establish that patch is secure!
        assert result.status == VerificationStatus.FAILED_VERIFICATION
        assert result.original_finding_status == "persisting"
        assert any(
            cf.classification == FindingRegressionClassification.STILL_PRESENT
            for cf in result.classified_findings
        )

