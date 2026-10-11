"""Comprehensive Security-Fix Verification Evaluation Suite for Difficult Scenarios.

Investigates 10 critical AppSec edge cases:
1. Genuinely resolves the targeted vulnerability (VERIFIED_AGAINST_DEFINED_CHECKS).
2. Changes code but leaves vulnerability intact (FAILED_VERIFICATION / STILL_PRESENT).
3. Fixes one execution path but leaves another vulnerable path (FAILED_VERIFICATION / POTENTIALLY_REGRESSED).
4. Removes original scanner finding through obfuscation without fixing underlying weakness (FAILED_VERIFICATION / Exploit Test Fails).
5. Introduces a detectable security regression (FAILED_VERIFICATION / NEW finding).
6. Breaks application functionality (FAILED_VERIFICATION / Unit test regression).
7. Relevant scanner is unavailable (INCONCLUSIVE / TOOL_NOT_INSTALLED).
8. Tests time out (INCONCLUSIVE / TIMEOUT).
9. Insufficient evidence to reach a conclusion (INCONCLUSIVE / INCOMPARABLE).
10. Affects code outside intended scope / path traversal (INCONCLUSIVE / Patch validation failure).

Assurance Invariants:
- Never classify missing evidence as a successful verification.
- Do not equate disappearance of a scanner finding with proof that a vulnerability has been eliminated.
"""
from datetime import datetime, timezone
from pathlib import Path
import pytest
from unittest.mock import MagicMock, patch

from app.models.finding import SecurityFinding
from app.models.repository import Repository
from app.models.user import User
from app.schemas.verification import (
    FindingRegressionClassification,
    VerificationRunRequest,
    VerificationStatus,
)
from app.scanner.base import NormalizedFinding, ScannerStatus
from app.verification.comparator import compare_verification_findings
from app.verification.patch_parser import parse_unified_diff
from app.verification.service import execute_fix_verification


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def scenario_repository(db_session):
    """Sets up a controlled test repository for difficulty scenarios."""
    repo = db_session.query(Repository).filter(Repository.id == "repo-scenario-test-01").first()
    if not repo:
        repo = Repository(
            id="repo-scenario-test-01",
            owner_id="usr-scenario-seed-001",
            name="xerova/difficult-scenarios-repo",
            default_branch="main",
            health_score=85,
        )
        db_session.add(repo)
        db_session.commit()
    return repo


@pytest.fixture
def sqli_finding(db_session, scenario_repository):
    """SQL Injection finding fixture."""
    f = db_session.query(SecurityFinding).filter(SecurityFinding.id == "FIND-SQLI-SCENARIO").first()
    if not f:
        f = SecurityFinding(
            id="FIND-SQLI-SCENARIO",
            repo_id=scenario_repository.id,
            cwe="CWE-89: SQL Injection",
            title="Unescaped SQL query string formatting",
            severity="HIGH",
            scanner_name="Semgrep OSS",
            file_path="src/gateway/query.py",
            line_number=5,
            rule_identifier="python.sqlalchemy.security.audit.raw-sql-format",
            code_excerpt=(
                "def query_user(cursor, user_id):\n"
                "    query = f\"SELECT * FROM users WHERE id = '{user_id}'\"\n"
                "    return cursor.execute(query).fetchall()\n"
            )
        )
        db_session.add(f)
        db_session.commit()
    db_session.refresh(f)
    return f


@pytest.fixture
def multi_path_finding(db_session, scenario_repository):
    """Multi-path SQL Injection finding fixture."""
    f = db_session.query(SecurityFinding).filter(SecurityFinding.id == "FIND-MULTIPATH-SCENARIO").first()
    if not f:
        f = SecurityFinding(
            id="FIND-MULTIPATH-SCENARIO",
            repo_id=scenario_repository.id,
            cwe="CWE-89: SQL Injection",
            title="Conditional branches with raw SQL queries",
            severity="HIGH",
            scanner_name="Bandit Python SAST",
            file_path="src/gateway/multi_path.py",
            line_number=6,
            rule_identifier="B608",
            code_excerpt=(
                "def get_account(cursor, acc_id, is_admin=False):\n"
                "    if is_admin:\n"
                "        return cursor.execute(f\"SELECT * FROM admin_accounts WHERE id = '{acc_id}'\").fetchall()\n"
                "    else:\n"
                "        return cursor.execute(f\"SELECT * FROM user_accounts WHERE id = '{acc_id}'\").fetchall()\n"
            )
        )
        db_session.add(f)
        db_session.commit()
    db_session.refresh(f)
    return f


@pytest.fixture
def cmd_injection_finding(db_session, scenario_repository):
    """Command injection finding fixture."""
    f = db_session.query(SecurityFinding).filter(SecurityFinding.id == "FIND-CMDI-SCENARIO").first()
    if not f:
        f = SecurityFinding(
            id="FIND-CMDI-SCENARIO",
            repo_id=scenario_repository.id,
            cwe="CWE-78: OS Command Injection",
            title="Dynamic shell command execution",
            severity="CRITICAL",
            scanner_name="Bandit Python SAST",
            file_path="src/utils/ping.py",
            line_number=4,
            rule_identifier="B605",
            code_excerpt=(
                "import os\n"
                "def ping_host(target):\n"
                "    return os.system('ping -c 1 ' + target)\n"
            )
        )
        db_session.add(f)
        db_session.commit()
    db_session.refresh(f)
    return f


# =============================================================================
# SCENARIO 1: GENUINELY RESOLVES THE TARGETED VULNERABILITY
# =============================================================================

def test_scenario_01_genuinely_resolves_vulnerability(db_session, sqli_finding):
    """Scenario 1: Patch parameterizes the SQL query and passes behavioral checks.
    
    Expected: VERIFIED_AGAINST_DEFINED_CHECKS
    Rationale: Baseline finding reproduced, eliminated in patched workspace, no new regressions.
    """
    valid_patch = """--- a/src/gateway/query.py
+++ b/src/gateway/query.py
@@ -1,5 +1,5 @@
 def query_user(cursor, user_id):
-    query = f"SELECT * FROM users WHERE id = '{user_id}'"
-    return cursor.execute(query).fetchall()
+    query = "SELECT * FROM users WHERE id = %s"
+    return cursor.execute(query, (user_id,)).fetchall()
"""
    req = VerificationRunRequest(
        finding_id=sqli_finding.id,
        proposed_patch=valid_patch,
        run_existing_tests=False,
        run_regression_tests=True,
        regression_test_code="""
def test_parameterized():
    assert True, "Parameterized query executes safely"
""",
        timeout_seconds=20
    )

    baseline_fnd = NormalizedFinding(
        scanner_name="Semgrep OSS",
        scanner_rule_id="python.sqlalchemy.security.audit.raw-sql-format",
        vulnerability_category="CWE-89: SQL Injection",
        file_path="src/gateway/query.py",
        start_line=2,
        severity="HIGH"
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        mock_scan.side_effect = [
            ([baseline_fnd], {"semgrep": {"version": "1.78.0"}}, []),  # baseline
            ([], {"semgrep": {"version": "1.78.0"}}, [])             # patched
        ]
        result = execute_fix_verification(req, db=db_session)

        assert result.status == VerificationStatus.VERIFIED_AGAINST_DEFINED_CHECKS
        assert result.original_finding_status == "resolved"
        assert len(result.new_findings) == 0
        assert result.baseline_hash != result.patched_hash


# =============================================================================
# SCENARIO 2: CHANGES CODE BUT LEAVES VULNERABILITY INTACT
# =============================================================================

def test_scenario_02_cosmetic_change_leaves_vulnerability_intact(db_session, sqli_finding):
    """Scenario 2: Patch performs cosmetic refactor but leaves string formatting intact.
    
    Expected: FAILED_VERIFICATION
    Rationale: Finding remains detected in patched workspace (STILL_PRESENT).
    """
    ineffective_patch = """--- a/src/gateway/query.py
+++ b/src/gateway/query.py
@@ -1,5 +1,6 @@
 def query_user(cursor, user_id):
-    query = f"SELECT * FROM users WHERE id = '{user_id}'"
+    uid_str = str(user_id)
+    query = f"SELECT * FROM users WHERE id = '{uid_str}'"
     return cursor.execute(query).fetchall()
"""
    req = VerificationRunRequest(
        finding_id=sqli_finding.id,
        proposed_patch=ineffective_patch,
        run_existing_tests=False,
        run_regression_tests=False,
        timeout_seconds=20
    )

    persisting_fnd = NormalizedFinding(
        scanner_name="Semgrep OSS",
        scanner_rule_id="python.sqlalchemy.security.audit.raw-sql-format",
        vulnerability_category="CWE-89: SQL Injection",
        file_path="src/gateway/query.py",
        start_line=3,
        severity="HIGH"
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        mock_scan.side_effect = [
            ([persisting_fnd], {"semgrep": {"version": "1.78.0"}}, []),
            ([persisting_fnd], {"semgrep": {"version": "1.78.0"}}, [])
        ]
        result = execute_fix_verification(req, db=db_session)

        assert result.status == VerificationStatus.FAILED_VERIFICATION
        assert result.original_finding_status == "persisting"
        assert any("remains reported" in r for r in result.reasons)


# =============================================================================
# SCENARIO 3: FIXES ONE PATH BUT LEAVES ANOTHER VULNERABLE PATH
# =============================================================================

def test_scenario_03_partial_fix_leaves_alternate_path_vulnerable(db_session, multi_path_finding):
    """Scenario 3: Patch fixes the 'is_admin=True' branch but leaves the fallback branch vulnerable.
    
    Expected: FAILED_VERIFICATION
    Rationale: Scanner detects unparameterized query on modified file (POTENTIALLY_REGRESSED / STILL_PRESENT).
    """
    partial_patch = """--- a/src/gateway/multi_path.py
+++ b/src/gateway/multi_path.py
@@ -1,6 +1,6 @@
 def get_account(cursor, acc_id, is_admin=False):
     if is_admin:
-        return cursor.execute(f"SELECT * FROM admin_accounts WHERE id = '{acc_id}'").fetchall()
+        return cursor.execute("SELECT * FROM admin_accounts WHERE id = %s", (acc_id,)).fetchall()
     else:
         return cursor.execute(f"SELECT * FROM user_accounts WHERE id = '{acc_id}'").fetchall()
"""
    req = VerificationRunRequest(
        finding_id=multi_path_finding.id,
        proposed_patch=partial_patch,
        run_existing_tests=False,
        run_regression_tests=False,
        timeout_seconds=20
    )

    baseline_fnd = NormalizedFinding(
        scanner_name="Bandit Python SAST",
        scanner_rule_id="B608",
        vulnerability_category="CWE-89: SQL Injection",
        file_path="src/gateway/multi_path.py",
        start_line=3,
        severity="HIGH"
    )
    # The alternate branch still triggers B608 on line 5!
    remaining_fnd = NormalizedFinding(
        scanner_name="Bandit Python SAST",
        scanner_rule_id="B608",
        vulnerability_category="CWE-89: SQL Injection",
        file_path="src/gateway/multi_path.py",
        start_line=5,
        severity="HIGH"
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        mock_scan.side_effect = [
            ([baseline_fnd], {"bandit": {"version": "1.9.4"}}, []),
            ([remaining_fnd], {"bandit": {"version": "1.9.4"}}, [])
        ]
        result = execute_fix_verification(req, db=db_session)

        assert result.status == VerificationStatus.FAILED_VERIFICATION
        assert result.original_finding_status in ("modified", "persisting")


# =============================================================================
# SCENARIO 4: SCANNER EVASION WITHOUT RESOLVING WEAKNESS
# =============================================================================

def test_scenario_04_scanner_evasion_caught_by_exploit_regression_test(db_session, cmd_injection_finding):
    """Scenario 4: Patch obfuscates code so static scanner misses it, but behavioral exploit test catches it.
    
    Expected: FAILED_VERIFICATION
    Rationale: Disappearance of scanner finding != vulnerability eliminated.
               Behavioral exploit test fails, forcing FAILED_VERIFICATION.
    """
    evasive_patch = """--- a/src/utils/ping.py
+++ b/src/utils/ping.py
@@ -1,4 +1,4 @@
 import os
 def ping_host(target):
-    return os.system('ping -c 1 ' + target)
+    return getattr(os, 'sys' + 'tem')(''.join(['ping -c 1 ', target]))
"""
    # Behavioral test proves exploit still executes arbitrary command injection
    failing_exploit_test = """
def test_exploit_command_injection():
    # If injection payload executes, test fails
    is_vulnerable = True
    assert not is_vulnerable, "Command injection payload successfully executed despite scanner evasion!"
"""
    req = VerificationRunRequest(
        finding_id=cmd_injection_finding.id,
        proposed_patch=evasive_patch,
        run_existing_tests=False,
        run_regression_tests=True,
        regression_test_code=failing_exploit_test,
        timeout_seconds=20
    )

    base_fnd = NormalizedFinding(
        scanner_name="Bandit Python SAST",
        scanner_rule_id="B605",
        vulnerability_category="CWE-78: OS Command Injection",
        file_path="src/utils/ping.py",
        start_line=3,
        severity="CRITICAL"
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        # Scanner was fooled (0 findings in patched!), BUT exploit test fails
        mock_scan.side_effect = [
            ([base_fnd], {"bandit": {"version": "1.9.4"}}, []),
            ([], {"bandit": {"version": "1.9.4"}}, [])
        ]
        result = execute_fix_verification(req, db=db_session)

        assert result.status == VerificationStatus.FAILED_VERIFICATION
        assert any("regression test failed" in r.lower() for r in result.reasons)


# =============================================================================
# SCENARIO 5: INTRODUCES A DETECTABLE SECURITY REGRESSION
# =============================================================================

def test_scenario_05_patch_introduces_security_regression(db_session, sqli_finding):
    """Scenario 5: Patch resolves SQLi but introduces hardcoded AWS credentials.
    
    Expected: FAILED_VERIFICATION
    Rationale: Differential analysis detects NEW critical finding in patched workspace.
    """
    regressive_patch = """--- a/src/gateway/query.py
+++ b/src/gateway/query.py
@@ -1,5 +1,7 @@
+AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
 def query_user(cursor, user_id):
-    query = f"SELECT * FROM users WHERE id = '{user_id}'"
-    return cursor.execute(query).fetchall()
+    query = "SELECT * FROM users WHERE id = %s"
+    return cursor.execute(query, (user_id,)).fetchall()
"""
    req = VerificationRunRequest(
        finding_id=sqli_finding.id,
        proposed_patch=regressive_patch,
        run_existing_tests=False,
        run_regression_tests=False,
        timeout_seconds=20
    )

    sqli_base = NormalizedFinding(
        scanner_name="Semgrep OSS",
        scanner_rule_id="python.sqlalchemy.security.audit.raw-sql-format",
        vulnerability_category="CWE-89: SQL Injection",
        file_path="src/gateway/query.py",
        start_line=2,
        severity="HIGH"
    )
    new_secret_fnd = NormalizedFinding(
        scanner_name="RepoShield Secret Engine",
        scanner_rule_id="SEC-AWS-KEY",
        vulnerability_category="CWE-798: Use of Hard-coded Credentials",
        file_path="src/gateway/query.py",
        start_line=1,
        severity="CRITICAL",
        scanner_message="Hardcoded AWS Access Key ID detected"
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        mock_scan.side_effect = [
            ([sqli_base], {"semgrep": {"version": "1.78.0"}}, []),
            ([new_secret_fnd], {"semgrep": {"version": "1.78.0"}, "secret_engine": {"version": "1.0"}}, [])
        ]
        result = execute_fix_verification(req, db=db_session)

        assert result.status == VerificationStatus.FAILED_VERIFICATION
        assert len(result.new_findings) == 1
        assert result.new_findings[0]["rule_id"] == "SEC-AWS-KEY"


# =============================================================================
# SCENARIO 6: BREAKS APPLICATION FUNCTIONALITY
# =============================================================================

def test_scenario_06_patch_breaks_functional_unit_tests(db_session, sqli_finding):
    """Scenario 6: Patch fixes vulnerability by throwing an unhandled exception, breaking unit tests.
    
    Expected: FAILED_VERIFICATION
    Rationale: Existing project unit tests fail after patch application.
    """
    breaking_patch = """--- a/src/gateway/query.py
+++ b/src/gateway/query.py
@@ -1,5 +1,4 @@
 def query_user(cursor, user_id):
-    query = f"SELECT * FROM users WHERE id = '{user_id}'"
-    return cursor.execute(query).fetchall()
+    raise NotImplementedError("Blocked all access to prevent SQL injection")
"""
    req = VerificationRunRequest(
        finding_id=sqli_finding.id,
        proposed_patch=breaking_patch,
        run_existing_tests=True,
        run_regression_tests=False,
        timeout_seconds=20
    )

    base_fnd = NormalizedFinding(
        scanner_name="Semgrep OSS",
        scanner_rule_id="python.sqlalchemy.security.audit.raw-sql-format",
        vulnerability_category="CWE-89: SQL Injection",
        file_path="src/gateway/query.py",
        start_line=2,
        severity="HIGH"
    )

    from app.verification.runner import TestExecutionOutcome

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan, \
         patch("app.verification.service.run_pytest_in_workspace") as mock_test:
        
        mock_scan.side_effect = [
            ([base_fnd], {"semgrep": {"version": "1.78.0"}}, []),
            ([], {"semgrep": {"version": "1.78.0"}}, [])
        ]
        # Unit test fails due to NotImplementedError
        mock_test.return_value = TestExecutionOutcome(
            test_suite_name="test_gateway",
            status="failed",
            passed_count=0,
            failed_count=1,
            output_log="NotImplementedError: Blocked all access",
            error_message="1 failed in test_gateway.py"
        )

        result = execute_fix_verification(req, db=db_session)

        assert result.status == VerificationStatus.FAILED_VERIFICATION
        assert any("unit test suite" in r.lower() or "failed" in r.lower() for r in result.reasons)


# =============================================================================
# SCENARIO 7: RELEVANT SCANNER IS UNAVAILABLE
# =============================================================================

def test_scenario_07_scanner_unavailable_produces_inconclusive(db_session, sqli_finding):
    """Scenario 7: Scanner binary is uninstalled or encounters an execution fault.
    
    Expected: INCONCLUSIVE
    Rationale: Missing analysis tools cannot confirm security fixes; missing evidence is never a success.
    """
    valid_patch = """--- a/src/gateway/query.py
+++ b/src/gateway/query.py
@@ -1,5 +1,5 @@
 def query_user(cursor, user_id):
-    query = f"SELECT * FROM users WHERE id = '{user_id}'"
+    query = "SELECT * FROM users WHERE id = %s"
     return cursor.execute(query, (user_id,)).fetchall()
"""
    req = VerificationRunRequest(
        finding_id=sqli_finding.id,
        proposed_patch=valid_patch,
        run_existing_tests=False,
        run_regression_tests=False,
        timeout_seconds=20
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        # Scanner crashes or is unavailable with tool error
        mock_scan.side_effect = [
            ([], {}, ["Semgrep binary not found in PATH or environment"]),
            ([], {}, ["Semgrep binary not found in PATH or environment"])
        ]
        result = execute_fix_verification(req, db=db_session)

        assert result.status == VerificationStatus.INCONCLUSIVE
        assert len(result.execution_errors) > 0
        assert any("semgrep" in err.lower() for err in result.execution_errors)


# =============================================================================
# SCENARIO 8: TESTS TIME OUT
# =============================================================================

def test_scenario_08_test_timeout_produces_inconclusive(db_session, sqli_finding):
    """Scenario 8: Test suite hangs / exceeds timeout threshold.
    
    Expected: INCONCLUSIVE or FAILED_VERIFICATION (depending on gate configuration)
    Rationale: Timed-out execution produces incomplete evidence.
    """
    patch_with_deadlock = """--- a/src/gateway/query.py
+++ b/src/gateway/query.py
@@ -1,5 +1,6 @@
+import time
 def query_user(cursor, user_id):
-    query = f"SELECT * FROM users WHERE id = '{user_id}'"
+    time.sleep(9999)
     return cursor.execute(query).fetchall()
"""
    req = VerificationRunRequest(
        finding_id=sqli_finding.id,
        proposed_patch=patch_with_deadlock,
        run_existing_tests=True,
        run_regression_tests=False,
        timeout_seconds=5
    )

    base_fnd = NormalizedFinding(
        scanner_name="Semgrep OSS",
        scanner_rule_id="python.sqlalchemy.security.audit.raw-sql-format",
        vulnerability_category="CWE-89: SQL Injection",
        file_path="src/gateway/query.py",
        start_line=2,
        severity="HIGH"
    )

    from app.verification.runner import TestExecutionOutcome

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan, \
         patch("app.verification.service.run_pytest_in_workspace") as mock_test:
        
        mock_scan.side_effect = [
            ([base_fnd], {"semgrep": {"version": "1.78.0"}}, []),
            ([], {"semgrep": {"version": "1.78.0"}}, [])
        ]
        mock_test.return_value = TestExecutionOutcome(
            test_suite_name="test_gateway",
            status="timeout",
            passed_count=0,
            failed_count=0,
            output_log="Process timed out after 5 seconds",
            error_message="Test runner execution timed out"
        )

        result = execute_fix_verification(req, db=db_session)

        # Timeout in test execution prevents verified status!
        assert result.status in (VerificationStatus.INCONCLUSIVE, VerificationStatus.FAILED_VERIFICATION)
        assert result.status != VerificationStatus.VERIFIED_AGAINST_DEFINED_CHECKS


# =============================================================================
# SCENARIO 9: INSUFFICIENT EVIDENCE (BASELINE UNREPRODUCED)
# =============================================================================

def test_scenario_09_baseline_unreproduced_produces_inconclusive(db_session, sqli_finding):
    """Scenario 9: Finding was never detected in the baseline workspace (INCOMPARABLE).
    
    Expected: INCONCLUSIVE
    Rationale: Resolution cannot be claimed through static checks alone when the baseline finding was never observed.
    """
    valid_patch = """--- a/src/gateway/query.py
+++ b/src/gateway/query.py
@@ -1,3 +1,3 @@
 def query_user(cursor, user_id):
-    query = f"SELECT * FROM users WHERE id = '{user_id}'"
+    query = "SELECT * FROM users WHERE id = %s"
     return cursor.execute(query).fetchall()
"""
    req = VerificationRunRequest(
        finding_id=sqli_finding.id,
        proposed_patch=valid_patch,
        run_existing_tests=False,
        run_regression_tests=False,
        timeout_seconds=20
    )

    with patch("app.verification.service.run_scanners_on_directory") as mock_scan:
        # Baseline scanner reported NO findings (finding was not reproduced in baseline)
        mock_scan.side_effect = [
            ([], {"semgrep": {"version": "1.78.0"}}, []),  # baseline has no findings!
            ([], {"semgrep": {"version": "1.78.0"}}, [])   # patched has no findings
        ]
        result = execute_fix_verification(req, db=db_session)

        assert result.status == VerificationStatus.INCONCLUSIVE
        assert result.original_finding_status == "untested"
        assert any("baseline" in m.lower() for m in result.missing_evidence) or any("inconclusive" in r.lower() or "baseline" in r.lower() for r in result.reasons)


# =============================================================================
# SCENARIO 10: PATCH MODIFIES CODE OUTSIDE INTENDED SCOPE / TRAVERSAL
# =============================================================================

def test_scenario_10_patch_outside_scope_or_traversal_rejected(db_session, sqli_finding):
    """Scenario 10: Patch modifies files outside repository boundary (directory traversal).
    
    Expected: INCONCLUSIVE / Rejected with invalid patch error
    Rationale: Scope boundary violation stops verification before execution.
    """
    traversal_patch = """--- a/../../../../etc/shadow
+++ b/../../../../etc/shadow
@@ -1,1 +1,1 @@
-root:*:19000:0:99999:7:::
+root:$6$hacked$:19000:0:99999:7:::
"""
    req = VerificationRunRequest(
        finding_id=sqli_finding.id,
        proposed_patch=traversal_patch,
        run_existing_tests=False,
        run_regression_tests=False,
        timeout_seconds=20
    )

    result = execute_fix_verification(req, db=db_session)

    assert result.status == VerificationStatus.INCONCLUSIVE
    assert any("traversal" in r.lower() or "invalid" in r.lower() for r in result.reasons)
