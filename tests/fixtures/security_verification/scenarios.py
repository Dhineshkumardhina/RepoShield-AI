"""Controlled Test Fixture Inventory for Fix-Verification Engine Validation.

Defines 10 reproducible, deterministic, and safe AppSec verification scenarios:
1. Known vulnerability with an effective fix.
2. Known vulnerability with an ineffective fix.
3. Partially corrected vulnerability.
4. Finding that disappears due to scanner configuration change (evasion).
5. Fix that introduces a security regression (new vulnerability).
6. Fix that breaks expected application behavior (functional regression).
7. Scanner that is unavailable / uninstalled.
8. Scanner timeout or execution error.
9. Patch that touches an unrelated code path without fixing the vulnerability.
10. Evidence is insufficient to determine whether the fix works (epistemic modesty).
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class VerificationScenarioFixture:
    scenario_id: str
    scenario_number: int
    name: str
    cwe: str
    scanner_rule_id: str
    scanner_name: str
    vulnerable_file_path: str
    vulnerable_source_code: str
    existing_unit_test_path: str
    existing_unit_test_code: str
    targeted_security_test_code: Optional[str]
    candidate_patch: str
    scanner_names: List[str]
    scanner_config: Dict[str, Any] = field(default_factory=dict)
    run_existing_tests: bool = True
    run_regression_tests: bool = True
    expected_status: str = "VERIFIED_AGAINST_DEFINED_CHECKS"
    expected_original_finding_status: str = "resolved"
    expected_classification: Optional[str] = "RESOLVED_BY_DEFINED_CHECKS"
    expected_regression_count: int = 0
    expected_errors_contain: List[str] = field(default_factory=list)
    expected_reasons_contain: List[str] = field(default_factory=list)
    expected_missing_evidence_contain: List[str] = field(default_factory=list)
    epistemic_rationale: str = ""


# Shared source files
SQLI_VULNERABLE_SOURCE = """import sqlite3

def query_user_account(db_conn, username: str):
    cursor = db_conn.cursor()
    query = f"SELECT id, username, role FROM accounts WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
"""

SQLI_EXISTING_UNIT_TEST = """import sqlite3
from src.user_dao import query_user_account

def test_query_user_account_success():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE accounts (id INT, username TEXT, role TEXT)")
    conn.execute("INSERT INTO accounts VALUES (1, 'alice', 'admin')")
    row = query_user_account(conn, "alice")
    assert row == (1, 'alice', 'admin')
"""

SQLI_TARGETED_EXPLOIT_TEST = """import sqlite3
from src.user_dao import query_user_account

def test_sql_injection_payload_is_neutralized():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE accounts (id INT, username TEXT, role TEXT)")
    conn.execute("INSERT INTO accounts VALUES (1, 'alice', 'admin')")
    # Attack payload trying to bypass authentication
    row = query_user_account(conn, "' OR '1'='1")
    assert row is None
"""

MULTI_SINK_VULNERABLE_SOURCE = """import sqlite3

def query_tenant_user(db_conn, tenant_id: str, username: str):
    cursor = db_conn.cursor()
    query = f"SELECT id, username FROM accounts WHERE tenant_id = '{tenant_id}' AND username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()
"""

MULTI_SINK_UNIT_TEST = """import sqlite3
from src.user_dao import query_tenant_user

def test_query_tenant_user():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE accounts (id INT, tenant_id TEXT, username TEXT)")
    conn.execute("INSERT INTO accounts VALUES (1, 't-100', 'bob')")
    res = query_tenant_user(conn, 't-100', 'bob')
    assert len(res) == 1
"""

MULTI_SINK_TARGETED_TEST = """import sqlite3
from src.user_dao import query_tenant_user

def test_tenant_injection_fails():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE accounts (id INT, tenant_id TEXT, username TEXT)")
    conn.execute("INSERT INTO accounts VALUES (1, 't-100', 'bob')")
    res = query_tenant_user(conn, "' OR '1'='1", "bob")
    assert len(res) <= 1
"""


# -----------------------------------------------------------------------------
# 10 Controlled Scenarios
# -----------------------------------------------------------------------------

VERIFICATION_SCENARIOS: Dict[str, VerificationScenarioFixture] = {
    # 1. Effective Fix
    "SCENARIO_01_EFFECTIVE_FIX": VerificationScenarioFixture(
        scenario_id="SCENARIO_01_EFFECTIVE_FIX",
        scenario_number=1,
        name="SQL Injection with Parameterized Query Fix",
        cwe="CWE-89: SQL Injection",
        scanner_rule_id="B608",
        scanner_name="bandit",
        vulnerable_file_path="src/user_dao.py",
        vulnerable_source_code=SQLI_VULNERABLE_SOURCE,
        existing_unit_test_path="tests/test_user_dao.py",
        existing_unit_test_code=SQLI_EXISTING_UNIT_TEST,
        targeted_security_test_code=SQLI_TARGETED_EXPLOIT_TEST,
        candidate_patch="""--- a/src/user_dao.py
+++ b/src/user_dao.py
@@ -3,4 +3,4 @@
 def query_user_account(db_conn, username: str):
     cursor = db_conn.cursor()
-    query = f"SELECT id, username, role FROM accounts WHERE username = '{username}'"
-    cursor.execute(query)
+    query = "SELECT id, username, role FROM accounts WHERE username = ?"
+    cursor.execute(query, (username,))
     return cursor.fetchone()
""",
        scanner_names=["bandit"],
        expected_status="VERIFIED_AGAINST_DEFINED_CHECKS",
        expected_original_finding_status="resolved",
        expected_classification="RESOLVED_BY_DEFINED_CHECKS",
        expected_regression_count=0,
        expected_reasons_contain=["All defined checks completed successfully", "no blocking regression"],
        epistemic_rationale="Vulnerability reproduced in baseline, cleanly absent in patched workspace under same rule, existing unit test passes, and runtime exploit test confirms neutralization.",
    ),

    # 2. Ineffective Fix
    "SCENARIO_02_INEFFECTIVE_FIX": VerificationScenarioFixture(
        scenario_id="SCENARIO_02_INEFFECTIVE_FIX",
        scenario_number=2,
        name="SQL Injection with Ineffective String Strip Fix",
        cwe="CWE-89: SQL Injection",
        scanner_rule_id="B608",
        scanner_name="bandit",
        vulnerable_file_path="src/user_dao.py",
        vulnerable_source_code=SQLI_VULNERABLE_SOURCE,
        existing_unit_test_path="tests/test_user_dao.py",
        existing_unit_test_code=SQLI_EXISTING_UNIT_TEST,
        targeted_security_test_code=SQLI_TARGETED_EXPLOIT_TEST,
        candidate_patch="""--- a/src/user_dao.py
+++ b/src/user_dao.py
@@ -3,4 +3,5 @@
 def query_user_account(db_conn, username: str):
     cursor = db_conn.cursor()
+    clean_user = str(username).strip()
-    query = f"SELECT id, username, role FROM accounts WHERE username = '{username}'"
+    query = f"SELECT id, username, role FROM accounts WHERE username = '{clean_user}'"
     cursor.execute(query)
     return cursor.fetchone()
""",
        scanner_names=["bandit"],
        expected_status="FAILED_VERIFICATION",
        expected_original_finding_status="persisting",
        expected_classification="POTENTIALLY_REGRESSED",
        expected_regression_count=0,
        expected_reasons_contain=["persisting", "remains detected"],
        epistemic_rationale="The patch naively stripped whitespace but retained raw f-string interpolation into the database sink. Scanner detects B608 still present.",
    ),

    # 3. Partially Corrected Vulnerability
    "SCENARIO_03_PARTIAL_FIX": VerificationScenarioFixture(
        scenario_id="SCENARIO_03_PARTIAL_FIX",
        scenario_number=3,
        name="Multi-Parameter Injection Partially Corrected",
        cwe="CWE-89: SQL Injection",
        scanner_rule_id="B608",
        scanner_name="bandit",
        vulnerable_file_path="src/user_dao.py",
        vulnerable_source_code=MULTI_SINK_VULNERABLE_SOURCE,
        existing_unit_test_path="tests/test_user_dao.py",
        existing_unit_test_code=MULTI_SINK_UNIT_TEST,
        targeted_security_test_code=MULTI_SINK_TARGETED_TEST,
        candidate_patch="""--- a/src/user_dao.py
+++ b/src/user_dao.py
@@ -3,3 +3,3 @@
 def query_tenant_user(db_conn, tenant_id: str, username: str):
     cursor = db_conn.cursor()
-    query = f"SELECT id, username FROM accounts WHERE tenant_id = '{tenant_id}' AND username = '{username}'"
+    query = f"SELECT id, username FROM accounts WHERE tenant_id = '{tenant_id}' AND username = ?"
-    cursor.execute(query)
+    cursor.execute(query, (username,))
""",
        scanner_names=["bandit"],
        expected_status="FAILED_VERIFICATION",
        expected_original_finding_status="persisting",
        expected_classification="STILL_PRESENT",
        expected_regression_count=0,
        expected_reasons_contain=["remains detected", "persisting"],
        epistemic_rationale="The patch parameterized the username parameter but left the tenant_id parameter vulnerable to SQL injection in the modified hunk.",
    ),

    # 4. Scanner Configuration Change Evasion
    "SCENARIO_04_SCANNER_CONFIG_EVASION": VerificationScenarioFixture(
        scenario_id="SCENARIO_04_SCANNER_CONFIG_EVASION",
        scenario_number=4,
        name="Finding Disappears Due to Scanner Config Override Rather Than Fix",
        cwe="CWE-89: SQL Injection",
        scanner_rule_id="B608",
        scanner_name="bandit",
        vulnerable_file_path="src/user_dao.py",
        vulnerable_source_code=SQLI_VULNERABLE_SOURCE,
        existing_unit_test_path="tests/test_user_dao.py",
        existing_unit_test_code=SQLI_EXISTING_UNIT_TEST,
        targeted_security_test_code=None,
        candidate_patch="""--- a/src/user_dao.py
+++ b/src/user_dao.py
@@ -1,3 +1,4 @@
 import sqlite3
+# Refactored comment header
 
 def query_user_account(db_conn, username: str):
""",
        scanner_names=["bandit"],
        scanner_config={"skip_rules": ["B608"]},
        expected_status="INCONCLUSIVE",
        expected_original_finding_status="untested",
        expected_classification="INCOMPARABLE",
        expected_regression_count=0,
        expected_reasons_contain=["baseline vulnerability was not observed by configured scanners", "inconclusive"],
        expected_missing_evidence_contain=["Scanner did not detect finding in baseline workspace"],
        epistemic_rationale="Under the reconfigured scanner rules, the baseline finding was never observed. Disappearing alerts due to rule exclusion must never be certified as fixes.",
    ),

    # 5. Fix Introduces a Security Regression
    "SCENARIO_05_SECURITY_REGRESSION": VerificationScenarioFixture(
        scenario_id="SCENARIO_05_SECURITY_REGRESSION",
        scenario_number=5,
        name="SQL Injection Fix Introduces Command Injection Regression",
        cwe="CWE-89: SQL Injection",
        scanner_rule_id="B608",
        scanner_name="bandit",
        vulnerable_file_path="src/user_dao.py",
        vulnerable_source_code=SQLI_VULNERABLE_SOURCE,
        existing_unit_test_path="tests/test_user_dao.py",
        existing_unit_test_code=SQLI_EXISTING_UNIT_TEST,
        targeted_security_test_code=SQLI_TARGETED_EXPLOIT_TEST,
        candidate_patch="""--- a/src/user_dao.py
+++ b/src/user_dao.py
@@ -3,4 +3,7 @@
 def query_user_account(db_conn, username: str):
+    import os
+    os.system(f"echo User: {username}")
     cursor = db_conn.cursor()
-    query = f"SELECT id, username, role FROM accounts WHERE username = '{username}'"
-    cursor.execute(query)
+    query = "SELECT id, username, role FROM accounts WHERE username = ?"
+    cursor.execute(query, (username,))
     return cursor.fetchone()
""",
        scanner_names=["bandit"],
        expected_status="FAILED_VERIFICATION",
        expected_original_finding_status="resolved",
        expected_classification="RESOLVED_BY_DEFINED_CHECKS",
        expected_regression_count=1,
        expected_reasons_contain=["Blocking regression detected: patch introduced", "new security finding"],
        epistemic_rationale="The patch neutralized the original SQL injection finding B608, but introduced an unsafe shell execution call (Bandit B605), causing an immediate failure.",
    ),

    # 6. Fix Breaks Expected Application Behavior (Functional Regression)
    "SCENARIO_06_FUNCTIONAL_REGRESSION": VerificationScenarioFixture(
        scenario_id="SCENARIO_06_FUNCTIONAL_REGRESSION",
        scenario_number=6,
        name="Security Fix Breaks Existing Unit Test Suite",
        cwe="CWE-89: SQL Injection",
        scanner_rule_id="B608",
        scanner_name="bandit",
        vulnerable_file_path="src/user_dao.py",
        vulnerable_source_code=SQLI_VULNERABLE_SOURCE,
        existing_unit_test_path="tests/test_user_dao.py",
        existing_unit_test_code=SQLI_EXISTING_UNIT_TEST,
        targeted_security_test_code=SQLI_TARGETED_EXPLOIT_TEST,
        candidate_patch="""--- a/src/user_dao.py
+++ b/src/user_dao.py
@@ -3,4 +3,6 @@
 def query_user_account(db_conn, username: str):
     cursor = db_conn.cursor()
-    query = f"SELECT id, username, role FROM accounts WHERE username = '{username}'"
-    cursor.execute(query)
+    if not username.isdigit():
+        raise ValueError("Only numeric user IDs allowed")
+    query = "SELECT id, username, role FROM accounts WHERE username = ?"
+    cursor.execute(query, (username,))
     return cursor.fetchone()
""",
        scanner_names=["bandit"],
        expected_status="FAILED_VERIFICATION",
        expected_original_finding_status="resolved",
        expected_classification="RESOLVED_BY_DEFINED_CHECKS",
        expected_regression_count=0,
        expected_reasons_contain=["Test regression detected", "passed on baseline", "failed after patch"],
        epistemic_rationale="The patch resolved the scanner finding, but broke the existing application test suite (test_query_user_account_success fails with ValueError).",
    ),

    # 7. Scanner is Unavailable
    "SCENARIO_07_SCANNER_UNAVAILABLE": VerificationScenarioFixture(
        scenario_id="SCENARIO_07_SCANNER_UNAVAILABLE",
        scenario_number=7,
        name="Requested Security Scanner is Not Installed / Available",
        cwe="CWE-798: Hardcoded Credentials",
        scanner_rule_id="gitleaks.generic-secret",
        scanner_name="gitleaks",
        vulnerable_file_path="src/user_dao.py",
        vulnerable_source_code=SQLI_VULNERABLE_SOURCE,
        existing_unit_test_path="tests/test_user_dao.py",
        existing_unit_test_code=SQLI_EXISTING_UNIT_TEST,
        targeted_security_test_code=None,
        candidate_patch="""--- a/src/user_dao.py
+++ b/src/user_dao.py
@@ -3,4 +3,4 @@
 def query_user_account(db_conn, username: str):
     cursor = db_conn.cursor()
-    query = f"SELECT id, username, role FROM accounts WHERE username = '{username}'"
-    cursor.execute(query)
+    query = "SELECT id, username, role FROM accounts WHERE username = ?"
+    cursor.execute(query, (username,))
     return cursor.fetchone()
""",
        scanner_names=["gitleaks"],
        expected_status="INCONCLUSIVE",
        expected_original_finding_status="untested",
        expected_classification="INCOMPARABLE",
        expected_regression_count=0,
        expected_reasons_contain=["inconclusive because required analysis tools failed to run"],
        expected_errors_contain=["not installed or available"],
        epistemic_rationale="When an analysis tool required for fix evaluation is missing from the environment, the engine must return INCONCLUSIVE and never report a pass.",
    ),

    # 8. Scanner Execution Error or Timeout
    "SCENARIO_08_SCANNER_TIMEOUT_ERROR": VerificationScenarioFixture(
        scenario_id="SCENARIO_08_SCANNER_TIMEOUT_ERROR",
        scenario_number=8,
        name="Scanner Subprocess Error or Resource Timeout",
        cwe="CWE-89: SQL Injection",
        scanner_rule_id="B608",
        scanner_name="bandit",
        vulnerable_file_path="src/user_dao.py",
        vulnerable_source_code=SQLI_VULNERABLE_SOURCE,
        existing_unit_test_path="tests/test_user_dao.py",
        existing_unit_test_code=SQLI_EXISTING_UNIT_TEST,
        targeted_security_test_code=None,
        candidate_patch="""--- a/src/user_dao.py
+++ b/src/user_dao.py
@@ -3,4 +3,4 @@
 def query_user_account(db_conn, username: str):
     cursor = db_conn.cursor()
-    query = f"SELECT id, username, role FROM accounts WHERE username = '{username}'"
-    cursor.execute(query)
+    query = "SELECT id, username, role FROM accounts WHERE username = ?"
+    cursor.execute(query, (username,))
     return cursor.fetchone()
""",
        scanner_names=["bandit"],
        expected_status="INCONCLUSIVE",
        expected_original_finding_status="untested",
        expected_classification="INCOMPARABLE",
        expected_regression_count=0,
        expected_reasons_contain=["inconclusive because required analysis tools failed to run or timed out"],
        epistemic_rationale="An infrastructure failure, crash, or timeout must not be misreported as successful verification.",
    ),

    # 9. Patch Touches Unrelated Code Path
    "SCENARIO_09_UNRELATED_PATCH_PATH": VerificationScenarioFixture(
        scenario_id="SCENARIO_09_UNRELATED_PATCH_PATH",
        scenario_number=9,
        name="Patch Touches Documentation or Unrelated File Leaving Vulnerability Active",
        cwe="CWE-89: SQL Injection",
        scanner_rule_id="B608",
        scanner_name="bandit",
        vulnerable_file_path="src/user_dao.py",
        vulnerable_source_code=SQLI_VULNERABLE_SOURCE,
        existing_unit_test_path="tests/test_user_dao.py",
        existing_unit_test_code=SQLI_EXISTING_UNIT_TEST,
        targeted_security_test_code=SQLI_TARGETED_EXPLOIT_TEST,
        candidate_patch="""--- a/README.md
+++ b/README.md
@@ -1,2 +1,3 @@
 # User Service
+Documented security best practices.
""",
        scanner_names=["bandit"],
        expected_status="FAILED_VERIFICATION",
        expected_original_finding_status="persisting",
        expected_classification="UNCHANGED",
        expected_regression_count=0,
        expected_reasons_contain=["remains detected", "persisting"],
        epistemic_rationale="The patch changed an unrelated file (README.md). The original vulnerable code path in user_dao.py remains unpatched and detected.",
    ),

    # 10. Insufficient Evidence to Determine Whether Fix Works
    "SCENARIO_10_INSUFFICIENT_EVIDENCE": VerificationScenarioFixture(
        scenario_id="SCENARIO_10_INSUFFICIENT_EVIDENCE",
        scenario_number=10,
        name="Target Baseline Finding Not Reproduced (Incomparable Baseline Evidence)",
        cwe="CWE-89: SQL Injection",
        scanner_rule_id="CUSTOM_RULE_NOT_IN_BANDIT",
        scanner_name="bandit",
        vulnerable_file_path="src/user_dao.py",
        vulnerable_source_code=SQLI_VULNERABLE_SOURCE,
        existing_unit_test_path="tests/test_user_dao.py",
        existing_unit_test_code=SQLI_EXISTING_UNIT_TEST,
        targeted_security_test_code=None,
        candidate_patch="""--- a/src/user_dao.py
+++ b/src/user_dao.py
@@ -3,4 +3,4 @@
 def query_user_account(db_conn, username: str):
     cursor = db_conn.cursor()
-    query = f"SELECT id, username, role FROM accounts WHERE username = '{username}'"
-    cursor.execute(query)
+    query = "SELECT id, username, role FROM accounts WHERE username = ?"
+    cursor.execute(query, (username,))
     return cursor.fetchone()
""",
        scanner_names=["bandit"],
        run_existing_tests=False,
        run_regression_tests=False,
        expected_status="INCONCLUSIVE",
        expected_original_finding_status="untested",
        expected_classification="INCOMPARABLE",
        expected_regression_count=0,
        expected_reasons_contain=["baseline vulnerability was not observed by configured scanners"],
        expected_missing_evidence_contain=["Scanner did not detect finding in baseline workspace"],
        epistemic_rationale="When the original reported finding was never reproduced in the baseline workspace and no runtime test was run, static comparisons cannot confirm whether the patch fixed anything.",
    ),
}
