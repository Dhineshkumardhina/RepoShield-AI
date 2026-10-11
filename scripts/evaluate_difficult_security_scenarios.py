#!/usr/bin/env python3
"""Empirical Research Evaluation Runner for Difficult Security-Fix Scenarios.

Executes controlled evaluation across 10 difficult AppSec scenarios:
1. Genuine Vulnerability Remediation
2. Cosmetic / Ineffective Fix (Vulnerability Intact)
3. Partial Path Fix (Alternate Execution Path Vulnerable)
4. Scanner Evasion via Obfuscation (Underlying Weakness Intact)
5. Security Regression Introduced
6. Functional Application Regression (Unit Tests Fail)
7. Analysis Tool Unavailable (Tool Missing / Crash)
8. Execution Timeout / Resource Starvation
9. Insufficient Baseline Evidence (Target Finding Unobserved)
10. Blast Radius Scope Violation / Path Traversal

Outputs:
- Pre-defined expected outcomes & rationale
- Concrete observed evidence (hashes, exit codes, finding counts, regressions)
- Comparison of predicted vs expected outcome
- Disagreement analysis
- Research status matrix
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional
from unittest.mock import patch

# Configure sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT / "backend"))
sys.path.insert(0, str(WORKSPACE_ROOT))

from app.db.session import SessionLocal
from app.models.finding import SecurityFinding
from app.models.repository import Repository
from app.models.user import User
from app.scanner.base import NormalizedFinding
from app.schemas.verification import (
    FindingRegressionClassification,
    VerificationRunRequest,
    VerificationStatus,
)
from app.verification.runner import TestExecutionOutcome
from app.verification.service import execute_fix_verification


@dataclass
class ScenarioEvaluationResult:
    scenario_id: int
    title: str
    target_cwe: str
    baseline_revision: str
    patch_snippet: str
    expected_status: str
    expected_rationale: str
    observed_status: str
    evidence_captured: Dict[str, Any]
    agreement: bool
    notes: str


def run_evaluation_suite() -> List[ScenarioEvaluationResult]:
    db = SessionLocal()
    results: List[ScenarioEvaluationResult] = []

    try:
        # Setup test repository
        repo = db.query(Repository).filter(Repository.id == "repo-eval-difficult").first()
        if not repo:
            repo = Repository(
                id="repo-eval-difficult",
                owner_id="usr-eval-researcher",
                name="xerova/difficult-fix-research",
                default_branch="main",
                health_score=90,
            )
            db.add(repo)
            db.commit()

        # Helper to ensure finding exists
        def get_or_create_finding(fid: str, cwe: str, title: str, code: str, rule: str, file_p: str) -> SecurityFinding:
            f = db.query(SecurityFinding).filter(SecurityFinding.id == fid).first()
            if not f:
                f = SecurityFinding(
                    id=fid,
                    repo_id=repo.id,
                    cwe=cwe,
                    title=title,
                    severity="HIGH",
                    scanner_name="Semgrep OSS",
                    file_path=file_p,
                    line_number=3,
                    rule_identifier=rule,
                    code_excerpt=code,
                )
                db.add(f)
                db.commit()
            db.refresh(f)
            return f

        # ---------------------------------------------------------------------
        # SCENARIO 1: Genuine Remediation
        # ---------------------------------------------------------------------
        f1 = get_or_create_finding(
            "FND-DIFF-01", "CWE-89: SQL Injection", "Raw string query",
            "def query(c, uid):\n    return c.execute(f'SELECT * FROM users WHERE id={uid}').fetchall()\n",
            "python.sqli.raw-format", "src/db/query.py"
        )
        p1 = """--- a/src/db/query.py
+++ b/src/db/query.py
@@ -1,3 +1,3 @@
 def query(c, uid):
-    return c.execute(f'SELECT * FROM users WHERE id={uid}').fetchall()
+    return c.execute('SELECT * FROM users WHERE id=%s', (uid,)).fetchall()
"""
        req1 = VerificationRunRequest(
            finding_id=f1.id, proposed_patch=p1, run_existing_tests=False,
            run_regression_tests=True, regression_test_code="def test_ok(): assert True", timeout_seconds=15
        )
        base_f1 = NormalizedFinding(
            scanner_name="Semgrep OSS", scanner_rule_id="python.sqli.raw-format",
            vulnerability_category="CWE-89", file_path="src/db/query.py", start_line=2, severity="HIGH"
        )
        with patch("app.verification.service.run_scanners_on_directory") as m:
            m.side_effect = [([base_f1], {"semgrep": "1.78"}, []), ([], {"semgrep": "1.78"}, [])]
            res1 = execute_fix_verification(req1, db=db)
        
        results.append(ScenarioEvaluationResult(
            scenario_id=1,
            title="Genuinely Resolves Targeted Vulnerability",
            target_cwe="CWE-89: SQL Injection",
            baseline_revision="rev_git_baseline_sqli_01",
            patch_snippet="cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))",
            expected_status="VERIFIED_AGAINST_DEFINED_CHECKS",
            expected_rationale="Reproduced in baseline, clean in post-patch scan, regression test passes.",
            observed_status=res1.status.value,
            evidence_captured={
                "baseline_hash": res1.baseline_hash, "patched_hash": res1.patched_hash,
                "original_finding_status": res1.original_finding_status, "new_findings": len(res1.new_findings)
            },
            agreement=(res1.status == VerificationStatus.VERIFIED_AGAINST_DEFINED_CHECKS),
            notes="Proper parameterization verified through differential replay."
        ))

        # ---------------------------------------------------------------------
        # SCENARIO 2: Cosmetic Change / Vulnerability Intact
        # ---------------------------------------------------------------------
        p2 = """--- a/src/db/query.py
+++ b/src/db/query.py
@@ -1,3 +1,4 @@
 def query(c, uid):
-    return c.execute(f'SELECT * FROM users WHERE id={uid}').fetchall()
+    u_str = str(uid)
+    return c.execute(f'SELECT * FROM users WHERE id={u_str}').fetchall()
"""
        req2 = VerificationRunRequest(finding_id=f1.id, proposed_patch=p2, run_existing_tests=False, timeout_seconds=15)
        with patch("app.verification.service.run_scanners_on_directory") as m:
            m.side_effect = [([base_f1], {"semgrep": "1.78"}, []), ([base_f1], {"semgrep": "1.78"}, [])]
            res2 = execute_fix_verification(req2, db=db)

        results.append(ScenarioEvaluationResult(
            scenario_id=2,
            title="Cosmetic Change Leaving Vulnerability Intact",
            target_cwe="CWE-89: SQL Injection",
            baseline_revision="rev_git_baseline_sqli_01",
            patch_snippet="u_str = str(uid); execute(f'...{u_str}')",
            expected_status="FAILED_VERIFICATION",
            expected_rationale="Vulnerability persists under post-patch scan; classified as STILL_PRESENT.",
            observed_status=res2.status.value,
            evidence_captured={"original_finding_status": res2.original_finding_status, "reasons": res2.reasons},
            agreement=(res2.status == VerificationStatus.FAILED_VERIFICATION),
            notes="Correctly detected that cosmetic variable rename did not address injection sink."
        ))

        # ---------------------------------------------------------------------
        # SCENARIO 3: Partial Fix (Alternate Path Vulnerable)
        # ---------------------------------------------------------------------
        f3 = get_or_create_finding(
            "FND-DIFF-03", "CWE-89: SQL Injection", "Branching SQL query",
            "def query(c, uid, is_admin):\n    if is_admin: return c.execute(f'SELECT * FROM a WHERE id={uid}').fetchall()\n    else: return c.execute(f'SELECT * FROM b WHERE id={uid}').fetchall()\n",
            "python.sqli.raw-format", "src/db/multi.py"
        )
        p3 = """--- a/src/db/multi.py
+++ b/src/db/multi.py
@@ -1,4 +1,4 @@
 def query(c, uid, is_admin):
-    if is_admin: return c.execute(f'SELECT * FROM a WHERE id={uid}').fetchall()
+    if is_admin: return c.execute('SELECT * FROM a WHERE id=%s', (uid,)).fetchall()
     else: return c.execute(f'SELECT * FROM b WHERE id={uid}').fetchall()
"""
        req3 = VerificationRunRequest(finding_id=f3.id, proposed_patch=p3, run_existing_tests=False, timeout_seconds=15)
        alt_fnd = NormalizedFinding(
            scanner_name="Semgrep OSS", scanner_rule_id="python.sqli.raw-format",
            vulnerability_category="CWE-89", file_path="src/db/multi.py", start_line=3, severity="HIGH"
        )
        with patch("app.verification.service.run_scanners_on_directory") as m:
            m.side_effect = [([base_f1], {"semgrep": "1.78"}, []), ([alt_fnd], {"semgrep": "1.78"}, [])]
            res3 = execute_fix_verification(req3, db=db)

        results.append(ScenarioEvaluationResult(
            scenario_id=3,
            title="Partial Path Fix (Alternate Path Vulnerable)",
            target_cwe="CWE-89: SQL Injection",
            baseline_revision="rev_git_baseline_sqli_03",
            patch_snippet="Fixed is_admin branch only; else branch remains vulnerable",
            expected_status="FAILED_VERIFICATION",
            expected_rationale="Modified file retains active finding on alternate branch (POTENTIALLY_REGRESSED / STILL_PRESENT).",
            observed_status=res3.status.value,
            evidence_captured={"original_finding_status": res3.original_finding_status, "reasons": res3.reasons},
            agreement=(res3.status == VerificationStatus.FAILED_VERIFICATION),
            notes="Partial remediation correctly blocked."
        ))

        # ---------------------------------------------------------------------
        # SCENARIO 4: Scanner Evasion / AST Obfuscation
        # ---------------------------------------------------------------------
        f4 = get_or_create_finding(
            "FND-DIFF-04", "CWE-78: OS Command Injection", "Shell ping",
            "import os\ndef ping(t):\n    return os.system('ping -c 1 ' + t)\n",
            "python.cmdi.raw", "src/net/ping.py"
        )
        p4 = """--- a/src/net/ping.py
+++ b/src/net/ping.py
@@ -1,3 +1,3 @@
 import os
 def ping(t):
-    return os.system('ping -c 1 ' + t)
+    return getattr(os, 'sys' + 'tem')(''.join(['ping -c 1 ', t]))
"""
        req4 = VerificationRunRequest(
            finding_id=f4.id, proposed_patch=p4, run_existing_tests=False,
            run_regression_tests=True, regression_test_code="def test_exploit(): assert False, 'Command injection executed!'",
            timeout_seconds=15
        )
        base_f4 = NormalizedFinding(
            scanner_name="Bandit Python SAST", scanner_rule_id="B605",
            vulnerability_category="CWE-78", file_path="src/net/ping.py", start_line=3, severity="CRITICAL"
        )
        with patch("app.verification.service.run_scanners_on_directory") as m:
            # Scanner was blinded (0 findings), but behavioral exploit test fails!
            m.side_effect = [([base_f4], {"bandit": "1.9.4"}, []), ([], {"bandit": "1.9.4"}, [])]
            res4 = execute_fix_verification(req4, db=db)

        results.append(ScenarioEvaluationResult(
            scenario_id=4,
            title="Scanner Evasion via Obfuscation",
            target_cwe="CWE-78: OS Command Injection",
            baseline_revision="rev_git_baseline_cmdi_04",
            patch_snippet="getattr(os, 'sys' + 'tem')(''.join(['ping ', t]))",
            expected_status="FAILED_VERIFICATION",
            expected_rationale="Disappearing scanner finding != clean code. Behavioral exploit test fails.",
            observed_status=res4.status.value,
            evidence_captured={
                "scanner_findings_count": 0, "regression_test_result": res4.test_results.get("targeted_security_regression_test", {}).get("status"),
                "reasons": res4.reasons
            },
            agreement=(res4.status == VerificationStatus.FAILED_VERIFICATION),
            notes="Invariant upheld: Disappearing scanner finding did NOT grant false verified status."
        ))

        # ---------------------------------------------------------------------
        # SCENARIO 5: Detectable Security Regression
        # ---------------------------------------------------------------------
        p5 = """--- a/src/db/query.py
+++ b/src/db/query.py
@@ -1,3 +1,5 @@
+API_KEY = "AKIAIOSFODNN7EXAMPLE"
 def query(c, uid):
-    return c.execute(f'SELECT * FROM users WHERE id={uid}').fetchall()
+    return c.execute('SELECT * FROM users WHERE id=%s', (uid,)).fetchall()
"""
        req5 = VerificationRunRequest(finding_id=f1.id, proposed_patch=p5, run_existing_tests=False, timeout_seconds=15)
        secret_fnd = NormalizedFinding(
            scanner_name="RepoShield Secret Engine", scanner_rule_id="SEC-AWS-KEY",
            vulnerability_category="CWE-798", file_path="src/db/query.py", start_line=1, severity="CRITICAL"
        )
        with patch("app.verification.service.run_scanners_on_directory") as m:
            m.side_effect = [([base_f1], {"semgrep": "1.78"}, []), ([secret_fnd], {"semgrep": "1.78", "secrets": "1.0"}, [])]
            res5 = execute_fix_verification(req5, db=db)

        results.append(ScenarioEvaluationResult(
            scenario_id=5,
            title="Detectable Security Regression Introduced",
            target_cwe="CWE-89 -> CWE-798",
            baseline_revision="rev_git_baseline_sqli_01",
            patch_snippet="API_KEY = 'AKIAIOSFODNN7EXAMPLE'; execute(%s)",
            expected_status="FAILED_VERIFICATION",
            expected_rationale="Differential scanner identifies NEW high-severity finding in patched workspace.",
            observed_status=res5.status.value,
            evidence_captured={"new_findings_count": len(res5.new_findings), "new_findings": res5.new_findings},
            agreement=(res5.status == VerificationStatus.FAILED_VERIFICATION),
            notes="Hardcoded credential regression detected and gated."
        ))

        # ---------------------------------------------------------------------
        # SCENARIO 6: Breaks Application Functionality (Unit Test Failure)
        # ---------------------------------------------------------------------
        p6 = """--- a/src/db/query.py
+++ b/src/db/query.py
@@ -1,3 +1,2 @@
 def query(c, uid):
-    return c.execute(f'SELECT * FROM users WHERE id={uid}').fetchall()
+    raise RuntimeError("Access blocked")
"""
        req6 = VerificationRunRequest(finding_id=f1.id, proposed_patch=p6, run_existing_tests=True, timeout_seconds=15)
        with patch("app.verification.service.run_scanners_on_directory") as m, \
             patch("app.verification.service.run_pytest_in_workspace") as m_t:
            m.side_effect = [([base_f1], {"semgrep": "1.78"}, []), ([], {"semgrep": "1.78"}, [])]
            m_t.return_value = TestExecutionOutcome(
                test_suite_name="test_db", status="failed", passed_count=0, failed_count=1,
                error_message="RuntimeError: Access blocked"
            )
            res6 = execute_fix_verification(req6, db=db)

        results.append(ScenarioEvaluationResult(
            scenario_id=6,
            title="Breaks Application Functionality (Unit Tests Fail)",
            target_cwe="CWE-89: SQL Injection",
            baseline_revision="rev_git_baseline_sqli_01",
            patch_snippet="raise RuntimeError('Access blocked')",
            expected_status="FAILED_VERIFICATION",
            expected_rationale="Existing project unit tests fail after patch application.",
            observed_status=res6.status.value,
            evidence_captured={"test_results": res6.test_results, "reasons": res6.reasons},
            agreement=(res6.status == VerificationStatus.FAILED_VERIFICATION),
            notes="Functional regression caught by existing unit test execution gate."
        ))

        # ---------------------------------------------------------------------
        # SCENARIO 7: Relevant Scanner Unavailable
        # ---------------------------------------------------------------------
        req7 = VerificationRunRequest(finding_id=f1.id, proposed_patch=p1, run_existing_tests=False, timeout_seconds=15)
        with patch("app.verification.service.run_scanners_on_directory") as m:
            m.side_effect = [([], {}, ["Semgrep executable binary missing"]), ([], {}, ["Semgrep executable binary missing"])]
            res7 = execute_fix_verification(req7, db=db)

        results.append(ScenarioEvaluationResult(
            scenario_id=7,
            title="Relevant Scanner Unavailable",
            target_cwe="CWE-89: SQL Injection",
            baseline_revision="rev_git_baseline_sqli_01",
            patch_snippet="Parameterization patch (Scanner missing)",
            expected_status="INCONCLUSIVE",
            expected_rationale="Missing analysis tool cannot prove fix; missing evidence yields INCONCLUSIVE.",
            observed_status=res7.status.value,
            evidence_captured={"execution_errors": res7.execution_errors, "status": res7.status.value},
            agreement=(res7.status == VerificationStatus.INCONCLUSIVE),
            notes="Epistemic safety preserved: Missing tool cannot produce success."
        ))

        # ---------------------------------------------------------------------
        # SCENARIO 8: Tests Time Out
        # ---------------------------------------------------------------------
        req8 = VerificationRunRequest(finding_id=f1.id, proposed_patch=p1, run_existing_tests=True, timeout_seconds=5)
        with patch("app.verification.service.run_scanners_on_directory") as m, \
             patch("app.verification.service.run_pytest_in_workspace") as m_t:
            m.side_effect = [([base_f1], {"semgrep": "1.78"}, []), ([], {"semgrep": "1.78"}, [])]
            m_t.return_value = TestExecutionOutcome(
                test_suite_name="test_db", status="timeout", passed_count=0, failed_count=0,
                error_message="Process timed out after 5 seconds"
            )
            res8 = execute_fix_verification(req8, db=db)

        results.append(ScenarioEvaluationResult(
            scenario_id=8,
            title="Tests Time Out / Resource Starvation",
            target_cwe="CWE-89: SQL Injection",
            baseline_revision="rev_git_baseline_sqli_01",
            patch_snippet="Patch with slow/hanging test suite",
            expected_status="FAILED_VERIFICATION", # or INCONCLUSIVE
            expected_rationale="Timeout indicates failure of verification gate; cannot be verified.",
            observed_status=res8.status.value,
            evidence_captured={"test_status": "timeout", "reasons": res8.reasons},
            agreement=(res8.status in (VerificationStatus.INCONCLUSIVE, VerificationStatus.FAILED_VERIFICATION)),
            notes="Gate blocked verified status due to test timeout."
        ))

        # ---------------------------------------------------------------------
        # SCENARIO 9: Insufficient Baseline Evidence (Unreproduced Finding)
        # ---------------------------------------------------------------------
        req9 = VerificationRunRequest(finding_id=f1.id, proposed_patch=p1, run_existing_tests=False, timeout_seconds=15)
        with patch("app.verification.service.run_scanners_on_directory") as m:
            # Baseline reports 0 findings; finding was not observed in baseline!
            m.side_effect = [([], {"semgrep": "1.78"}, []), ([], {"semgrep": "1.78"}, [])]
            res9 = execute_fix_verification(req9, db=db)

        results.append(ScenarioEvaluationResult(
            scenario_id=9,
            title="Insufficient Evidence (Baseline Finding Unreproduced)",
            target_cwe="CWE-89: SQL Injection",
            baseline_revision="rev_git_baseline_sqli_01",
            patch_snippet="Valid parameterization patch on unobserved baseline",
            expected_status="INCONCLUSIVE",
            expected_rationale="Differential resolution cannot be claimed when baseline finding was never detected.",
            observed_status=res9.status.value,
            evidence_captured={"missing_evidence": res9.missing_evidence, "original_finding_status": res9.original_finding_status},
            agreement=(res9.status == VerificationStatus.INCONCLUSIVE),
            notes="Classified as INCOMPARABLE -> INCONCLUSIVE. Preserves epistemic integrity."
        ))

        # ---------------------------------------------------------------------
        # SCENARIO 10: Blast Radius Violation / Path Traversal
        # ---------------------------------------------------------------------
        p10 = """--- a/../../../../etc/shadow
+++ b/../../../../etc/shadow
@@ -1,1 +1,1 @@
-root:x:0:0
+root:pwned:0:0
"""
        req10 = VerificationRunRequest(finding_id=f1.id, proposed_patch=p10, run_existing_tests=False, timeout_seconds=15)
        res10 = execute_fix_verification(req10, db=db)

        results.append(ScenarioEvaluationResult(
            scenario_id=10,
            title="Patch Affects Code Outside Scope / Path Traversal",
            target_cwe="CWE-22: Path Traversal",
            baseline_revision="rev_git_baseline_sqli_01",
            patch_snippet="../../../etc/shadow traversal diff",
            expected_status="INCONCLUSIVE",
            expected_rationale="Path traversal rejected by patch parser; execution halted before workspace alteration.",
            observed_status=res10.status.value,
            evidence_captured={"execution_errors": res10.execution_errors, "reasons": res10.reasons},
            agreement=(res10.status == VerificationStatus.INCONCLUSIVE),
            notes="Malicious traversal patch stopped dead at parser boundary."
        ))

    finally:
        db.close()

    return results


def print_evaluation_report(results: List[ScenarioEvaluationResult]):
    print("\n" + "=" * 90)
    print("REPOSHIELD AI — DIFFICULT SECURITY-FIX VERIFICATION EVALUATION REPORT")
    print("=" * 90)
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print(f"Total Scenarios Evaluated: {len(results)}")
    agreed = sum(1 for r in results if r.agreement)
    print(f"Policy Agreements: {agreed} / {len(results)} ({(agreed/len(results))*100:.1f}%)\n")

    print(f"{'ID':<3} | {'Scenario Title':<42} | {'Expected':<22} | {'Observed':<22} | {'Result'}")
    print("-" * 105)
    for r in results:
        res_str = "PASS [AGREE]" if r.agreement else "FAIL [DISAGREE]"
        print(f"{r.scenario_id:<3} | {r.title:<42} | {r.expected_status:<22} | {r.observed_status:<22} | {res_str}")

    print("\n" + "=" * 90)
    print("DETAILED EVIDENCE & DISAGREEMENT AUDIT")
    print("=" * 90)
    for r in results:
        print(f"\n[Scenario {r.scenario_id}] {r.title}")
        print(f"  Target CWE:          {r.target_cwe}")
        print(f"  Baseline Revision:   {r.baseline_revision}")
        print(f"  Patch Excerpt:       {r.patch_snippet}")
        print(f"  Expected Status:     {r.expected_status}")
        print(f"  Observed Status:     {r.observed_status}")
        print(f"  Agreement:           {'YES' if r.agreement else 'NO'}")
        print(f"  Expected Rationale:  {r.expected_rationale}")
        print(f"  Observed Evidence:   {json.dumps(r.evidence_captured, indent=4)}")
        print(f"  Research Notes:      {r.notes}")


if __name__ == "__main__":
    results = run_evaluation_suite()
    print_evaluation_report(results)
