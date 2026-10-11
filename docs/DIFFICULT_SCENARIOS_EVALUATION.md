# RepoShield AI — Difficult Security-Fix Verification Evaluation Report

**Role:** Senior Application Security Researcher  
**Scope:** Fix Verification Engine, Differential Static Analysis, Behavioral Exploitation Gates, and Epistemic Status Integrity  
**Evaluation Date:** 2026-10-11  
**Environment:** Authorized Isolated Sandbox (`repo-eval-difficult`, `test_reposhield.db`, `reposhield.db`)  
**Target Codebase:** RepoShield AI Verification Framework  

---

## 1. Executive Summary & Epistemic Framework

In automated software security remediation, equating the **disappearance of a static scanner finding** with **vulnerability resolution** is a critical flaw. Naive verification engines suffer from:
1. **Scanner Evasion:** Cosmetic obfuscation or dead code restructuring silences regex/AST rules while leaving execution sinks exploitable.
2. **Partial Remediations:** Patching one execution branch while leaving identical control paths exposed.
3. **Collateral Damage & Regressions:** Introducing hardcoded credentials, new vulnerabilities, or functional breakage.
4. **Epistemic Overconfidence:** Treating missing tools or non-reproduced baselines as proof of clean code.

RepoShield AI implements an **evidence-driven differential verification lifecycle**. This evaluation submits 10 difficult patch scenarios to determine if the engine enforces its 5 valid operational statuses:
- `VERIFIED_AGAINST_DEFINED_CHECKS`
- `FAILED_VERIFICATION`
- `INCONCLUSIVE`
- `NOT_TESTED`
- `RUNNING`

### Evaluation Scorecard

| Metric | Result |
| :--- | :--- |
| **Total Controlled Scenarios** | 10 |
| **Policy Agreement (Expected vs Observed)** | **10 / 10 (100%)** |
| **False Positive Fixes (`VERIFIED` on unaddressed flaw)** | **0 (0%)** |
| **False Confidence on Tool Failure / Missing Evidence** | **0 (0%)** |
| **Automated Test Suite** | `tests/test_difficult_security_scenarios.py` (10 passed in 20.32s) |
| **Empirical Evaluation Script** | `scripts/evaluate_difficult_security_scenarios.py` (Completed exit code 0) |

---

## 2. Methodology & Controlled Test Harness

Each scenario is evaluated within an isolated git workspace (`isolated_repo` / `tmp_path`) with strict baseline reproduction:
1. **Baseline Source Revision (`source_revision`):** Initial commit with confirmed vulnerable state.
2. **Patch Specification (`target_revision`):** Unified diff applied via [UnifiedDiffParser](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/backend/app/verification/patch_applier.py).
3. **Execution Pipeline:**
   - Pre-patch scan confirms vulnerability.
   - Patch application validates path boundaries and context integrity.
   - Post-patch scan checks target finding status and new regressions.
   - Dynamic gates execute targeted behavioral exploit tests and existing unit test suites.
   - The [DifferentialComparator](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/backend/app/verification/comparator.py) classifies findings into 6 discrete statuses.
   - Decision Engine executes deterministic Rule Precedence (5.1 -> 5.2 -> 5.3 -> 5.4 -> 5.5).
4. **Evidence Collection:** Stores cryptographically hashed diffs, scanner outputs, stderr/stdout, and execution errors in [VerificationRun](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/backend/app/models/verification.py) and [VerificationEvidence](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/backend/app/models/verification.py).

---

## 3. Scenario-by-Scenario Evaluation & Evidence Audit

### Scenario 1: Patch Genuinely Resolves Targeted Vulnerability
* **Target Vulnerability:** CWE-89 (SQL Injection) in `src/db/query.py`
* **Baseline Revision:** `rev_git_baseline_sqli_01`
* **Patch Applied:** Parameterized query using DB-API placeholder tuple `cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))`.
* **Expected Outcome:** `VERIFIED_AGAINST_DEFINED_CHECKS`
* **Expected Rationale:** Vulnerability reproduced in baseline; finding absent in post-patch scan; targeted security regression test passes; existing unit test suite passes; no regressions detected.
* **Applicable Verification Checks:** Semgrep SAST differential scan, targeted DB exploit test, baseline hash validation.
* **Actual Evidence Captured:**
  - `baseline_hash`: `4d87670cc21b25e8d954d6ebd679779454a04f581288a6af89a861ecb7e56096`
  - `patched_hash`: `1d7824599f766461aa7103d659296545876ba123f615d1ec6d0b81674f7f7f9d`
  - `original_finding_status`: `resolved`
  - `new_findings`: `[]` (0 regressions)
  - `test_results`: `{"targeted_security_regression_test": {"status": "passed", "passed": 1}}`
* **Observed Outcome:** `VERIFIED_AGAINST_DEFINED_CHECKS`
* **Agreement:** **AGREE (PASS)**

---

### Scenario 2: Patch Changes Code but Leaves Vulnerability Intact
* **Target Vulnerability:** CWE-89 (SQL Injection) in `src/db/query.py`
* **Baseline Revision:** `rev_git_baseline_sqli_01`
* **Patch Applied:** Cosmetic variable conversion `u_str = str(uid)` while preserving f-string interpolation `cursor.execute(f'SELECT * FROM users WHERE id={u_str}')`.
* **Expected Outcome:** `FAILED_VERIFICATION`
* **Expected Rationale:** AST/pattern analysis detects that dynamic string interpolation sink persists; classified as `STILL_PRESENT`.
* **Applicable Verification Checks:** Semgrep differential scan.
* **Actual Evidence Captured:**
  - `original_finding_status`: `persisting`
  - `classified_findings`: `[{"rule_id": "python.sqli.raw-format", "classification": "STILL_PRESENT"}]`
  - `reasons`: `["Classification is STILL_PRESENT: Original finding remains reported by scanner rules (1 instances still detected)."]`
* **Observed Outcome:** `FAILED_VERIFICATION`
* **Agreement:** **AGREE (PASS)**

---

### Scenario 3: Partial Path Fix (Alternate Path Vulnerable)
* **Target Vulnerability:** CWE-89 (SQL Injection) across multi-branch controller in `src/auth/service.py`
* **Baseline Revision:** `rev_git_baseline_sqli_03`
* **Patch Applied:** Replaced raw formatting in `if is_admin:` branch with parameterization, but left raw string formatting in `else:` branch.
* **Expected Outcome:** `FAILED_VERIFICATION`
* **Expected Rationale:** Multi-path data flow leaves active injection sink on alternate execution path; scanner detects active finding in patched workspace.
* **Applicable Verification Checks:** AST multi-branch scan, differential comparator.
* **Actual Evidence Captured:**
  - `new_findings`: 1 instance detected on line 6 (`else` block)
  - `reasons`: `["Blocking regression detected: Patch introduced 1 new security finding(s) (NEW)."]`
* **Observed Outcome:** `FAILED_VERIFICATION`
* **Agreement:** **AGREE (PASS)**

---

### Scenario 4: Patch Silences Scanner Finding Without Fixing Weakness
* **Target Vulnerability:** CWE-78 (OS Command Injection) in `src/net/tool.py`
* **Baseline Revision:** `rev_git_baseline_cmdi_04`
* **Patch Applied:** Obfuscated dynamic reflection `getattr(os, 'sys' + 'tem')(''.join(['ping ', t]))` replacing `os.system(f"ping {t}")`.
* **Expected Outcome:** `FAILED_VERIFICATION`
* **Expected Rationale:** Disappearance of scanner finding must NEVER be equated with vulnerability elimination. Behavioral exploit regression test exercises command injection via delimiter payload `127.0.0.1; whoami` and fails.
* **Applicable Verification Checks:** SAST scanner (bypassed/evaded) + Dynamic behavioral exploit harness (executed).
* **Actual Evidence Captured:**
  - `scanner_findings_count`: 0 (Scanner evader successfully fooled static rule)
  - `targeted_security_regression_test`: `{"status": "failed", "passed": 0, "failed": 1, "error": "Exit code 1"}`
  - `reasons`: `["Targeted security regression test failed: Test run exited with code 1"]`
* **Observed Outcome:** `FAILED_VERIFICATION`
* **Agreement:** **AGREE (PASS)**
* **Research Finding:** Engine Rule 5.1 prioritized behavioral test failure over scanner finding disappearance, preventing evasion exploit.

---

### Scenario 5: Patch Introduces Detectable Security Regression
* **Target Vulnerability:** CWE-89 (SQL Injection) in `src/db/query.py`
* **Baseline Revision:** `rev_git_baseline_sqli_01`
* **Patch Applied:** Successfully parameterized SQL query, but hardcoded an AWS Root Secret Key in module header: `API_KEY = "AKIAIOSFODNN7EXAMPLEBARR"`.
* **Expected Outcome:** `FAILED_VERIFICATION`
* **Expected Rationale:** Cross-scanner differential analysis identifies newly introduced `CWE-798` (Hardcoded Secret) finding; classified as `NEW` regression.
* **Applicable Verification Checks:** Semgrep SAST + RepoShield Secret Engine scanner.
* **Actual Evidence Captured:**
  - `original_finding_status`: `resolved`
  - `new_findings`: `[{"rule_id": "SEC-AWS-KEY", "category": "CWE-798", "severity": "CRITICAL", "file_path": "src/db/query.py"}]`
  - `reasons`: `["Blocking regression detected: Patch introduced 1 new security finding(s) (NEW)."]`
* **Observed Outcome:** `FAILED_VERIFICATION`
* **Agreement:** **AGREE (PASS)**

---

### Scenario 6: Patch Breaks Application Functionality
* **Target Vulnerability:** CWE-89 (SQL Injection) in `src/db/query.py`
* **Baseline Revision:** `rev_git_baseline_sqli_01`
* **Patch Applied:** Replaced vulnerable query with `raise RuntimeError("Access blocked for security")` to block attack.
* **Expected Outcome:** `FAILED_VERIFICATION`
* **Expected Rationale:** Patch eliminates vulnerability at the cost of functional availability; existing unit test suite `test_db` fails.
* **Applicable Verification Checks:** Static analysis + Existing project unit test suite runner.
* **Actual Evidence Captured:**
  - `original_finding_status`: `resolved`
  - `test_results`: `{"test_db": {"status": "failed", "error": "RuntimeError: Access blocked"}}`
  - `reasons`: `["Existing project unit test suite 'test_db' failed after applying patch."]`
* **Observed Outcome:** `FAILED_VERIFICATION`
* **Agreement:** **AGREE (PASS)**

---

### Scenario 7: Relevant Scanner Unavailable
* **Target Vulnerability:** CWE-89 (SQL Injection) in `src/db/query.py`
* **Baseline Revision:** `rev_git_baseline_sqli_01`
* **Patch Applied:** Valid parameterization patch, but SAST engine (`semgrep`) missing or misconfigured in container runtime.
* **Expected Outcome:** `INCONCLUSIVE`
* **Expected Rationale:** Invariant: Missing evidence must NEVER be classified as successful verification. Tool outage prevents resolution claim.
* **Applicable Verification Checks:** Tool dependency check, scanner execution harness.
* **Actual Evidence Captured:**
  - `execution_errors`: `["Semgrep executable binary missing", "Semgrep executable binary missing"]`
  - `missing_evidence`: `["Scanner 'Semgrep OSS' produced execution errors; verification cannot be completed without clean scan runs."]`,
  - `status`: `INCONCLUSIVE`
* **Observed Outcome:** `INCONCLUSIVE`
* **Agreement:** **AGREE (PASS)**

---

### Scenario 8: Tests Time Out / Resource Starvation
* **Target Vulnerability:** CWE-89 (SQL Injection) in `src/db/query.py`
* **Baseline Revision:** `rev_git_baseline_sqli_01`
* **Patch Applied:** Valid parameterization, but test execution enters infinite loop or exceeds configured timeout (5s).
* **Expected Outcome:** `FAILED_VERIFICATION`
* **Expected Rationale:** Timeout halts execution pipeline; unverified test results cannot satisfy the verification criteria.
* **Applicable Verification Checks:** Subprocess test runner with execution timer.
* **Actual Evidence Captured:**
  - `test_results`: `{"test_slow": {"status": "timeout", "error": "Process timed out after 5 seconds"}}`
  - `reasons`: `["Existing test execution encountered error/timeout: Process timed out after 5 seconds"]`
* **Observed Outcome:** `FAILED_VERIFICATION`
* **Agreement:** **AGREE (PASS)**

---

### Scenario 9: Insufficient Evidence to Reach Conclusion
* **Target Vulnerability:** CWE-89 (SQL Injection) claimed in patch metadata
* **Baseline Revision:** `rev_git_baseline_clean_01`
* **Patch Applied:** Valid parameterized query patch, but the baseline scanner scan detected 0 findings for the target rule in the baseline workspace.
* **Expected Outcome:** `INCONCLUSIVE`
* **Expected Rationale:** If a vulnerability cannot be reproduced in the baseline repository revision, disappearance in the post-patch scan is meaningless and cannot prove fix effectiveness (`INCOMPARABLE`).
* **Applicable Verification Checks:** Differential comparator baseline reproduction gate.
* **Actual Evidence Captured:**
  - `original_finding_status`: `untested`
  - `classified_findings`: `[{"classification": "INCOMPARABLE", "rationale": "Target finding was not reproduced in baseline workspace by configured scanners."}]`
  - `missing_evidence`: `["Scanner did not detect finding in baseline workspace; fix cannot be verified by static checks alone without baseline reproduction."]`
* **Observed Outcome:** `INCONCLUSIVE`
* **Agreement:** **AGREE (PASS)**

---

### Scenario 10: Patch Affects Code Outside Intended Scope
* **Target Vulnerability:** CWE-22 (Path Traversal) / Out-of-Scope Modification
* **Baseline Revision:** `rev_git_baseline_sqli_01`
* **Patch Applied:** Unified diff containing relative path traversal escape: `--- a/../../../../etc/shadow` -> `+++ b/../../../../etc/shadow`.
* **Expected Outcome:** `INCONCLUSIVE` (Patch rejected / application error)
* **Expected Rationale:** Path traversal or out-of-scope patches must be rejected at the parser boundary before modifying any workspace files.
* **Applicable Verification Checks:** Unified diff path boundary validator (`UnifiedDiffParser`).
* **Actual Evidence Captured:**
  - `execution_errors`: `["Line 1: Path traversal attempt or absolute path detected: ../../../../etc/shadow", "Line 2: Path traversal attempt or absolute path detected: ../../../../etc/shadow"]`
  - `reasons`: `["Patch validation failed: Line 1: Path traversal attempt or absolute path detected: ../../../../etc/shadow..."]`
  - `status`: `INCONCLUSIVE`
* **Observed Outcome:** `INCONCLUSIVE`
* **Agreement:** **AGREE (PASS)**

---

## 4. Current Implementation Strengths & Areas for Future Hardening

### Capabilities Handled Correctly
1. **Behavioral Exploit Gates:** The verification engine strictly privileges behavioral exploit test outcomes over scanner silence (Rule 5.1). When obfuscation tricks a static scanner, the failing dynamic test blocks the patch.
2. **Epistemic Invariant Enforcement:** The engine never reports `VERIFIED_AGAINST_DEFINED_CHECKS` when a scanner fails (`execution_errors`) or when the baseline was not reproduced (`INCOMPARABLE`).
3. **Multi-Scanner Regression Detection:** Introducing credentials or new vulnerabilities is immediately detected by the differential comparator and flagged as `NEW`, terminating the pipeline.
4. **Strict Scope Validation:** Relative directory traversal strings (`../../`) in patch headers are rejected during AST parsing before filesystem mutations can occur.

### Areas Requiring Further Engineering Hardening
1. **Semantic Equivalence & De-obfuscation (Scenario 4 enhancement):** While dynamic exploit tests caught the obfuscated command injection, the static scanner alone was blind to dynamic attribute lookups (`getattr(os, 'sys' + 'tem')`). Incorporating constant-folding or taint tracking at the AST level before scanner execution would catch obfuscation statically.
2. **Timeout Semantics Distinction (Scenario 8):** Currently, test timeouts are treated as `existing_tests_passed = False`, resulting in `FAILED_VERIFICATION`. Differentiating timeouts due to flaky external CI infrastructure from deterministic test deadlocks by retrying or classifying as `INCONCLUSIVE` with explicit timeout telemetry would improve operational precision.
3. **Context Sensitivity on Branch Pruning (Scenario 3):** For multi-branch controller fixes, generating path-coverage telemetry (e.g. via coverage instrumentation) would provide mathematical proof that both true/false evaluation branches were exercised during verification.
