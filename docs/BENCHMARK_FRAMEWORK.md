# RepoShield AI Benchmark Framework: Empirical Evaluation of Fix Verification

**Version:** 1.0  
**Domain:** Empirical Software Security & Automated Vulnerability Remediation  
**Package:** `benchmark`  

---

## Executive Summary

Automated static application security testing (SAST) tools and AI coding assistants frequently propose patches for detected vulnerabilities. However, evaluating whether a candidate patch genuinely eliminates the vulnerability—without introducing functional regressions or secondary security flaws—remains a major open challenge in software security.

Conventional patch evaluation relies either on:
1. **Static Analysis Alone (SAST delta):** Marking a vulnerability resolved if the static analyzer no longer flags the affected line.
2. **Existing Unit Test Suites Alone:** Running standard project unit tests in CI and approving the patch if existing tests pass.
3. **AI / Large Language Model (LLM) Review Alone:** Prompting an LLM to judge whether the patch diff appears safe.

This benchmark framework implements a rigorous, reproducible empirical methodology to evaluate the central research question:

> **Research Question (RQ):** *Does combining static analysis, targeted security tests, and explicit evidence rules improve the reliability of security-fix evaluation compared with appropriate baseline methods?*

---

## 1. Research Protocol & Hypotheses

### 1.1 Hypotheses
* **Null Hypothesis ($H_0$):** A multi-tier evidence pipeline combining static analysis, targeted security regression tests, and explicit evidence rules yields no statistically significant improvement in verification precision or reduction in false-positive verification rates compared to single-technique baselines (static analysis alone, existing tests alone, or zero-shot LLM review).
* **Alternative Hypothesis ($H_1$):** Multi-tier evidence-based verification yields significantly higher verification precision and a lower false-positive rate by correctly identifying cosmetic evasions, incomplete sanitizers, and regressive patches, while explicitly categorizing unobserved baseline vulnerabilities as inconclusive.

### 1.2 Epistemic Honesty Principles
1. **A disappearing scanner finding alone must NOT establish that a vulnerability is fixed:** AST-level suppressions and syntax reorganizations frequently blind linters without fixing runtime vulnerabilities.
2. **A passing test suite alone must NOT establish that a patch is secure:** Standard unit tests assert nominal application behavior and rarely test malicious exploit payloads.
3. **Uncertainty must be explicitly tracked:** When baseline scanner findings cannot be reproduced or when required test evidence is unavailable, the verdict must be `INCONCLUSIVE`, not an unwarranted pass.

---

## 2. Benchmark Case Architecture & Schema

Each benchmark case conforms to the formal JSON Schema defined in [`benchmark/schema/benchmark_schema.json`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/benchmark/schema/benchmark_schema.json).

### 2.1 Recorded Attributes
Every benchmark case records:
- **Case Identifier (`case_id`):** Unique identifier (e.g., `RS-BENCH-001`).
- **Origin (`origin`):** Dataset origin (`synthetic_curated`, `cve_adapted`, `juliet_benchmark`).
- **Vulnerability Category (`vulnerability_category`, `cwe_id`, `cve_id`):** Normalized classification and CWE identifier.
- **Baseline Source Revision (`baseline_revision`):** Cryptographic SHA-256 digest or unpinned content hash.
- **Source Code (`source_file`, `vulnerable_code`):** Complete baseline file contents containing the construct.
- **Baseline Finding (`baseline_finding`):** Expected scanner rule, category, line number, and severity.
- **Relevant Tests (`existing_unit_test`, `targeted_regression_test`):** General unit tests and targeted exploit assertions.
- **Partition Split (`split`):** Explicit separation into `dev` (development tuning) or `held_out` (unseen evaluation).
- **Candidate Patches (`candidate_patches`):** Array of candidate patches, each with:
  - `patch_id`: Unique identifier (e.g., `RS-001-P1`).
  - `patch_type`: Categorical taxonomy (e.g., `true_fix`, `cosmetic_evasion`, `incomplete_fix`, `regressive_fix`, `security_regression`, `false_positive_finding`, `missing_evidence_case`, `tool_failure_timeout`).
  - `ground_truth_label`: Tri-state ground truth (`FIX`, `NON_FIX`, `INCONCLUSIVE`).
  - `ground_truth_rationale`: Scientific justification for the label.
  - `expected_classification`: Expected verdict (`VERIFIED`, `FAILED`, `INCONCLUSIVE`).
  - `expected_regression_status`: Expected comparator finding status (`RESOLVED_BY_DEFINED_CHECKS`, `STILL_PRESENT`, `POTENTIALLY_REGRESSED`, `NEW`, `UNCHANGED`, `INCOMPARABLE`).
  - `unified_diff`: Standard unified diff.
  - `description`: Summary of patch mechanics.

---

## 3. Systematic Test Categories

The benchmark suite explicitly incorporates all seven critical evaluation categories:

| Category | Definition | Ground Truth | Expected Verdict |
| :--- | :--- | :---: | :---: |
| **1. Effective Security Fixes (`true_fix`)** | Patches that eliminate the vulnerability sink, preserve nominal functionality, and pass both unit and exploit tests. | `FIX` | `VERIFIED` |
| **2. Ineffective Fixes (`cosmetic_evasion`)** | Patches that alter AST or syntax to evade static rules without eliminating runtime exploitability. | `NON_FIX` | `FAILED` |
| **3. Partial Fixes (`incomplete_fix`)** | Patches addressing one input path or using naive blacklists (`replace("'", "")`) while leaving alternate vectors exploitable. | `NON_FIX` | `FAILED` |
| **4. Detectable Regressions (`regressive_fix`, `security_regression`)** | Patches breaking existing functional unit tests or introducing new detectable security flaws (e.g. hardcoded secrets). | `NON_FIX` | `FAILED` |
| **5. False-Positive Scanner Findings (`false_positive_finding`)** | Safe constructs flagged by naive static rules where candidate refactoring silences the warning while maintaining valid behavior. | `FIX` | `VERIFIED` |
| **6. Missing-Evidence Cases (`missing_evidence_case`)** | Flaws unobserved by static analyzers (e.g. business logic CWE-862) lacking dynamic security test harnesses. | `INCONCLUSIVE` | `INCONCLUSIVE` |
| **7. Tool Failures and Timeouts (`tool_failure_timeout`)** | Execution errors, malformed patch diffs, harness exceptions, or process timeouts. | `INCONCLUSIVE` | `INCONCLUSIVE` |

---

## 4. Evaluated Baselines

All four baselines evaluate the exact same candidate patches and source code sandboxes:

```
                              ┌────────────────────────────────────────┐
                              │          Candidate Patch Diff          │
                              └───────────────────┬────────────────────┘
                                                  │
                 ┌────────────────────────────────┼────────────────────────────────┐
                 │                                │                                │
                 ▼                                ▼                                ▼
   ┌───────────────────────────┐    ┌───────────────────────────┐    ┌───────────────────────────┐
   │        Baseline 1         │    │        Baseline 2         │    │        Baseline 3         │
   │    Static Analysis Alone  │    │     Existing Tests Alone  │    │     AI / LLM Judge Alone  │
   │       (SAST Delta)        │    │    (General Test Suite)   │    │   (Syntactic Plausibility)│
   └─────────────┬─────────────┘    └─────────────┬─────────────┘    └─────────────┬─────────────┘
                 │                                │                                │
                 └────────────────────────────────┼────────────────────────────────┘
                                                  │
                                                  ▼
                                    ┌───────────────────────────┐
                                    │        Baseline 4         │
                                    │    RepoShield Combined    │
                                    │   Multi-Tier Evidence Gate│
                                    └───────────────────────────┘
```

### Baseline 1: Static Analysis Alone (SAST Delta)
- **Engine:** Bandit AST scanner.
- **Rule:** If target rule detected in baseline and absent in patched workspace: $\hat{Y} = \text{VERIFIED}$. If target rule persists: $\hat{Y} = \text{FAILED}$. If rule unobserved in baseline: $\hat{Y} = \text{INCONCLUSIVE}$.

### Baseline 2: Existing Unit Tests Alone (General Test Suite)
- **Engine:** Pytest executing `tests/test_existing.py`.
- **Rule:** If exit code is 0 (all pass): $\hat{Y} = \text{VERIFIED}$. If exit code $\neq 0$: $\hat{Y} = \text{FAILED}$. If skipped/timeout: $\hat{Y} = \text{INCONCLUSIVE}$.

### Baseline 3: AI / LLM Judge Alone
- **Engine:** Zero-shot heuristic diff review reflecting literature models (*SecureCodeBench*, *RepairBench*).
- **Rule:** Accepts patches exhibiting superficial sanitization tokens (`.replace()`, safe wrappers, AST variable indirection); rejects explicit syntax abortions (`raise `, `return 1`).

### Baseline 4: RepoShield Fix Verification Engine
- **Engine:** `benchmark.baselines.RepoShieldCombinedBaseline`.
- **Rule:** Establishes baseline hash, validates patch diff (path traversal rejection), creates isolated disposable worktree, executes differential SAST with 6-status finding comparison, executes unit tests (detecting test regressions where tests passed in baseline but fail after patch), executes targeted exploit regression test, and enforces tri-state epistemic decision logic (`VERIFIED`, `FAILED`, `INCONCLUSIVE`).

---

## 5. Metrics Definitions, Denominators, and Inconclusive Handling

### 5.1 Confusion Matrix & Ground Truth Mapping
In security-critical fix evaluation, certifying an ineffective, partial, or regressive patch as "VERIFIED" constitutes a fatal **False Positive ($FP$)**, as it would permit vulnerable code into production.

| Automated Prediction ($\hat{Y}$) | Ground Truth: FIX ($Y = \text{FIX}$) | Ground Truth: NON_FIX ($Y = \text{NON\_FIX}$) | Ground Truth: INCONCLUSIVE ($Y = \text{INCONCLUSIVE}$) |
| :--- | :---: | :---: | :---: |
| **VERIFIED** | **True Positive (TP)** | **False Positive (FP)** *(Fatal Hazard)* | **False Positive (FP)** *(Unwarranted Pass)* |
| **FAILED** | **False Negative (FN)** | **True Negative (TN)** *(Safe Block)* | **True Negative (TN)** *(Safe Block)* |
| **INCONCLUSIVE** | **False Negative (FN)** *(Strict)* | **True Negative (TN)** *(Safe Block)* | **Correct Inconclusive** *(Epistemic Honesty)* |

### 5.2 Mathematical Formulas and Denominators

1. **Correct Classification Rate ($\text{CCR}$ / Accuracy):**
   $$\text{CCR} = \frac{\sum_{i=1}^N \mathbb{I}(\text{Correct}(\hat{Y}_i, Y_i))}{N}$$
   - **Denominator:** $N$ (Total evaluated patch samples).

2. **Precision ($P$):**
   $$P = \frac{TP}{TP + FP}$$
   - **Denominator:** All candidate patches declared `VERIFIED` ($TP + FP$). If $TP + FP = 0$, $P = 0.0$.

3. **Recall ($R$):**
   $$R = \frac{TP}{TP + FN}$$
   - **Denominator:** Total ground-truth genuine security fixes ($N_{\text{fix}} = TP + FN$).

4. **False Positive Rate ($\text{FPR}$):**
   $$\text{FPR} = \frac{FP}{FP + TN} = \frac{FP}{N_{\text{non-fix}} + N_{\text{inconclusive}}}$$
   - **Denominator:** All ground-truth non-fix and inconclusive samples ($FP + TN$).

5. **False Negative Rate ($\text{FNR}$):**
   $$\text{FNR} = \frac{FN}{TP + FN} = 1 - \text{Recall}$$
   - **Denominator:** Total ground-truth genuine security fixes ($TP + FN$).

6. **Inconclusive Outcome Rate ($\text{IR}$):**
   $$\text{IR} = \frac{|\{i : \hat{Y}_i = \text{INCONCLUSIVE}\}|}{N}$$
   - **Denominator:** Total evaluated patch samples ($N$).

7. **Regression Detection Rate ($\text{RDR}$):**
   $$\text{RDR} = \frac{|\{i : \text{PatchType}_i \in \{\text{regressive\_fix}, \text{security\_regression}\} \land \hat{Y}_i = \text{FAILED}\}|}{N_{\text{regressive}}}$$
   - **Denominator:** Total regressive fix samples ($N_{\text{regressive}}$).

8. **Runtime Latency:**
   Arithmetic Mean, Median (50th percentile), and p95 (95th percentile) wall-clock time in milliseconds.

---

## 6. Reproducibility & Integrity Protocol

1. **Dataset Uniqueness & Deduplication (`benchmark.deduplicator`):**
   - Detects duplicate `case_id` or `patch_id` collisions.
   - Computes normalized SHA-256 hashes of vulnerable code to detect duplicate code bodies.
   - Detects identical unified diffs.
   - Verifies **split integrity**: ensures zero data leakage between `dev` and `held_out` partitions.
2. **Environment Isolation:**
   - Every evaluation executes inside a disposable temporary directory (`tempfile.mkdtemp`).
   - Runner purges sensitive environment variables (`GEMINI_API_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`).
   - Hard execution timeouts (20 seconds) prevent runaway subprocesses.
3. **Capture of Tool Failures:**
   - Tool crashes, timeouts, and syntax errors are captured into raw execution evidence logs without aborting the experiment suite.
4. **Machine-Readable Exports:**
   - `benchmark/results/latest_evaluation_report.json`
   - `benchmark/results/benchmark_metrics_summary.csv`
   - `benchmark/results/benchmark_samples.csv`
   - `benchmark/results/benchmark_evaluation_report.md`

---

## 7. Execution Guide

### 7.1 Running the Automated Test Suite
```bash
# Run the benchmark framework automated test suite
python -m pytest tests/test_benchmark_framework.py
```

### 7.2 Running the Full Evaluation Benchmark
```bash
# Run all benchmark cases across all baselines
python -m benchmark.runner --split all

# Run only held-out evaluation cases
python -m benchmark.runner --split held_out

# Run using the scripts wrapper
python scripts/evaluate_fix_verification.py
```
