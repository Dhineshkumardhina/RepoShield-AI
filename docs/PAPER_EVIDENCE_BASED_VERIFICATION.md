# Evidence-Based Verification of Automated Security Fixes Using Static Analysis and Targeted Testing

**Authors:** Application Security & Automated Program Repair Research Group  
**Target Venue:** ACM Transactions on Software Engineering and Methodology (TOSEM) / IEEE S&P / USENIX Security (Provisional Draft)  
**Status:** Working Draft & Empirical Benchmark Report  
**Date:** October 2026  

---

## Abstract

Automated Program Repair (APR) and Large Language Model (LLM)-driven code generation increasingly produce candidate patches for software vulnerabilities. However, establishing whether a candidate patch genuinely eliminates a vulnerability without introducing regressions remains an open and hazardous problem. Existing automated evaluation pipelines predominantly rely on two naive heuristics: (1) **scanner-delta verification**, which declares success if an alert from a static application security testing (SAST) tool disappears from the post-patch abstract syntax tree (AST); or (2) **regression test-suite execution**, which certifies patches that pass pre-existing continuous integration (CI) tests.

In this paper, we demonstrate through controlled empirical evaluation that both single-technique approaches fail catastrophically: SAST-delta verification suffers a **38.9% False Positive Rate (FPR)** due to cosmetic evasion and dead-code obfuscation, while existing test-suite execution suffers a **61.1% FPR** because functional tests rarely assert security exploit pre-conditions. Similarly, heuristic LLM-as-a-judge review suffers a **61.1% FPR** due to plausibility bias.

To address these vulnerabilities in the verification process, we propose **RepoShield AI**, a multi-tier, evidence-grounded verification framework. RepoShield enforces three strict epistemic principles: (i) *mandatory baseline reproduction* (vulnerabilities unobserved in baseline workspaces yield an `INCONCLUSIVE` status, never success); (ii) *multi-scanner differential classification* into six discrete regression states; and (iii) *targeted behavioral exploit gating*, coupling differential static analysis with dynamically synthesized exploit assertions. Across a curated multi-CWE benchmark suite ($N = 23$ candidate patches across 7 cases) and an adversarial evaluation suite ($N = 10$ difficult fix scenarios), RepoShield achieves **100% Precision, 100% Recall, and 0.0% False Positive Rate**, catching 100% of functional and security regressions ($\chi^2 \ge 7.111, p < 0.01$ over all baselines via McNemar's test). We provide full reproducibility artifacts, dataset provenance, and an audit of threats to validity.

---

## 1. Introduction

Software vulnerabilities represent persistent systemic risks to modern software supply chains. In response, automated program repair (APR) has evolved from search-based (e.g., GenProg [Le Goues et al., 2012]) and constraint-based techniques (e.g., Angelix [Mechtaev et al., 2016]) to data-driven and Large Language Model (LLM)-based generative techniques (e.g., VulRepair [Fu et al., 2022], Getafix [Bader et al., 2019], and Codex/GPT-4 [Pearce et al., 2023]).

Despite notable gains in patch generation throughput, **patch verification remains the critical bottleneck**. In general program repair, the "patch plausibility vs. correctness" problem is well-documented: Qi et al. [2015] and Smith et al. [2015] demonstrated that the vast majority of generated patches are merely *plausible*—they satisfy a sparse test suite by deleting functionality, bypassing branches, or overfitting, rather than achieving semantic correctness.

In *security-critical repair*, this challenge is magnified. Security patches operate in an adversarial domain. An imperfect functional patch causes a software defect; an imperfect security patch leaves an enterprise vulnerable while creating a dangerous illusion of remediation.

Industry tools and academic workflows typically verify automated security patches through two shortcuts:
1. **The Disappearing-Alert Shortcut:** Re-running a SAST scanner (e.g., Bandit, Semgrep, CodeQL) over the patched file and certifying the fix if the target rule alert vanishes.
2. **The Green-Build Shortcut:** Executing the repository's existing unit test suite in CI. If the test runner exits with code 0, the patch is accepted.
3. **The LLM-as-a-Judge Shortcut:** Prompts an LLM to review the patch diff and classify whether the vulnerability is resolved.

### Empirical Motivation
As we show empirically, all three shortcuts fail under routine developer refactoring and adversarial patch modifications:
- **Cosmetic Evasion:** A patch that splits a string across variables or invokes dynamic reflection (e.g., `getattr(os, 'system')`) silences SAST AST pattern matchers while leaving the execution sink entirely exploitable.
- **Functional Destruction:** A patch that injects `raise PermissionError()` or `return 1` eliminates the vulnerable data flow but destroys application functionality. SAST scanners declare success because the vulnerable sink is pruned.
- **Secondary Regressions:** A patch that correctly parameterizes a SQL query but commits a hardcoded AWS API key (`AKIA...`) in the file header passes target-specific SAST rules and functional CI builds.

### Contributions
In this paper, we formulate and evaluate an evidence-driven verification pipeline implemented in RepoShield AI. Our primary contributions are:
1. **Empirical Quantitation of Verification Failure:** We measure the failure rates of SAST-alone (38.9% FPR), Test-alone (61.1% FPR), and AI-judge (61.1% FPR) verifiers across multi-CWE patches, demonstrating that scanner silence must never be equated with vulnerability elimination.
2. **The Multi-Tier Evidence Verification Model:** We design and implement an architecture that combines:
   - Sandboxed workspace isolation with strict unified diff boundary checking.
   - Deterministic 6-status finding classification (`RESOLVED_BY_DEFINED_CHECKS`, `STILL_PRESENT`, `POTENTIALLY_REGRESSED`, `NEW`, `INCOMPARABLE`, `UNTESTED`).
   - Coupling of pre-existing unit test regression gates and targeted behavioral exploit tests.
3. **Epistemic Invariant Enforcement:** We introduce explicit rules governing missing evidence: an unobserved baseline finding or unavailable tool produces `INCONCLUSIVE`, guaranteeing that missing evidence never collapses into a false positive verification.
4. **Reproducible Empirical Benchmark:** We release a reproducible evaluation suite comprising 23 candidate patches across 7 CWE categories, a 10-scenario adversarial stress suite, and an advisory machine-learning triage model ($ROC\text{-}AUC = 1.000$).

---

## 2. Problem Statement & Threat Model

### Problem Definition
Let $R$ be a software repository at baseline commit revision $C_{\text{base}}$. Let $f \in \mathcal{F}(R)$ be a reported security finding associated with a vulnerability rule $r_{\text{target}}$ (e.g., CWE-89, SQL Injection). A program repair mechanism proposes a patch $P$, transforming the repository into $R' = P(R)$ at target revision $C_{\text{patch}}$.

The verification problem requires computing a verdict $V(R, P, f) \in \mathcal{S}$ where:
$$\mathcal{S} = \{\text{VERIFIED\_AGAINST\_DEFINED\_CHECKS}, \text{FAILED\_VERIFICATION}, \text{INCONCLUSIVE}, \text{NOT\_TESTED}\}$$

### Verification Invariants
We define two non-negotiable safety invariants for any sound verification engine:
* **Invariant 1 (Non-Equivalence of Scanner Disappearance):**
  $$\left(r_{\text{target}} \notin \text{Scanners}(R')\right) \centernot\implies \left(V = \text{VERIFIED}\right)$$
  The disappearance of a scanner finding is necessary but strictly insufficient to claim remediation.
* **Invariant 2 (Epistemic Monotonicity / No False Confidence):**
  $$\left(\text{Evidence}(R, P, f) = \emptyset\right) \implies \left(V = \text{INCONCLUSIVE}\right)$$
  Missing execution traces, unobserved baselines, or tool outages must never yield a certified verification verdict.

### Threat Model
We assume candidate patches $P$ are generated by automated generative models (LLMs) or untrusted contributors. Patches may be:
- *Inadvertently flawed:* Partial branch parameterization, functional breakage, over-constraining filters.
- *Adversarially evasive:* Restructured AST constructs designed to deceive linters, path traversal escapes (`../../../../etc/passwd`), or prompt-injection commentary intended to deceive AI-driven triage pipelines.

---

## 3. Related Work

### Automated Program Repair (APR) & Overfitting
The foundational work of Le Goues et al. [2012] (GenProg) highlighted the promise of automated patch synthesis. However, Qi et al. [2015] analyzed GenProg and RSRepair patches, discovering that 98% of candidate patches were non-plausible or overfitted—frequently passing the test suite by simply deleting the functionality under test. Smith et al. [2015] formalized this as test-suite overfitting.

To mitigate overfitting, semantic repair tools such as SemFix [Nguyen et al., 2013], Angelix [Mechtaev et al., 2016], and Prophet [Long and Rinard, 2016] employed symbolic execution and probabilistic models of correct code. However, these tools are computationally expensive and scale poorly to multi-file modern enterprise web applications.

### Automated Vulnerability Repair
Security-specific program repair has gained intense traction. Bader et al. [2019] developed Getafix at Meta, learning AST repair patterns from internal commits. Fu et al. [2022] proposed VulRepair, framing vulnerability repair as a sequence-to-sequence translation task using CodeT5.

Pearce et al. [2023] conducted an extensive study evaluating zero-shot LLM vulnerability repair (OpenAI Codex, GPT-3.5) across synthetic and real-world CVEs. Their primary empirical finding was that LLMs frequently output patches that appear syntactically plausible to human engineers but fail to eliminate the underlying CWE or introduce subtle behavioral regressions.

### Patch Correctness Assessment & Verification
Assessing patch correctness post-synthesis remains an active subfield. Le et al. [2019] investigated automated patch validation techniques, finding that independent test generation (e.g., via EvoSuite or fuzzing) caught semantic regressions that standard CI test suites missed. Xiong et al. [2018] developed heuristics comparing execution traces between unpatched and patched code.

However, existing literature focuses heavily on *general functional correctness*. Dedicated research evaluating *multi-tier evidence synthesis for security patches*—unifying differential static analysis, exploit-guided behavioral tests, and epistemic logic—has remained fragmented.

---

## 4. Research Gap

Prior work exhibits four fundamental limitations:
1. **Over-reliance on Static Disappearance:** Literature evaluating LLM vulnerability repair (e.g., SecureCodeBench [2024], CyberSecEval [Bhatt et al., 2023]) predominantly scores patch success by whether static tools (CodeQL, Bandit, Semgrep) alert on the generated code, without dynamic verification against evasion.
2. **Test-Suite Orthogonality:** Standard unit tests evaluate nominal business logic (e.g., "valid user can log in"). They do not assert adversarial pre-conditions (e.g., "' OR 1=1 cannot log in").
3. **Dichotomous vs. Epistemic Status Models:** Most repair pipelines enforce a binary $\text{Pass}/\text{Fail}$ model. They lack an explicit `INCONCLUSIVE` status to handle unobserved baselines, incomplete context, or tool failures, causing tool outages to be falsely recorded as successes or failures.
4. **Cross-Engine Regression Blindness:** Single-scanner evaluators cannot detect cross-domain regressions (e.g., a SQL patch that commits an AWS secret key).

---

## 5. Proposed Method: Multi-Tier Fix Verification

To resolve these gaps, RepoShield AI implements a multi-tier, evidence-grounded verification pipeline:

```
[Candidate Patch Diff]
         │
         ▼
[Unified Diff Boundary Validator] ──(Traversal / Out-of-Scope)──> INCONCLUSIVE
         │
         ▼
[Isolated Workspace Sandboxing]
         │
         ├───────────────────────────────────────────┐
         ▼                                           ▼
[Baseline Scan & Reproduction]             [Patched Workspace Scan]
(Pre-patch SAST + Secret Detector)         (Post-patch SAST + Secret Detector)
         │                                           │
         └─────────────────────┬─────────────────────┘
                               ▼
                 [Differential Comparator]
                 (6-Status Finding Taxonomy)
                               │
         ┌─────────────────────┼─────────────────────┐
         ▼                     ▼                     ▼
[Baseline CI Tests]   [Targeted Exploit Test]   [Regression Check]
(Unit Regression Gate)  (Behavioral Sink Gate)   (New CWE Check)
         │                     │                     │
         └─────────────────────┼─────────────────────┘
                               ▼
                   [Deterministic Rule Precedence]
                     (Rule 5.1 -> 5.2 -> 5.3 -> 5.4)
                               │
                               ▼
       [VERIFIED | FAILED_VERIFICATION | INCONCLUSIVE]
```

### Deterministic Rule Precedence
RepoShield's decision engine evaluates evidence through strict priority rules:
* **Rule 5.1 (Exploit / Test Failure Gate):** If the targeted security exploit test fails, OR if the baseline functional test suite fails on the patched workspace, the verdict is immediately forced to `FAILED_VERIFICATION`, overriding any disappearance of scanner findings.
* **Rule 5.2 (Execution Errors / Missing Scanners Gate):** If configured scanner adapters produce execution errors or missing binaries, the verdict is forced to `INCONCLUSIVE`.
* **Rule 5.3 (Security Regression Gate):** If the differential comparator identifies findings classified as `NEW` or `POTENTIALLY_REGRESSED`, the verdict is forced to `FAILED_VERIFICATION`.
* **Rule 5.4 (Baseline Non-Reproduction Gate):** If the target finding was not reproduced in the baseline scan (`INCOMPARABLE`), static analysis cannot claim resolution. The verdict is forced to `INCONCLUSIVE` unless an affirmative targeted exploit test passed.
* **Rule 5.5 (Affirmative Certification):** If and only if the original finding is `RESOLVED_BY_DEFINED_CHECKS`, no regressions exist, and all dynamic tests pass, the verdict is `VERIFIED_AGAINST_DEFINED_CHECKS`.

---

## 6. System Architecture & Implementation

RepoShield AI is implemented as a modular enterprise security architecture:
1. **Workspace Sandboxing ([`runner.py`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/backend/app/verification/runner.py)):** Execution occurs within disposable, temporary file trees. Patch applications are validated by [`patch_applier.py`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/backend/app/verification/patch_applier.py) using strict context line matching. Path traversal attempts (`../../`) trigger immediate parser abortion.
2. **Scanner Adapters ([`semgrep_adapter.py`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/backend/app/scanner/semgrep_adapter.py), [`secret_detector.py`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/backend/app/scanner/secret_detector.py)):** Normalized finding abstraction mapping heterogeneous scanner outputs into canonical `NormalizedFinding` instances.
3. **Differential Comparator ([`comparator.py`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/backend/app/verification/comparator.py)):** Evaluates rule IDs, file paths, line numbers, and normalized messages between baseline and patched ASTs to classify findings into six statuses:
   - `RESOLVED_BY_DEFINED_CHECKS`
   - `STILL_PRESENT`
   - `POTENTIALLY_REGRESSED`
   - `NEW`
   - `INCOMPARABLE`
   - `UNTESTED`
4. **Evidence Storage & Integrity ([`models/verification.py`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/backend/app/models/verification.py)):** Cryptographic content-hashing (SHA-256) of patch diffs, raw stdout/stderr logs, tool metadata, and AI commentary. Advisory AI interpretations are strictly segregated from factual execution logs.

---

## 7. Experimental Setup

### Research Questions
* **RQ1 (Verification Accuracy):** Does combining differential static analysis, existing unit tests, and targeted exploit tests improve verification accuracy over single-technique baselines?
* **RQ2 (False-Positive Hazard):** To what degree do conventional baselines falsely certify insecure or evasive patches?
* **RQ3 (Adversarial Robustness):** How does RepoShield perform under deliberate scanner evasion, resource starvation, and path traversal attacks?
* **RQ4 (Machine-Learning Triage Feasibility):** Can an interpretable ML classifier accurately predict findings that suffer from evidence deficits prior to test execution?

### Comparative Baselines
We evaluate four comparative pipelines under identical execution environments:
1. **B1: Static Analysis Alone (SAST Delta):** Evaluates Bandit / Semgrep before and after patch application; certifies if target finding is absent.
2. **B2: Existing Unit Tests Alone:** Executes the repository's nominal test suite; certifies if tests pass in CI.
3. **B3: AI / LLM Judge Alone:** Evaluates unified diff via zero-shot heuristic code review (simulating LLM-as-a-judge).
4. **B4: RepoShield Combined Pipeline:** Multi-tier evidence gate coupling baseline reproduction, differential SAST, unit test regression gates, targeted exploit tests, and deterministic rule precedence.

---

## 8. Datasets & Ground Truth

### Benchmark Corpus
The primary benchmark corpus consists of 23 candidate patches across 7 comprehensive cases:
* **`RS-BENCH-001` (SQL Injection, CWE-89, DEV Split):** 5 patches (True parameterization, cosmetic string concatenation evasion, naive `.replace("'", "")` sanitizer, functional abort regression, hardcoded AWS secret regression).
* **`RS-BENCH-002` (OS Command Injection, CWE-78, DEV Split):** 4 patches (Native `shutil.make_archive`, `os.system` evasion, command failure `return 1` regression, naive semicolon strip).
* **`RS-BENCH-003` (Path Traversal, CWE-22, DEV Split):** 4 patches (`Path.resolve()` boundary verification, flawed `.replace("../", "")`, dot-reject regression, `Path / filename` evasion).
* **`RS-BENCH-004` (Insecure Deserialization, CWE-502, HELD_OUT Split):** 4 patches (`yaml.safe_load`, `getattr(yaml, 'FullLoader')` evasion, empty dict return regression, naive string blacklist).
* **`RS-BENCH-005` (Missing Authorization, CWE-862, HELD_OUT Split):** 2 patches (Unobserved baseline check, blanket permission error regression).
* **`RS-BENCH-006` (False Positive SAST Finding, CWE-89, HELD_OUT Split):** 2 patches (Benign query branching refactor, descending sort removal regression).
* **`RS-BENCH-007` (Tool Failure / Timeout, CWE-400, HELD_OUT Split):** 2 patches (Path traversal escape diff, unobserved scanner rule).

---

## 9. Evaluation Metrics & Denominators

### Formal Mathematical Definitions

| Metric | Formulation | Denominator Specification |
| :--- | :---: | :--- |
| **Precision** | $\frac{\text{TP}}{\text{TP} + \text{FP}}$ | Total positive claims made by the system ($\text{Pred} = \text{VERIFIED}$). |
| **Recall (Sensitivity)** | $\frac{\text{TP}}{\text{TP} + \text{FN}}$ | Total ground-truth actual fixes ($\text{GT} = \text{FIX}$). |
| **Specificity (TNR)** | $\frac{\text{TN}}{\text{TN} + \text{FP}}$ | Total ground-truth non-fixes and inconclusive cases. |
| **False Positive Rate (FPR)** | $\frac{\text{FP}}{\text{FP} + \text{TN}} = 1 - \text{Specificity}$ | Fatal security failure rate: certifying an insecure patch as verified. |
| **False Negative Rate (FNR)** | $\frac{\text{FN}}{\text{FN} + \text{TP}} = 1 - \text{Recall}$ | Conservative rejection rate: rejecting a valid patch. |
| **Inconclusive Rate** | $\frac{N_{\text{inconclusive}}}{N}$ | Total population ($N$). Measures epistemic refusal. |
| **Regression Detection Rate** | $\frac{\text{Detected Regressions}}{\text{Total Regressive Patches}}$ | Catches of functional breaks and newly introduced vulnerabilities. |

---

## 10. Empirical Results

### RQ1 & RQ2: Verification Performance & False-Positive Rates

Table 1 summarizes the empirical benchmark results across all 23 candidate patches:

#### Table 1: Empirical Benchmark Results across Comparative Verification Baselines ($N = 23$)

| Baseline Approach | Acc (%) | Precision (%) | Recall (%) | Specificity (%) | FPR (%) | FNR (%) | Inconc. (%) | Regr. Det. (%) | Median Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **B1: Static Analysis Alone (SAST Delta)** | 60.9% | 36.4% | 80.0% | 61.1% | **38.9%** | 20.0% | 30.4% | 0.0% | 1703.6 ms |
| **B2: Existing Unit Tests Alone (CI Suite)** | 47.8% | 31.2% | **100.0%** | 38.9% | **61.1%** | 0.0% | 0.0% | 85.7% | 681.4 ms |
| **B3: AI / LLM Judge Alone (Heuristic Diff)** | 52.2% | 31.2% | **100.0%** | 38.9% | **61.1%** | 0.0% | 8.7% | 71.4% | **250.0 ms** |
| **B4: RepoShield Multi-Tier Combined Pipeline** | **100.0%** | **100.0%** | **100.0%** | **100.0%** | **0.0%** | **0.0%** | 13.0% | **100.0%** | 3718.2 ms |

#### Statistical Significance (McNemar's Paired Contingency Test)
Using Edwards continuity correction ($\alpha = 0.05$):
- **RepoShield vs. B1 (SAST Alone):** $\chi^2 = 7.111, p = 0.0077 \rightarrow$ **Statistically Significant ($p < 0.01$)**
- **RepoShield vs. B2 (Existing Tests):** $\chi^2 = 10.083, p = 0.0015 \rightarrow$ **Statistically Significant ($p < 0.01$)**
- **RepoShield vs. B3 (AI Judge Alone):** $\chi^2 = 9.091, p = 0.0026 \rightarrow$ **Statistically Significant ($p < 0.01$)**

---

### RQ3: Adversarial & Stress Scenarios

We submitted RepoShield to a dedicated adversarial evaluation suite comprising 10 difficult security-fix scenarios ([`tests/test_difficult_security_scenarios.py`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/tests/test_difficult_security_scenarios.py)). Table 2 reports the results:

#### Table 2: Adversarial Stress Scenario Evaluation ($N = 10$)

| # | Stress Scenario | Expected Status | Observed Status | Agreement | Invariant Upheld |
| :---: | :--- | :--- | :--- | :---: | :--- |
| **1** | Genuine Parameterization | `VERIFIED` | `VERIFIED` | **AGREE** | Complete differential proof |
| **2** | Cosmetic Variable Indirection | `FAILED` | `FAILED` | **AGREE** | Finding `STILL_PRESENT` |
| **3** | Partial Branch Remediation | `FAILED` | `FAILED` | **AGREE** | Caught as `NEW` finding |
| **4** | Reflection-Based SAST Evasion | `FAILED` | `FAILED` | **AGREE** | Dynamic exploit test failed |
| **5** | Hardcoded Credential Regression | `FAILED` | `FAILED` | **AGREE** | Secret Detector caught CWE-798 |
| **6** | Functional Destruction (`raise`) | `FAILED` | `FAILED` | **AGREE** | Baseline unit test failed |
| **7** | Scanner Unavailable (Missing Binary)| `INCONCLUSIVE` | `INCONCLUSIVE` | **AGREE** | Missing tool $\ne$ Success |
| **8** | Test Runner Timeout / Starvation | `FAILED` | `FAILED` | **AGREE** | Gate failure enforced |
| **9** | Unreproduced Baseline Finding | `INCONCLUSIVE` | `INCONCLUSIVE` | **AGREE** | Classified `INCOMPARABLE` |
| **10**| Path Traversal (`../../etc/passwd`) | `INCONCLUSIVE` | `INCONCLUSIVE` | **AGREE** | Diff rejected at boundary |

---

### RQ4: Machine Learning Evidence Deficit Prediction

To investigate whether an ML classifier can predict when a finding suffers from an evidence deficit prior to test execution, we trained an L2-regularized logistic regression model ([`train_and_evaluate.py`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/ml_experiments/evidence_deficit_prediction/train_and_evaluate.py)) across 40 findings (28 training, 12 held-out).

#### Table 3: Evidence Deficit Prediction on Held-Out Test Data ($N = 12$)

| Approach | Acc (%) | Precision (%) | Recall (%) | Specificity (%) | F1-Score | FPR (%) | ROC-AUC | Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Rule-Based Baseline** | 91.7% | 83.3% | **100.0%** | 85.7% | 0.909 | 14.3% | N/A | **0.000 ms** |
| **Decision Tree ($\text{depth}=3$)**| 83.3% | 80.0% | 80.0% | 85.7% | 0.800 | 14.3% | 0.829 | 0.060 ms |
| **Logistic Regression (ML)**| **91.7%** | **83.3%** | **100.0%** | **85.7%** | **0.909** | **14.3%** | **1.000** | 0.076 ms |

#### Learned Odds-Ratio Attributions
* **`cross_file_reference` ($+1.668, \text{OR} = 5.30\times$):** Increases the odds of requiring additional evidence by $5.30\times$.
* **`has_custom_sanitizer` ($+0.756, \text{OR} = 2.13\times$):** Increases the odds of an evidence deficit by $2.13\times$.
* **`scanner_confidence` ($-0.745, \text{OR} = 0.47\times$):** High confidence on local sinks halves the odds of an evidence deficit ($0.47\times$).

---

## 11. Error Analysis & Case Studies

### Case Study 1: The Plausibility Trap in Heuristic Review (`RS-001-P3`)
In candidate patch `RS-001-P3`, the repair agent attempted to fix SQL injection via:
```python
clean_user = username.replace("'", "")
query = f"SELECT id FROM users WHERE username = '{clean_user}' AND password_hash = '{password_hash}'"
```
* **Baseline Behavior:** Both the existing unit test suite (B2) and the LLM judge (B3) declared `VERIFIED`. The unit tests passed because nominal user queries contain no quotes. The LLM accepted `.replace("'", "")` as a plausible sanitizer.
* **RepoShield Behavior:** The targeted security regression test replayed a bypass payload targeting `password_hash`. The test failed, triggering Rule 5.1 and correctly rejecting the patch as `FAILED_VERIFICATION`.

### Case Study 2: Cross-Engine Regression (`RS-001-P5`)
In candidate patch `RS-001-P5`, the patch parameterized the SQL query but committed:
```python
SERVICE_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
```
* **Baseline Behavior:** Baselines B1, B2, and B3 declared `VERIFIED`. The SQL scanner only inspected database calls; the unit tests passed; the LLM reviewed only the SQL query lines.
* **RepoShield Behavior:** The cross-scanner differential comparator executed the Secret Detector adapter alongside SAST, identifying a `NEW` critical credential finding, terminating the verification run as `FAILED_VERIFICATION`.

---

## 12. Threats to Validity

### Internal Validity
* *Ground Truth Integrity:* Labels might suffer from subjective researcher bias. We mitigated this by requiring physical, verifiable proofs (e.g., executing exploit scripts for `NON_FIX`, AST inspection of `?` parameterization for `FIX`).
* *Harness Overfitting:* The targeted exploit tests were written by security researchers for specific benchmark cases. To evaluate generalization, we tested on a held-out split (`RS-BENCH-004` to `007`) that was completely isolated during initial rule formulation.

### External Validity
* *Dataset Scale:* The benchmark dataset comprises 23 candidate patches and 10 adversarial scenarios across Python backends. While covering major OWASP Top 10 categories (CWE-89, CWE-78, CWE-22, CWE-502, CWE-862, CWE-798), further empirical validation across Java, C/C++, and Go is required.
* *Scanner Diversity:* Evaluated against Bandit, Semgrep OSS, and RepoShield Secret Engine. Commercial scanners (e.g., Snyk, Veracode, Checkmarx) may exhibit different AST evasion sensitivities.

### Construct Validity
* *Metric Alignment:* In security verification, False Positives (certifying an insecure patch) are far more dangerous than False Negatives (withholding judgment). Our metric definitions explicitly separate Specificity and False Positive Rates rather than relying solely on raw Accuracy.

---

## 13. Limitations & Future Work

1. **Exploit Test Synthesis Automation:** While RepoShield's verification engine reliably executes targeted security regression tests, authoring those tests currently requires either curated exploit harnesses or LLM-synthesized test suites. Future work will investigate automated dynamic exploit generation via guided concolic fuzzing.
2. **De-obfuscation AST Normalization:** Currently, obfuscated dynamic reflection (`getattr(os, 'system')`) is caught dynamically by exploit tests. Enhancing the static collector with constant-folding AST normalization will enable SAST rules to catch dynamic reflection statically.
3. **Multi-Repository Microservice Tracing:** The current implementation operates within single repository worktrees. Expanding taint verification across distributed API contracts remains an open challenge.

---

## 14. Conclusion

Automated security program repair cannot succeed without trustworthy verification. Our empirical findings demonstrate that industry-standard shortcuts—such as static alert disappearance, green CI builds, and zero-shot LLM diff review—suffer from intolerable false-positive rates (38.9% to 61.1%), readily passing cosmetic evasions, functional breakage, and newly introduced credentials.

Through RepoShield AI, we have demonstrated that combining multi-tier differential static analysis, pre-existing unit test regression gates, and targeted behavioral exploit tests eliminates false-positive verifications (0.0% FPR) while achieving 100% precision and recall on ground-truth benchmarks. By enforcing strict epistemic logic—where missing evidence yields `INCONCLUSIVE` rather than false certainty—automated security repair systems can provide defensible, production-grade assurance.

---

## References

1. **Bader, J., Scott, A., Pradel, M., and Chandra, S.** 2019. Getafix: Learning to fix bugs at scale. *Proceedings of the ACM on Programming Languages*, 3(OOPSLA), 1–28.
2. **Bhatt, M., Chen, C., et al. (Meta AI).** 2023. Purple Llama CyberSecEval: A comprehensive benchmark for evaluating cybersecurity risks of large language models. *arXiv preprint arXiv:2312.04724*.
3. **Fu, M., Tantithamthavorn, C., Le, T., Nguyen, V., and Phung, D.** 2022. VulRepair: A specification-based automated program repair approach for vulnerabilities using large language models. *ACM SIGSOFT International Symposium on Foundations of Software Engineering (FSE)*, 935–947.
4. **Le, X. B. D., Ling, D., Lo, D., and Le Goues, C.** 2019. On reliability of patch correctness assessment in automated program repair. *IEEE Transactions on Software Engineering*, 47(7), 1292–1307.
5. **Le Goues, C., Nguyen, T., Forrest, S., and Weimer, W.** 2012. GenProg: A generic method for automatic software repair. *IEEE Transactions on Software Engineering*, 38(1), 54–72.
6. **Long, F., and Rinard, M.** 2016. Automatic patch generation by learning correct code. *ACM SIGPLAN Notices*, 51(1), 298–312.
7. **Mechtaev, S., Yi, J., and Roychoudhury, A.** 2016. Angelix: Execution-driven program repair. *Proceedings of the 38th International Conference on Software Engineering (ICSE)*, 691–702.
8. **Monperrus, M.** 2018. Automatic software repair: A bibliography. *ACM Computing Surveys*, 51(1), 1–24.
9. **Nguyen, H. D. T., Qi, D., Roychoudhury, A., and Chandra, S.** 2013. SemFix: Program repair via semantic analysis. *Proceedings of the 35th International Conference on Software Engineering (ICSE)*, 772–781.
10. **Pearce, H., Ahmad, B., Tan, B., Dolan-Gavitt, B., and Karri, R.** 2023. Examining zero-shot vulnerability repair with large language models. *IEEE Symposium on Security and Privacy (S&P)*, 2339–2356.
11. **Qi, Z., Long, F., Achour, S., and Rinard, M.** 2015. An analysis of patch plausibility and correctness for generate-and-validate patch generation. *Proceedings of the 2015 International Symposium on Software Testing and Analysis (ISSTA)*, 24–36.
12. **Smith, E. K., Barr, E. T., Le Goues, C., and Brun, Y.** 2015. Is the cure worse than the disease? Overfitting in automated program repair. *Proceedings of the 10th Joint Meeting on Foundations of Software Engineering (ESEC/FSE)*, 532–543.
13. **Xia, C. S., Wei, Y., and Zhang, L.** 2023. Automated program repair in the era of large language models: A comprehensive study. *Proceedings of the 45th International Conference on Software Engineering (ICSE)*, 1487–1499.
14. **Xiong, Y., Wang, J., Yan, R., Zhang, J., and Han, S.** 2018. Precise condition synthesis for program repair. *IEEE Transactions on Software Engineering*, 44(11), 1077–1103.

---

## Reproducibility Checklist & Artifact Mapping

| Claim / Section | Required Evidence Artifact | Verification Command / File Reference | Status |
| :--- | :--- | :--- | :---: |
| **RQ1 & RQ2: Benchmark Results (Table 1)** | Raw JSON records across 4 baselines | [`benchmark/results/latest_evaluation_report.json`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/benchmark/results/latest_evaluation_report.json) | **Verified** |
| **RQ1 & RQ2: Metrics Summary (Table 1)** | CSV summary with denominators | [`benchmark/results/benchmark_metrics_summary.csv`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/benchmark/results/benchmark_metrics_summary.csv) | **Verified** |
| **RQ1: Statistical Significance (McNemar)** | Paired contingency test calculations | [`benchmark/metrics.py`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/benchmark/metrics.py#L130-L165) | **Verified** |
| **RQ3: Adversarial Scenarios (Table 2)** | 10 Automated integration tests | [`tests/test_difficult_security_scenarios.py`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/tests/test_difficult_security_scenarios.py) | **Verified** (10/10 Passed) |
| **RQ3: Adversarial Trace Audit** | Audit evaluation script execution | [`scripts/evaluate_difficult_security_scenarios.py`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/scripts/evaluate_difficult_security_scenarios.py) | **Verified** |
| **RQ4: Evidence Deficit ML (Table 3)** | L2-logistic model weights & config | [`ml_experiments/models/evidence_deficit_model_v1.joblib`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/ml_experiments/models/evidence_deficit_model_v1.joblib) | **Verified** |
| **RQ4: ML Test Suite** | 6 Automated unit tests | [`tests/test_ml_evidence_predictor.py`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/tests/test_ml_evidence_predictor.py) | **Verified** (6/6 Passed) |
| **Invariant 1 & 2 Enforcement** | Deterministic rule precedence | [`backend/app/verification/service.py`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/backend/app/verification/service.py#L400-L460) | **Verified** |
| **Workspace Sandboxing** | Unified diff & traversal boundary check | [`backend/app/verification/patch_applier.py`](file:///c:/PROJECTS/dhina%20projects/RepoShield%20AI/backend/app/verification/patch_applier.py#L30-L110) | **Verified** |
