# [Evaluation Title]: Empirical Fix-Verification Benchmark Report

**Evaluation Date:** `YYYY-MM-DD`  
**Authors / Evaluators:** `[Author Name(s) / Research Team]`  
**Target Repository / Engine:** RepoShield AI Fix-Verification Engine (`app.verification.service`)  
**Benchmark Suite Version:** RS-BENCH v1.0  

---

## 1. Executive Summary

Provide a concise 2–3 paragraph summary answering the core research question:
> *Does combining static analysis, targeted security tests, and explicit evidence rules improve the reliability of security-fix evaluation compared with appropriate baseline methods?*

- **Key Finding:** Summarize the observed False Positive Rate (FPR), Precision, and Regression Detection Rate (RDR) of the combined evidence-based approach vs single-technique baselines.
- **Epistemic Honesty:** State how inconclusive outcomes and unobserved baseline vulnerabilities were handled.
- **Resource Trade-off:** Note the median latency cost incurred by isolated multi-tier verification.

---

## 2. Experimental Setup & Environment

Document exact hardware, OS, tool, and scanner configurations to ensure full reproducibility:

```yaml
Execution Environment:
  Operating System: [e.g., Windows 11 Enterprise / Ubuntu 22.04 LTS]
  Python Version: [e.g., Python 3.10.12]
  Runner Sandbox: Isolated disposable temporary directories (tempfile.mkdtemp)
  Timeouts: 20 seconds per tool execution

Tool & Scanner Versions:
  Bandit SAST: [e.g., 1.7.8]
  Semgrep OSS: [e.g., 1.78.0]
  Pytest Runner: [e.g., 8.2.1]
  LLM Judge Baseline: [e.g., Simulated zero-shot heuristic / GPT-4o snapshot]

Dataset Partitioning:
  Total Benchmark Cases: [e.g., 7 cases]
  Total Candidate Patches: [e.g., 23 candidate patches]
  Development Set (Dev): [e.g., 13 patches across cases RS-BENCH-001 to 003]
  Held-Out Evaluation Set: [e.g., 10 patches across cases RS-BENCH-004 to 007]
  Deduplication Check: Zero identifier collisions, zero diff duplicates, zero split leakage.
```

---

## 3. Evaluated Baselines

| Baseline Identifier | Approach Name | Verification Criteria |
| :--- | :--- | :--- |
| **B1_sast_alone** | Static Analysis Alone (SAST Delta) | Certified if baseline scanner rule finding disappears from AST. |
| **B2_existing_tests** | Existing Unit Tests Alone | Certified if standard repository unit tests pass (exit code 0). |
| **B3_ai_judge** | AI / LLM Judge Alone | Syntactic review of patch diff without execution grounding. |
| **B4_reposhield_pipeline** | RepoShield Multi-Tier Evidence Gate | Differential SAST + unit test regression check + targeted exploit test + 6-status finding classification. |

---

## 4. Empirical Evaluation Results

### 4.1 Comparative Metrics Table

| Baseline Approach | Correct Class. Rate | Precision | Recall | False Pos. Rate | False Neg. Rate | Inconclusive Rate | Regression Det. | Median Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Baseline 1: Static Analysis Alone** | `XX.X%` | `XX.X%` | `XX.X%` | `XX.X%` | `XX.X%` | `XX.X%` | `XX.X%` | `XXXX.X ms` |
| **Baseline 2: Existing Tests Alone** | `XX.X%` | `XX.X%` | `XX.X%` | `XX.X%` | `XX.X%` | `XX.X%` | `XX.X%` | `XXXX.X ms` |
| **Baseline 3: AI / LLM Judge Alone** | `XX.X%` | `XX.X%` | `XX.X%` | `XX.X%` | `XX.X%` | `XX.X%` | `XX.X%` | `XXXX.X ms` |
| **Baseline 4: RepoShield Combined** | **`XX.X%`** | **`XX.X%`** | **`XX.X%`** | **`XX.X%`** | **`XX.X%`** | **`XX.X%`** | **`XX.X%`** | **`XXXX.X ms`** |

### 4.2 Confusion Matrix Breakdown

| Baseline Approach | True Positives (TP) | False Positives (FP)* | True Negatives (TN) | False Negatives (FN) | Inconclusive Count |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Baseline 1: Static Analysis Alone** | `X` | `X` | `X` | `X` | `X` |
| **Baseline 2: Existing Tests Alone** | `X` | `X` | `X` | `X` | `X` |
| **Baseline 3: AI / LLM Judge Alone** | `X` | `X` | `X` | `X` | `X` |
| **Baseline 4: RepoShield Combined** | `X` | `X` | `X` | `X` | `X` |

*\*Note: In security verification, declaring a flawed, partial, or regressive patch as "VERIFIED" constitutes a fatal False Positive.*

---

## 5. Category-Wise Performance Analysis

### A. Effective Security Fixes (`true_fix`)
- *Evaluation:* `[Did the verification engine verify the fix? Did all defined checks pass?]`

### B. Ineffective Fixes & Cosmetic Evasions (`cosmetic_evasion`)
- *Evaluation:* `[How did single-technique baselines respond compared to targeted security regression tests?]`

### C. Partial Fixes (`incomplete_fix`)
- *Evaluation:* `[Did the 6-status comparator classify the outcome as POTENTIALLY_REGRESSED or STILL_PRESENT?]`

### D. Detectable Regressions (`regressive_fix` & `security_regression`)
- *Evaluation:* `[Were functional test regressions and newly introduced security flaws caught?]`

### E. False-Positive Scanner Findings (`false_positive_finding`)
- *Evaluation:* `[Did the engine verify benign refactoring without flagging false regressions?]`

### F. Missing-Evidence Cases (`missing_evidence_case`)
- *Evaluation:* `[Did the engine properly declare INCONCLUSIVE when baseline evidence was unobserved?]`

### G. Tool Failures and Timeouts (`tool_failure_timeout`)
- *Evaluation:* `[Did the engine gracefully capture exceptions and timeouts without crashing?]`

---

## 6. Statistical Significance Testing

Document McNemar's paired test with continuity correction ($\alpha = 0.05$):

- **RepoShield vs Baseline 1 (SAST Alone):** $\chi^2 = \text{X.XX}$, $p = \text{X.XXXX}$ $\rightarrow$ `[Significant / Not Significant]`
- **RepoShield vs Baseline 2 (Tests Alone):** $\chi^2 = \text{X.XX}$, $p = \text{X.XXXX}$ $\rightarrow$ `[Significant / Not Significant]`
- **RepoShield vs Baseline 3 (AI Judge Alone):** $\chi^2 = \text{X.XX}$, $p = \text{X.XXXX}$ $\rightarrow$ `[Significant / Not Significant]`

---

## 7. Threats to Validity & Limitations

- **Construct Validity:** `[Threats related to mapping ground-truth labels and evaluation checks]`
- **Internal Validity:** `[Threats related to sandbox determinism, secret sanitization, and timeouts]`
- **External Validity:** `[Language coverage, CWE distribution, and scalability to enterprise repos]`
- **Conclusion Validity:** `[Statistical power, sample size, and avoidance of overclaiming]`

---

## 8. Artifact References

- Raw Experiment Data: `benchmark/results/latest_evaluation_report.json`
- Metrics Summary CSV: `benchmark/results/benchmark_metrics_summary.csv`
- Granular Samples CSV: `benchmark/results/benchmark_samples.csv`
- Markdown Report: `benchmark/results/benchmark_evaluation_report.md`
