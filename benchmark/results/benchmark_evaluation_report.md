# Empirical Evaluation of Evidence-Based Security-Fix Verification

**Evaluation Timestamp:** 2026-10-12T11:47:18.811054+00:00  
**Platform:** nt (Windows-11-10.0.26300-SP0) | **Python:** 3.14.7  
**Total Benchmark Cases:** 7 | **Total Evaluated Patches:** 23 (13 dev, 10 held-out)  

---

## 1. Research Objective & Baselines

This benchmark investigates the central research question:
> *Does combining static analysis, targeted security tests, and explicit evidence rules improve the reliability of security-fix evaluation compared with single-technique baselines?*

Five comparative evaluation pipelines were executed over identical candidate patches and source code trees:
1. **Baseline A: Static Analysis Alone (SAST Delta):** Certifies a fix if the target scanner rule disappears from the AST.
2. **Baseline B: Targeted Tests Alone (Exploit Regression Suite):** Certifies a fix if the vulnerability exploit fails against patched code.
3. **Baseline B2: General Unit Tests Alone:** Certifies a fix if repository functional unit tests pass in CI.
4. **Baseline C: AI / LLM Judge Alone:** Zero-shot heuristic diff review without execution grounding.
5. **Baseline D: RepoShield Combined Pipeline:** Multi-tier evidence gate coupling baseline reproduction, differential SAST, unit test regressions, targeted exploit test verification, and 6-status finding classification.

---

## 2. Empirical Benchmark Metrics Summary

| Baseline Approach | Correct Class. Rate | Precision | Recall | False Pos. Rate | False Neg. Rate | Inconclusive Rate | Regression Det. | Median Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Static Analysis Alone (SAST Delta)** | 60.9% | 36.4% | 80.0% | 38.9% | 20.0% | 30.4% | 0.0% | 1669.2ms |
| **Targeted Tests Alone (Exploit Regression Suite)** | 65.2% | 41.7% | 100.0% | 38.9% | 0.0% | 13.0% | 28.6% | 656.0ms |
| **Existing Unit Tests Alone (General Test Suite)** | 47.8% | 31.2% | 100.0% | 61.1% | 0.0% | 0.0% | 85.7% | 659.3ms |
| **AI / LLM Judge Alone (Syntactic Heuristic)** | 52.2% | 31.2% | 100.0% | 61.1% | 0.0% | 8.7% | 71.4% | 250.0ms |
| **RepoShield Combined Pipeline (Multi-Tier Evidence Gate)** | 100.0% | 100.0% | 100.0% | 0.0% | 0.0% | 13.0% | 100.0% | 3604.3ms |

---

## 3. Confusion Matrix Breakdown

| Baseline Approach | True Positives (TP) | False Positives (FP)* | True Negatives (TN) | False Negatives (FN) | Inconclusive Count |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Static Analysis Alone (SAST Delta)** | 4 | **7** | 11 | 1 | 7 |
| **Targeted Tests Alone (Exploit Regression Suite)** | 5 | **7** | 11 | 0 | 3 |
| **Existing Unit Tests Alone (General Test Suite)** | 5 | **11** | 7 | 0 | 0 |
| **AI / LLM Judge Alone (Syntactic Heuristic)** | 5 | **11** | 7 | 0 | 2 |
| **RepoShield Combined Pipeline (Multi-Tier Evidence Gate)** | 5 | **0** | 18 | 0 | 3 |

*\*Note: In security-fix evaluation, a False Positive (certifying an insecure patch as verified) is a catastrophic security failure.*

---

## 4. Statistical Significance Testing (McNemar's Test)

We evaluate paired 2x2 contingency tables using McNemar's test with Edwards continuity correction ($lpha = 0.05$):

- **RepoShield vs Baseline A: Static Analysis Alone:** $\chi^2 = 7.111$, $p = 0.0077$ $\rightarrow$ **Statistically Significant (p < 0.05)**
- **RepoShield vs Baseline B: Targeted Tests Alone:** $\chi^2 = 6.125$, $p = 0.0133$ $\rightarrow$ **Statistically Significant (p < 0.05)**
- **RepoShield vs Baseline B2: General Unit Tests Alone:** $\chi^2 = 10.083$, $p = 0.0015$ $\rightarrow$ **Statistically Significant (p < 0.05)**
- **RepoShield vs Baseline C: AI / LLM Judge Alone:** $\chi^2 = 9.091$, $p = 0.0026$ $\rightarrow$ **Statistically Significant (p < 0.05)**

---

## 5. Tool Versions & Reproducibility Environment

```json
{
  "platform": {
    "os": "nt",
    "platform": "Windows-11-10.0.26300-SP0",
    "python_version": "3.14.7",
    "processor": "Intel64 Family 6 Model 151 Stepping 2, GenuineIntel"
  },
  "tool_versions": {
    "python": "3.14.7",
    "bandit": "1.9.4",
    "pytest": "9.1.1"
  },
  "scanner_configuration": {
    "timeout_seconds": 20,
    "rule_profiles": [
      "bandit_default",
      "semgrep_security_audit"
    ],
    "severity_threshold": "LOW",
    "confidence_threshold": "LOW",
    "secret_detector_enabled": true,
    "sandbox_isolation": "disposable_scratchdir"
  }
}
```
