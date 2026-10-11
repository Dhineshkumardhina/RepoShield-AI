"""Reporting and Export Engine for Benchmark Results.

Generates:
1. Machine-readable JSON results.
2. Machine-readable summary CSV.
3. Machine-readable detailed samples CSV.
4. Comprehensive human-readable Markdown evaluation report.
"""
import csv
from datetime import datetime
import io
import json
from pathlib import Path
from typing import List

from .models import (
    BaselineEvaluationMetrics,
    BenchmarkSuiteSummary,
    SampleExperimentRecord,
)
from .metrics import compute_mcnemar_test


def export_json_report(summary: BenchmarkSuiteSummary, target_path: Path):
    """Write machine-readable JSON evaluation suite report."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(json.dumps(summary.to_dict(), indent=2), encoding="utf-8")


def export_csv_summary(metrics: List[BaselineEvaluationMetrics], target_path: Path):
    """Write machine-readable CSV metrics summary."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "baseline_id",
        "baseline_name",
        "total_samples",
        "correct_classification_rate",
        "precision",
        "recall",
        "false_positive_rate",
        "false_negative_rate",
        "inconclusive_rate",
        "regression_detection_rate",
        "true_positives",
        "false_positives",
        "true_negatives",
        "false_negatives",
        "inconclusive_count",
        "mean_latency_ms",
        "median_latency_ms",
        "p95_latency_ms",
    ]
    with target_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for m in metrics:
            d = m.to_dict()
            writer.writerow({k: d[k] for k in fieldnames})


def export_csv_detailed_samples(samples: List[SampleExperimentRecord], target_path: Path):
    """Write machine-readable CSV containing granular per-sample decision records."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "case_id",
        "patch_id",
        "patch_type",
        "split",
        "origin",
        "vulnerability_category",
        "ground_truth_label",
        "baseline_id",
        "baseline_name",
        "expected_classification",
        "actual_classification",
        "is_correct",
        "runtime_ms",
        "error_message",
    ]
    with target_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for s in samples:
            writer.writerow({
                "case_id": s.case_id,
                "patch_id": s.patch_id,
                "patch_type": s.patch_type,
                "split": s.split,
                "origin": s.origin,
                "vulnerability_category": s.vulnerability_category,
                "ground_truth_label": s.ground_truth_label,
                "baseline_id": s.baseline_id,
                "baseline_name": s.baseline_name,
                "expected_classification": s.expected_classification,
                "actual_classification": s.actual_classification,
                "is_correct": s.is_correct,
                "runtime_ms": f"{s.runtime_ms:.2f}",
                "error_message": s.error_message or "",
            })


def generate_markdown_report(summary: BenchmarkSuiteSummary) -> str:
    """Generate comprehensive human-readable Markdown evaluation report."""
    buf = io.StringIO()
    buf.write("# Empirical Evaluation of Evidence-Based Security-Fix Verification\n\n")
    buf.write(f"**Evaluation Timestamp:** {summary.timestamp}  \n")
    buf.write(f"**Platform:** {summary.platform_info.get('os', 'Unknown')} ({summary.platform_info.get('platform', '')}) | **Python:** {summary.platform_info.get('python_version', '')}  \n")
    buf.write(f"**Total Benchmark Cases:** {summary.total_cases} | **Total Evaluated Patches:** {summary.total_patches} "
              f"({summary.dev_patches_count} dev, {summary.held_out_patches_count} held-out)  \n\n")

    buf.write("---\n\n")
    buf.write("## 1. Research Objective & Baselines\n\n")
    buf.write("This benchmark investigates the central research question:\n")
    buf.write("> *Does combining static analysis, targeted security tests, and explicit evidence rules improve the reliability of security-fix evaluation compared with single-technique baselines?*\n\n")
    buf.write("Four comparative evaluation pipelines were executed over identical candidate patches and source code trees:\n")
    buf.write("1. **Baseline 1: Static Analysis Alone (SAST Delta):** Certifies a fix if the target scanner rule disappears from the AST.\n")
    buf.write("2. **Baseline 2: Existing Unit Tests Alone:** Certifies a fix if repository unit tests pass in CI.\n")
    buf.write("3. **Baseline 3: AI / LLM Judge Alone:** Zero-shot heuristic diff review without execution grounding.\n")
    buf.write("4. **Baseline 4: RepoShield Combined Pipeline:** Multi-tier evidence gate coupling baseline reproduction, differential SAST, unit test regressions, targeted exploit test verification, and 6-status finding classification.\n\n")

    buf.write("---\n\n")
    buf.write("## 2. Empirical Benchmark Metrics Summary\n\n")
    buf.write("| Baseline Approach | Correct Class. Rate | Precision | Recall | False Pos. Rate | False Neg. Rate | Inconclusive Rate | Regression Det. | Median Latency |\n")
    buf.write("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n")
    for m in summary.metrics:
        buf.write(
            f"| **{m.baseline_name}** | {m.correct_classification_rate:.1%} | {m.precision:.1%} | "
            f"{m.recall:.1%} | {m.false_positive_rate:.1%} | {m.false_negative_rate:.1%} | "
            f"{m.inconclusive_rate:.1%} | {m.regression_detection_rate:.1%} | {m.median_latency_ms:.1f}ms |\n"
        )
    buf.write("\n")

    buf.write("---\n\n")
    buf.write("## 3. Confusion Matrix Breakdown\n\n")
    buf.write("| Baseline Approach | True Positives (TP) | False Positives (FP)* | True Negatives (TN) | False Negatives (FN) | Inconclusive Count |\n")
    buf.write("| :--- | :---: | :---: | :---: | :---: | :---: |\n")
    for m in summary.metrics:
        buf.write(
            f"| **{m.baseline_name}** | {m.true_positives} | **{m.false_positives}** | "
            f"{m.true_negatives} | {m.false_negatives} | {m.inconclusive_count} |\n"
        )
    buf.write("\n*\\*Note: In security-fix evaluation, a False Positive (certifying an insecure patch as verified) is a catastrophic security failure.*\n\n")

    buf.write("---\n\n")
    buf.write("## 4. Statistical Significance Testing (McNemar's Test)\n\n")
    buf.write("We evaluate paired 2x2 contingency tables using McNemar's test with Edwards continuity correction ($\alpha = 0.05$):\n\n")
    b4_id = "B4_reposhield_pipeline"
    for b_id, b_label in [
        ("B1_sast_alone", "Baseline 1: Static Analysis Alone"),
        ("B2_existing_tests", "Baseline 2: Existing Tests Alone"),
        ("B3_ai_judge", "Baseline 3: AI / LLM Judge Alone"),
    ]:
        chi2, p_val = compute_mcnemar_test(summary.sample_records, b4_id, b_id)
        sig_str = "**Statistically Significant (p < 0.05)**" if p_val < 0.05 else "Not statistically significant"
        buf.write(f"- **RepoShield vs {b_label}:** $\\chi^2 = {chi2:.3f}$, $p = {p_val:.4f}$ $\\rightarrow$ {sig_str}\n")
    buf.write("\n")

    buf.write("---\n\n")
    buf.write("## 5. Tool Versions & Reproducibility Environment\n\n")
    buf.write("```json\n")
    buf.write(json.dumps({
        "platform": summary.platform_info,
        "tool_versions": summary.tool_versions,
        "scanner_configuration": summary.scanner_config,
    }, indent=2))
    buf.write("\n```\n")

    return buf.getvalue()
