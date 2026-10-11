"""Benchmark Experiment Orchestrator and CLI Runner.

Loads benchmark cases, validates schemas, executes deduplication checks, runs
all four comparative verification baselines across development and held-out splits,
captures runtime evidence and tool configurations, computes metrics, and exports reports.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# Ensure backend and root workspace are on sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT / "backend"))
sys.path.insert(0, str(WORKSPACE_ROOT))

from benchmark.models import (
    BenchmarkCaseDefinition,
    CandidatePatchDefinition,
    BenchmarkSuiteSummary,
    DatasetSplit,
    SampleExperimentRecord,
)
from benchmark.deduplicator import validate_dataset_uniqueness_and_splits
from benchmark.baselines import (
    SastAloneBaseline,
    ExistingTestsAloneBaseline,
    AiJudgeBaseline,
    RepoShieldCombinedBaseline,
)
from benchmark.metrics import calculate_baseline_metrics, evaluate_correctness
from benchmark.reporting import (
    export_csv_detailed_samples,
    export_csv_summary,
    export_json_report,
    generate_markdown_report,
)


def get_environment_metadata() -> Tuple[Dict[str, str], Dict[str, str], Dict[str, Any]]:
    """Capture system platform information, scanner tool versions, and configurations."""
    platform_info = {
        "os": os.name,
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "processor": platform.processor(),
    }

    tool_versions: Dict[str, str] = {
        "python": sys.version.split()[0],
    }

    # Detect Bandit version
    try:
        import bandit
        tool_versions["bandit"] = getattr(bandit, "__version__", "1.7.0+")
    except ImportError:
        tool_versions["bandit"] = "not_installed"

    # Detect Pytest version
    try:
        import pytest
        tool_versions["pytest"] = getattr(pytest, "__version__", "8.0.0+")
    except ImportError:
        tool_versions["pytest"] = "not_installed"

    scanner_config = {
        "timeout_seconds": 20,
        "rule_profiles": ["bandit_default", "semgrep_security_audit"],
        "severity_threshold": "LOW",
        "confidence_threshold": "LOW",
        "secret_detector_enabled": True,
        "sandbox_isolation": "disposable_scratchdir",
    }

    return platform_info, tool_versions, scanner_config


def load_benchmark_cases(
    cases_dir: Path,
    split_filter: Optional[str] = None,
) -> List[BenchmarkCaseDefinition]:
    """Parse and validate all benchmark JSON case files."""
    case_files = sorted(cases_dir.glob("*.json"))
    cases: List[BenchmarkCaseDefinition] = []

    for cf in case_files:
        try:
            data = json.loads(cf.read_text(encoding="utf-8"))
            patches = [
                CandidatePatchDefinition(
                    patch_id=p["patch_id"],
                    patch_type=p["patch_type"],
                    ground_truth_label=p["ground_truth_label"],
                    ground_truth_rationale=p.get("ground_truth_rationale", p.get("description", "")),
                    expected_classification=p.get("expected_classification", "VERIFIED" if p["ground_truth_label"] == "FIX" else "FAILED"),
                    unified_diff=p["unified_diff"],
                    description=p["description"],
                    expected_regression_status=p.get("expected_regression_status"),
                )
                for p in data["candidate_patches"]
            ]

            case = BenchmarkCaseDefinition(
                case_id=data["case_id"],
                origin=data.get("origin", "synthetic_curated"),
                cwe_id=data["cwe_id"],
                vulnerability_category=data["vulnerability_category"],
                description=data["description"],
                source_file=data["source_file"],
                vulnerable_code=data["vulnerable_code"],
                baseline_revision=data.get("baseline_revision", "sha256-unpinned"),
                baseline_finding=data["baseline_finding"],
                candidate_patches=patches,
                split=data.get("split", DatasetSplit.DEV.value),
                cve_id=data.get("cve_id"),
                existing_unit_test=data.get("existing_unit_test"),
                targeted_regression_test=data.get("targeted_regression_test"),
            )

            if split_filter and case.split != split_filter:
                continue

            cases.append(case)
        except Exception as e:
            print(f"[!] Warning: Failed parsing benchmark file {cf.name}: {e}", file=sys.stderr)

    return cases


def run_benchmark_suite(
    cases_dir: Path,
    results_dir: Path,
    split_filter: Optional[str] = None,
    timeout_seconds: int = 20,
    verbose: bool = True,
) -> BenchmarkSuiteSummary:
    """Execute complete reproducible evaluation across all baselines and benchmark cases."""
    platform_info, tool_versions, scanner_config = get_environment_metadata()
    cases = load_benchmark_cases(cases_dir, split_filter=split_filter)

    if not cases:
        raise ValueError(f"No benchmark cases found in {cases_dir} (filter={split_filter})")

    # Deduplication and Split Integrity Check
    dedup_report = validate_dataset_uniqueness_and_splits(cases)
    if dedup_report.has_errors:
        err_msgs = [i.message for i in dedup_report.issues if i.severity == "error"]
        raise ValueError(f"Benchmark dataset validation failed: {'; '.join(err_msgs)}")

    if verbose:
        print(f"[*] Loaded {len(cases)} benchmark cases ({dedup_report.total_patches_analyzed} candidate patches)")
        print(f"[*] Split integrity confirmed: {dedup_report.unique_cases} unique cases, {dedup_report.unique_patches} unique patches")

    baselines = [
        SastAloneBaseline(),
        ExistingTestsAloneBaseline(),
        AiJudgeBaseline(),
        RepoShieldCombinedBaseline(),
    ]

    all_sample_records: List[SampleExperimentRecord] = []

    dev_count = sum(len(c.candidate_patches) for c in cases if c.split == "dev")
    held_out_count = sum(len(c.candidate_patches) for c in cases if c.split == "held_out")

    for case in cases:
        if verbose:
            print(f"\n---> Evaluating [{case.split.upper()}] Case {case.case_id}: {case.cwe_id} ({case.vulnerability_category})")

        for patch in case.candidate_patches:
            if verbose:
                print(f"     Patch {patch.patch_id} [{patch.patch_type}] (Ground Truth: {patch.ground_truth_label})")

            for b in baselines:
                try:
                    outcome = b.evaluate_patch(case, patch, timeout_seconds=timeout_seconds)
                except Exception as ex:
                    # Capture failed experiments without crashing the benchmark
                    from benchmark.baselines.base import BaselineEvaluationOutcome
                    outcome = BaselineEvaluationOutcome(
                        baseline_id=b.baseline_id,
                        baseline_name=b.baseline_name,
                        decision="INCONCLUSIVE",
                        latency_ms=0.0,
                        error_message=f"Unhandled tool crash: {str(ex)}",
                        evidence={"exception": str(ex)}
                    )

                is_corr = evaluate_correctness(patch.ground_truth_label, outcome.decision)

                rec = SampleExperimentRecord(
                    case_id=case.case_id,
                    patch_id=patch.patch_id,
                    patch_type=patch.patch_type,
                    split=case.split,
                    origin=case.origin,
                    vulnerability_category=case.vulnerability_category,
                    baseline_revision=case.baseline_revision,
                    proposed_patch=patch.unified_diff,
                    ground_truth_label=patch.ground_truth_label,
                    ground_truth_rationale=patch.ground_truth_rationale,
                    baseline_id=b.baseline_id,
                    baseline_name=b.baseline_name,
                    expected_classification=patch.expected_classification,
                    actual_classification=outcome.decision,
                    is_correct=is_corr,
                    runtime_ms=outcome.latency_ms,
                    error_message=outcome.error_message,
                    evidence=outcome.evidence,
                )
                all_sample_records.append(rec)

                if verbose:
                    status_flag = "PASS" if is_corr else "FAIL"
                    print(f"       [{b.baseline_name[:36]:36s}] -> {outcome.decision:12s} ({status_flag}) [{outcome.latency_ms:.1f}ms]")

    # Compute empirical metrics across all 4 baselines
    metrics_list = [
        calculate_baseline_metrics(all_sample_records, b.baseline_id, b.baseline_name)
        for b in baselines
    ]

    summary = BenchmarkSuiteSummary(
        timestamp=datetime.now(timezone.utc).isoformat(),
        platform_info=platform_info,
        tool_versions=tool_versions,
        scanner_config=scanner_config,
        total_cases=len(cases),
        total_patches=len(all_sample_records) // len(baselines),
        dev_patches_count=dev_count,
        held_out_patches_count=held_out_count,
        metrics=metrics_list,
        sample_records=all_sample_records,
    )

    # Export machine-readable and human-readable outputs
    results_dir.mkdir(parents=True, exist_ok=True)
    export_json_report(summary, results_dir / "latest_evaluation_report.json")
    export_csv_summary(metrics_list, results_dir / "benchmark_metrics_summary.csv")
    export_csv_detailed_samples(all_sample_records, results_dir / "benchmark_samples.csv")

    md_report = generate_markdown_report(summary)
    (results_dir / "benchmark_evaluation_report.md").write_text(md_report, encoding="utf-8")

    if verbose:
        print("\n" + "=" * 125)
        print("EMPIRICAL BENCHMARK EVALUATION RESULTS TABLE")
        print("=" * 125)
        print("| Baseline Approach | Correct Class. Rate | Precision | Recall | False Pos. Rate | False Neg. Rate | Inconclusive Rate | Regression Det. | Median Latency |")
        print("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
        for m in metrics_list:
            print(f"| **{m.baseline_name:40s}** | {m.correct_classification_rate:6.1%} | {m.precision:6.1%} | {m.recall:6.1%} | {m.false_positive_rate:6.1%} | {m.false_negative_rate:6.1%} | {m.inconclusive_rate:6.1%} | {m.regression_detection_rate:6.1%} | {m.median_latency_ms:7.1f}ms |")
        print("=" * 125 + "\n")
        print(f"[*] Serialized machine-readable JSON to {results_dir / 'latest_evaluation_report.json'}")
        print(f"[*] Serialized summary CSV to {results_dir / 'benchmark_metrics_summary.csv'}")
        print(f"[*] Serialized detailed samples CSV to {results_dir / 'benchmark_samples.csv'}")
        print(f"[*] Serialized Markdown research report to {results_dir / 'benchmark_evaluation_report.md'}")

    return summary


def main():
    parser = argparse.ArgumentParser(description="RepoShield AI Reproducible Fix Verification Benchmark Suite")
    parser.add_argument("--cases-dir", type=Path, default=WORKSPACE_ROOT / "benchmark" / "cases", help="Path to benchmark case JSON files")
    parser.add_argument("--results-dir", type=Path, default=WORKSPACE_ROOT / "benchmark" / "results", help="Directory for output reports")
    parser.add_argument("--split", type=str, choices=["dev", "held_out", "all"], default="all", help="Dataset split filter")
    parser.add_argument("--timeout", type=int, default=20, help="Per-test/scan timeout limit in seconds")
    parser.add_argument("--quiet", action="store_true", help="Suppress verbose stdout traces")

    args = parser.parse_args()
    split_arg = None if args.split == "all" else args.split

    run_benchmark_suite(
        cases_dir=args.cases_dir,
        results_dir=args.results_dir,
        split_filter=split_arg,
        timeout_seconds=args.timeout,
        verbose=not args.quiet,
    )


if __name__ == "__main__":
    main()
