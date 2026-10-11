#!/usr/bin/env python3
"""Empirical Evaluation Runner for RepoShield AI Security-Fix Verification.

Executes and benchmarks four distinct verification strategies against a curated
ground-truth security fix dataset:
1. Baseline 1: Static Analysis Alone (SAST Delta)
2. Baseline 2: Existing Unit Tests Alone (General Test Suite)
3. Baseline 3: AI-Generated / LLM Judge Alone (Syntactic & Heuristic Plausibility)
4. Baseline 4: RepoShield Combined Pipeline (Multi-Tier Evidence Gate)

Calculates:
- Precision, Recall, FPR, FNR
- Inconclusive Outcome Rate
- Regression Detection Rate
- Latency (Mean, Median, p95)
- Confusion Matrix & McNemar's Significance Test
"""
from pathlib import Path
import sys

# Add workspace root and backend directory to sys.path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT / "backend"))
sys.path.insert(0, str(WORKSPACE_ROOT))

from benchmark.runner import run_benchmark_suite


if __name__ == "__main__":
    cases_dir = WORKSPACE_ROOT / "benchmark" / "cases"
    results_dir = WORKSPACE_ROOT / "benchmark" / "results"

    if not cases_dir.exists():
        print(f"[!] Error: Benchmark cases directory {cases_dir} does not exist.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Starting RepoShield AI Reproducible Fix-Verification Benchmark...")
    summary = run_benchmark_suite(
        cases_dir=cases_dir,
        results_dir=results_dir,
        split_filter=None,
        timeout_seconds=20,
        verbose=True,
    )
    print(f"[*] Completed evaluation of {summary.total_patches} patches across {summary.total_cases} cases.")
