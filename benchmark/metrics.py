"""Empirical Metrics Engine for Security-Fix Verification Evaluation.

Defines exact mathematical formulas, denominators, confusion matrices,
inconclusive handling rules, and statistical significance tests.
"""
from dataclasses import dataclass
import math
from typing import Dict, List, Optional, Tuple

from .models import (
    BaselineEvaluationMetrics,
    GroundTruthLabel,
    SampleExperimentRecord,
    VerificationVerdict,
)


def evaluate_correctness(ground_truth: str, predicted: str) -> bool:
    """Evaluate whether predicted classification matches ground truth under safety rules.

    Handling of Inconclusive & Safety Rules:
    - Ground Truth FIX: Correct iff predicted is VERIFIED.
    - Ground Truth NON_FIX: Correct if safely rejected as FAILED or held as INCONCLUSIVE.
    - Ground Truth INCONCLUSIVE: Correct iff predicted is INCONCLUSIVE (epistemic honesty).
    """
    if ground_truth == GroundTruthLabel.FIX.value:
        return predicted == VerificationVerdict.VERIFIED.value
    elif ground_truth == GroundTruthLabel.NON_FIX.value:
        return predicted in (VerificationVerdict.FAILED.value, VerificationVerdict.INCONCLUSIVE.value)
    elif ground_truth == GroundTruthLabel.INCONCLUSIVE.value:
        return predicted == VerificationVerdict.INCONCLUSIVE.value
    return False


def calculate_baseline_metrics(
    records: List[SampleExperimentRecord],
    baseline_id: str,
    baseline_name: str,
) -> BaselineEvaluationMetrics:
    """Calculate rigorous empirical metrics for a baseline across evaluated sample records.

    Denominator & Metric Specifications:
    - Total Samples (N): Total records evaluated for this baseline.
    - True Positives (TP): GT=FIX and Pred=VERIFIED.
    - False Positives (FP): GT in (NON_FIX, INCONCLUSIVE) and Pred=VERIFIED.
    - True Negatives (TN): GT in (NON_FIX, INCONCLUSIVE) and Pred in (FAILED, INCONCLUSIVE).
    - False Negatives (FN): GT=FIX and Pred in (FAILED, INCONCLUSIVE).
    - Precision: TP / (TP + FP)  [Denominator: total declared VERIFIED]
    - Recall: TP / (TP + FN)     [Denominator: total ground-truth FIX]
    - False Positive Rate: FP / (FP + TN) [Denominator: total non-fix and inconclusive samples]
    - False Negative Rate: FN / (TP + FN) = 1 - Recall [Denominator: total ground-truth FIX]
    - Inconclusive Rate: Pred=INCONCLUSIVE / N [Denominator: total evaluated samples N]
    - Regression Detection Rate: Regressive fixes caught as FAILED / Total regressive fixes
    """
    filtered = [r for r in records if r.baseline_id == baseline_id]
    metrics = BaselineEvaluationMetrics(baseline_id=baseline_id, baseline_name=baseline_name)
    metrics.total_samples = len(filtered)
    if not filtered:
        return metrics

    latencies: List[float] = []
    regressive_samples = [
        r for r in filtered if r.patch_type in ("regressive_fix", "security_regression")
    ]
    detected_regressions = 0

    for r in filtered:
        latencies.append(r.runtime_ms)
        gt = r.ground_truth_label
        pred = r.actual_classification

        if pred == VerificationVerdict.INCONCLUSIVE.value:
            metrics.inconclusive_count += 1

        if r.is_correct:
            metrics.correct_count += 1

        # Confusion Matrix Categorization
        if gt == GroundTruthLabel.FIX.value:
            if pred == VerificationVerdict.VERIFIED.value:
                metrics.true_positives += 1
            else:
                metrics.false_negatives += 1
        elif gt in (GroundTruthLabel.NON_FIX.value, GroundTruthLabel.INCONCLUSIVE.value):
            if pred == VerificationVerdict.VERIFIED.value:
                # Fatal security hazard: certifying non-fix as verified
                metrics.false_positives += 1
            else:
                # Conservative safe block or epistemic honesty
                metrics.true_negatives += 1

        # Regression detection tracking
        if r.patch_type in ("regressive_fix", "security_regression"):
            if pred == VerificationVerdict.FAILED.value:
                detected_regressions += 1

    # Ratio Calculations
    metrics.correct_classification_rate = (
        (metrics.correct_count / metrics.total_samples) if metrics.total_samples > 0 else 0.0
    )

    denom_p = metrics.true_positives + metrics.false_positives
    metrics.precision = (metrics.true_positives / denom_p) if denom_p > 0 else 0.0

    denom_r = metrics.true_positives + metrics.false_negatives
    metrics.recall = (metrics.true_positives / denom_r) if denom_r > 0 else 0.0

    denom_fpr = metrics.false_positives + metrics.true_negatives
    metrics.false_positive_rate = (metrics.false_positives / denom_fpr) if denom_fpr > 0 else 0.0

    denom_fnr = metrics.false_negatives + metrics.true_positives
    metrics.false_negative_rate = (metrics.false_negatives / denom_fnr) if denom_fnr > 0 else 0.0

    metrics.inconclusive_rate = (
        (metrics.inconclusive_count / metrics.total_samples) if metrics.total_samples > 0 else 0.0
    )

    if regressive_samples:
        metrics.regression_detection_rate = detected_regressions / len(regressive_samples)
    else:
        metrics.regression_detection_rate = 0.0

    # Latency Distributions
    latencies.sort()
    metrics.mean_latency_ms = sum(latencies) / len(latencies)
    metrics.median_latency_ms = latencies[len(latencies) // 2]
    p95_idx = int(0.95 * len(latencies))
    metrics.p95_latency_ms = latencies[min(p95_idx, len(latencies) - 1)]

    return metrics


def compute_mcnemar_test(
    records: List[SampleExperimentRecord],
    baseline_a_id: str,
    baseline_b_id: str,
) -> Tuple[float, float]:
    """Compute McNemar's chi-squared test with Edwards continuity correction for paired outcomes.

    Returns:
        (chi2_statistic, p_value_approx)
    """
    paired_a: Dict[Tuple[str, str], bool] = {}
    paired_b: Dict[Tuple[str, str], bool] = {}

    for r in records:
        key = (r.case_id, r.patch_id)
        if r.baseline_id == baseline_a_id:
            paired_a[key] = r.is_correct
        elif r.baseline_id == baseline_b_id:
            paired_b[key] = r.is_correct

    common_keys = set(paired_a.keys()).intersection(paired_b.keys())
    b_count = 0  # A correct, B incorrect
    c_count = 0  # A incorrect, B correct

    for k in common_keys:
        a_corr = paired_a[k]
        b_corr = paired_b[k]
        if a_corr and not b_corr:
            b_count += 1
        elif not a_corr and b_corr:
            c_count += 1

    total_discordant = b_count + c_count
    if total_discordant == 0:
        return 0.0, 1.0

    # McNemar with continuity correction
    chi2 = (abs(b_count - c_count) - 1.0) ** 2 / total_discordant
    
    # 1-df chi-square p-value approximation via survival function
    # p ≈ erfc(sqrt(chi2 / 2))
    p_val = math.erfc(math.sqrt(max(0.0, chi2) / 2.0))
    return chi2, p_val
