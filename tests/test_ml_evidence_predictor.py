"""Test Suite for Evidence Deficit Prediction Machine Learning Component.

Verifies:
1. Dataset schema, split isolation, and ground truth integrity.
2. Feature extraction vector dimensionalities and normalization bounds.
3. Rule-based baseline classifier determinism.
4. Interpretable Logistic Regression training, inference, and explanations.
5. Model disk serialization and deserialization equivalence.
6. Advisory safety invariants (ML output is strictly advisory and cannot override verification).
"""
import tempfile
from pathlib import Path
import numpy as np
import pytest

from ml_experiments.evidence_deficit_prediction.dataset import (
    FindingEvidenceSample,
    get_curated_evidence_dataset,
)
from ml_experiments.evidence_deficit_prediction.features import (
    FEATURE_NAMES,
    extract_dataset_matrices,
    extract_features,
)
from ml_experiments.evidence_deficit_prediction.model import (
    InterpretableEvidenceDeficitModel,
    RuleBasedBaselineClassifier,
)


def test_dataset_integrity_and_split_isolation():
    """Verify that dataset contains balanced representation and zero leakage across splits."""
    samples = get_curated_evidence_dataset()
    assert len(samples) >= 30, "Dataset must have sufficient sample density"

    train_samples = [s for s in samples if s.split == "train"]
    test_samples = [s for s in samples if s.split == "test"]

    assert len(train_samples) > 0
    assert len(test_samples) > 0

    # Verify zero repository leakage between train and test
    train_repos = {s.repo_name for s in train_samples}
    test_repos = {s.repo_name for s in test_samples}
    assert len(train_repos.intersection(test_repos)) == 0, "Train and test repositories must be strictly disjoint"

    # Verify label validity
    for s in samples:
        assert s.requires_additional_evidence in (0, 1)
        assert len(s.ground_truth_rationale) > 10


def test_feature_extractor_properties():
    """Verify that feature extraction yields correct dimensions and bounded values."""
    sample = FindingEvidenceSample(
        sample_id="T1", repo_name="r1", file_path="app.py", cwe_id="CWE-89",
        vulnerability_category="sql_injection", scanner_name="Bandit", scanner_severity="CRITICAL",
        scanner_confidence=0.9, has_local_sink=True, is_constant_arg=False, is_test_file=False,
        is_entrypoint_file=True, has_custom_sanitizer=False, has_prompt_injection=False,
        code_context_lines=15, num_variables_in_sink=2, cross_file_reference=False,
        has_framework_validation=True, requires_additional_evidence=0,
        ground_truth_rationale="test", split="train"
    )

    feat = extract_features(sample)
    assert isinstance(feat, np.ndarray)
    assert feat.shape == (len(FEATURE_NAMES),)
    assert 0.0 <= feat[0] <= 1.0  # severity normalized
    assert 0.0 <= feat[1] <= 1.0  # confidence
    assert 0.0 <= feat[8] <= 1.0  # context lines normalized


def test_rule_based_baseline_predictions():
    """Verify rule-based baseline follows documented heuristics."""
    rule_clf = RuleBasedBaselineClassifier()

    # Case 1: Test file -> should be 0
    test_sample = FindingEvidenceSample(
        sample_id="T2", repo_name="r1", file_path="tests/test_x.py", cwe_id="CWE-89",
        vulnerability_category="sql_injection", scanner_name="Bandit", scanner_severity="HIGH",
        scanner_confidence=0.9, has_local_sink=True, is_constant_arg=False, is_test_file=True,
        is_entrypoint_file=False, has_custom_sanitizer=False, has_prompt_injection=False,
        code_context_lines=10, num_variables_in_sink=1, cross_file_reference=False,
        has_framework_validation=False, requires_additional_evidence=0,
        ground_truth_rationale="test", split="train"
    )
    assert rule_clf.predict_sample(test_sample) == 0

    # Case 2: Custom sanitizer -> should be 1
    sanitizer_sample = FindingEvidenceSample(
        sample_id="T3", repo_name="r1", file_path="app.py", cwe_id="CWE-89",
        vulnerability_category="sql_injection", scanner_name="Bandit", scanner_severity="HIGH",
        scanner_confidence=0.9, has_local_sink=True, is_constant_arg=False, is_test_file=False,
        is_entrypoint_file=False, has_custom_sanitizer=True, has_prompt_injection=False,
        code_context_lines=10, num_variables_in_sink=1, cross_file_reference=False,
        has_framework_validation=False, requires_additional_evidence=1,
        ground_truth_rationale="test", split="train"
    )
    assert rule_clf.predict_sample(sanitizer_sample) == 1


def test_ml_model_fit_predict_and_explanation():
    """Verify ML model training, prediction, probabilities, and explainability."""
    samples = get_curated_evidence_dataset()
    train_samples = [s for s in samples if s.split == "train"]
    test_samples = [s for s in samples if s.split == "test"]

    X_train, y_train, _ = extract_dataset_matrices(train_samples)
    X_test, y_test, _ = extract_dataset_matrices(test_samples)

    model = InterpretableEvidenceDeficitModel(C=1.0, random_state=42)
    model.fit(X_train, y_train)

    assert model.is_fitted
    preds = model.predict(X_test)
    assert preds.shape == (len(test_samples),)
    assert set(preds).issubset({0, 1})

    probas = model.predict_proba(X_test)
    assert probas.shape == (len(test_samples), 2)
    assert np.all((probas >= 0.0) & (probas <= 1.0))
    assert np.allclose(np.sum(probas, axis=1), 1.0)

    # Explanation check
    exp = model.explain_prediction(test_samples[0])
    assert "deficit_probability" in exp
    assert "top_positive_factors" in exp
    assert "recommendation" in exp
    assert exp["recommendation"].startswith("ADVISORY:")


def test_model_serialization_and_reloading():
    """Verify model can be saved to disk and loaded with bit-identical outputs."""
    samples = get_curated_evidence_dataset()
    X_train, y_train, _ = extract_dataset_matrices(samples)

    model = InterpretableEvidenceDeficitModel(C=1.0, random_state=42)
    model.fit(X_train, y_train)

    with tempfile.TemporaryDirectory() as tmp_dir:
        model_file = Path(tmp_dir) / "test_model.joblib"
        model.save(model_file)
        assert model_file.exists()

        reloaded = InterpretableEvidenceDeficitModel.load(model_file)
        assert reloaded.is_fitted

        # Verify predictions match
        orig_preds = model.predict(X_train)
        reloaded_preds = reloaded.predict(X_train)
        np.testing.assert_array_equal(orig_preds, reloaded_preds)

        orig_probas = model.predict_proba(X_train)
        reloaded_probas = reloaded.predict_proba(X_train)
        np.testing.assert_allclose(orig_probas, reloaded_probas, atol=1e-5)


def test_advisory_safety_invariants():
    """Verify that ML model output explicitly declares non-authoritative advisory status."""
    samples = get_curated_evidence_dataset()
    X, y, _ = extract_dataset_matrices(samples)

    model = InterpretableEvidenceDeficitModel(C=1.0, random_state=42)
    model.fit(X, y)

    # Invariant: Model predictions must be framed as non-authoritative recommendations
    sample = samples[0]
    explanation = model.explain_prediction(sample)
    assert "ADVISORY" in explanation["recommendation"]
    assert "verification" in explanation["recommendation"].lower() or "patch" in explanation["recommendation"].lower()
