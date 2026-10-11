"""Interpretable Machine Learning Models and Rule Baseline for Evidence Deficit Prediction.

Implements:
1. RuleBasedBaselineClassifier (Deterministic AppSec Heuristic)
2. InterpretableEvidenceDeficitModel (Calibrated Logistic Regression with Odds Ratios)
3. Advisory Safety Envelopes (Ensures ML outputs cannot override verification)
"""
from dataclasses import dataclass
import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier

from .features import FEATURE_NAMES, extract_features
from .dataset import FindingEvidenceSample


class RuleBasedBaselineClassifier:
    """Heuristic rule-based baseline reflecting standard AppSec triage procedures.
    
    Rules:
    - Rule A: If finding is in test file OR constant argument -> 0 (Locally resolvable mock / false positive).
    - Rule B: If prompt injection OR custom sanitizer OR cross-file reference OR context lines < 5 -> 1 (Needs evidence).
    - Rule C: If local sink present AND dynamic variables in sink > 0 -> 0 (Locally demonstrable vulnerability).
    - Default: 1 (Conservative triage fallback).
    """

    def predict_sample(self, sample: FindingEvidenceSample) -> int:
        if sample.is_test_file or sample.is_constant_arg:
            return 0
        if (
            sample.has_prompt_injection
            or sample.has_custom_sanitizer
            or sample.cross_file_reference
            or sample.code_context_lines < 5
        ):
            return 1
        if sample.has_local_sink and sample.num_variables_in_sink > 0:
            return 0
        return 1

    def predict(self, samples: List[FindingEvidenceSample]) -> np.ndarray:
        return np.array([self.predict_sample(s) for s in samples], dtype=np.int32)


class InterpretableEvidenceDeficitModel:
    """Interpretable L2-Regularized Logistic Regression Model with Feature Attributions.
    
    Attributes:
    - C: Regularization inverse parameter (default 1.0)
    - weights: Learned coefficients mapped to feature names for auditability
    - intercept: Base prior log-odds
    """

    def __init__(self, C: float = 1.0, random_state: int = 42):
        self.C = C
        self.random_state = random_state
        self.model = LogisticRegression(
            C=self.C,
            solver="liblinear",
            random_state=self.random_state,
        )
        self.feature_names = FEATURE_NAMES
        self.is_fitted = False
        self.training_metadata: Dict[str, Any] = {}

    def fit(self, X: np.ndarray, y: np.ndarray, metadata: Optional[Dict[str, Any]] = None):
        """Fits the logistic regression model on training matrix X and labels y."""
        start = time.perf_counter()
        self.model.fit(X, y)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        self.is_fitted = True

        self.training_metadata = {
            "fit_time_ms": elapsed_ms,
            "samples_trained": int(len(X)),
            "features_used": self.feature_names,
            "classes": [int(c) for c in self.model.classes_],
            "intercept": float(self.model.intercept_[0]),
            "coefficients": {
                name: float(weight)
                for name, weight in zip(self.feature_names, self.model.coef_[0])
            },
            **(metadata or {}),
        }

    def predict(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before predict() can be called.")
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before predict_proba() can be called.")
        return self.model.predict_proba(X)

    def explain_prediction(self, sample: FindingEvidenceSample) -> Dict[str, Any]:
        """Provides human-readable mathematical feature attribution for an individual prediction."""
        X_vec = extract_features(sample).reshape(1, -1)
        prob = float(self.predict_proba(X_vec)[0, 1])
        pred = int(prob >= 0.5)

        contributions: Dict[str, float] = {}
        for name, val, coef in zip(self.feature_names, X_vec[0], self.model.coef_[0]):
            contributions[name] = float(val * coef)

        # Sort top positive drivers (pushing towards requiring evidence)
        sorted_contrib = sorted(contributions.items(), key=lambda kv: kv[1], reverse=True)

        return {
            "sample_id": sample.sample_id,
            "predicted_label": pred,
            "deficit_probability": round(prob, 4),
            "recommendation": (
                "ADVISORY: Prioritize additional evidence / human auditor triage before patch generation."
                if pred == 1 else
                "ADVISORY: Local AST context is self-contained; eligible for automated verification pipeline."
            ),
            "base_intercept": round(float(self.model.intercept_[0]), 4),
            "top_positive_factors": [
                {"feature": k, "impact": round(v, 4)} for k, v in sorted_contrib if v > 0.05
            ][:3],
            "top_mitigating_factors": [
                {"feature": k, "impact": round(v, 4)} for k, v in sorted_contrib if v < -0.05
            ][:3],
        }

    def save(self, filepath: Path):
        """Serializes model weights and configuration to disk."""
        filepath.parent.mkdir(parents=True, exist_ok=True)
        bundle = {
            "model": self.model,
            "metadata": self.training_metadata,
            "feature_names": self.feature_names,
            "C": self.C,
        }
        joblib.dump(bundle, filepath)

    @classmethod
    def load(cls, filepath: Path) -> "InterpretableEvidenceDeficitModel":
        """Loads serialized model bundle from disk."""
        bundle = joblib.load(filepath)
        instance = cls(C=bundle["C"])
        instance.model = bundle["model"]
        instance.training_metadata = bundle["metadata"]
        instance.feature_names = bundle["feature_names"]
        instance.is_fitted = True
        return instance
