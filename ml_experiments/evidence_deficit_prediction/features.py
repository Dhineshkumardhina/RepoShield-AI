"""Feature Extraction Pipeline for Evidence Deficit Prediction.

Converts finding evidence samples and AST indicators into normalized,
strictly interpretable numeric feature vectors for baseline and ML classifiers.
"""
from typing import Dict, List, Tuple
import numpy as np

from .dataset import FindingEvidenceSample

SEVERITY_MAP = {
    "INFORMATIONAL": 0.0,
    "LOW": 1.0,
    "MEDIUM": 2.0,
    "HIGH": 3.0,
    "CRITICAL": 4.0,
}

FEATURE_NAMES = [
    "severity_normalized",          # Scanner severity mapped [0.0 - 1.0]
    "scanner_confidence",           # Scanner reported confidence [0.0 - 1.0]
    "has_local_sink",               # 1.0 if sink explicitly observed in function
    "is_constant_arg",              # 1.0 if argument is literal compile-time constant
    "is_test_file",                 # 1.0 if located in test / mock directory
    "is_entrypoint_file",           # 1.0 if located in API / controller route
    "has_custom_sanitizer",         # 1.0 if custom unverified sanitizer call observed
    "has_prompt_injection",         # 1.0 if adversarial commentary detected
    "context_lines_normalized",     # min(context_lines, 30) / 30.0
    "num_variables_in_sink",        # Count of dynamic variables in sink
    "cross_file_reference",         # 1.0 if tainted input originates outside function
    "has_framework_validation",     # 1.0 if decorated by Pydantic / validation schema
]


def extract_features(sample: FindingEvidenceSample) -> np.ndarray:
    """Extracts a 1D float vector of 12 interpretable features from a sample."""
    sev_raw = sample.scanner_severity.upper()
    sev_num = SEVERITY_MAP.get(sev_raw, 2.0) / 4.0

    ctx_lines_norm = min(max(sample.code_context_lines, 0), 30) / 30.0

    features = [
        sev_num,
        float(sample.scanner_confidence),
        1.0 if sample.has_local_sink else 0.0,
        1.0 if sample.is_constant_arg else 0.0,
        1.0 if sample.is_test_file else 0.0,
        1.0 if sample.is_entrypoint_file else 0.0,
        1.0 if sample.has_custom_sanitizer else 0.0,
        1.0 if sample.has_prompt_injection else 0.0,
        ctx_lines_norm,
        float(sample.num_variables_in_sink),
        1.0 if sample.cross_file_reference else 0.0,
        1.0 if sample.has_framework_validation else 0.0,
    ]
    return np.array(features, dtype=np.float32)


def extract_dataset_matrices(
    samples: List[FindingEvidenceSample],
) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """Converts a collection of samples into feature matrix X, label vector y, and sample IDs."""
    X = np.array([extract_features(s) for s in samples], dtype=np.float32)
    y = np.array([s.requires_additional_evidence for s in samples], dtype=np.int32)
    sample_ids = [s.sample_id for s in samples]
    return X, y, sample_ids
