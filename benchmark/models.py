"""Data Models and Schema Definitions for RepoShield AI Benchmark Framework.

Defines:
- BenchmarkCaseDefinition and CandidatePatchDefinition
- Evaluation sample records capturing all input/output attributes
- Formal metrics dataclasses with exact denominators
- Baseline identifiers and experiment metadata
"""
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class DatasetSplit(str, Enum):
    DEV = "dev"
    HELD_OUT = "held_out"


class GroundTruthLabel(str, Enum):
    FIX = "FIX"                      # True fix: completely eliminates vulnerability without regressions
    NON_FIX = "NON_FIX"              # Flawed fix: ineffective, partial, regressive, or cosmetic evasion
    INCONCLUSIVE = "INCONCLUSIVE"    # Missing evidence, unsupported scanner rule, or tool failure


class VerificationVerdict(str, Enum):
    VERIFIED = "VERIFIED"            # Certified resolved against defined checks
    FAILED = "FAILED"                # Verification rejected due to persisting flaw, regression, or failure
    INCONCLUSIVE = "INCONCLUSIVE"    # Judgment withheld due to insufficient evidence or tool fault


class BenchmarkPatchType(str, Enum):
    TRUE_FIX = "true_fix"
    INEFFECTIVE_FIX = "ineffective_fix"
    COSMETIC_EVASION = "cosmetic_evasion"
    PARTIAL_FIX = "incomplete_fix"
    REGRESSIVE_FUNCTIONAL = "regressive_fix"
    REGRESSIVE_SECURITY = "security_regression"
    FALSE_POSITIVE = "false_positive_finding"
    MISSING_EVIDENCE = "missing_evidence_case"
    TOOL_FAILURE = "tool_failure_timeout"


class BaselineId(str, Enum):
    B1_SAST_ALONE = "B1_sast_alone"
    B2_EXISTING_TESTS = "B2_existing_tests"
    B3_AI_JUDGE = "B3_ai_judge"
    B4_REPOSHIELD_COMBINED = "B4_reposhield_pipeline"


@dataclass
class CandidatePatchDefinition:
    patch_id: str
    patch_type: str
    ground_truth_label: str
    ground_truth_rationale: str
    expected_classification: str
    unified_diff: str
    description: str
    expected_regression_status: Optional[str] = None


@dataclass
class BenchmarkCaseDefinition:
    case_id: str
    origin: str
    cwe_id: str
    vulnerability_category: str
    description: str
    source_file: str
    vulnerable_code: str
    baseline_revision: str
    baseline_finding: Dict[str, Any]
    candidate_patches: List[CandidatePatchDefinition]
    split: str = DatasetSplit.DEV.value
    cve_id: Optional[str] = None
    existing_unit_test: Optional[str] = None
    targeted_regression_test: Optional[str] = None


@dataclass
class VerificationEvidenceRecord:
    baseline_revision: str
    patched_revision: Optional[str]
    scanner_configuration: Dict[str, Any]
    scanner_versions: Dict[str, str]
    original_findings: List[Dict[str, Any]]
    new_findings: List[Dict[str, Any]]
    classified_findings: List[Dict[str, Any]]
    tests_executed: List[str]
    test_results: Dict[str, Any]
    missing_checks: List[str]
    final_status: str
    rationale: str


@dataclass
class SampleExperimentRecord:
    case_id: str
    patch_id: str
    patch_type: str
    split: str
    origin: str
    vulnerability_category: str
    baseline_revision: str
    proposed_patch: str
    ground_truth_label: str
    ground_truth_rationale: str
    baseline_id: str
    baseline_name: str
    expected_classification: str
    actual_classification: str
    is_correct: bool
    runtime_ms: float
    error_message: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BaselineEvaluationMetrics:
    baseline_id: str
    baseline_name: str
    total_samples: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    inconclusive_count: int = 0
    correct_count: int = 0
    correct_classification_rate: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    inconclusive_rate: float = 0.0
    regression_detection_rate: float = 0.0
    mean_latency_ms: float = 0.0
    median_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkSuiteSummary:
    timestamp: str
    platform_info: Dict[str, str]
    tool_versions: Dict[str, str]
    scanner_config: Dict[str, Any]
    total_cases: int
    total_patches: int
    dev_patches_count: int
    held_out_patches_count: int
    metrics: List[BaselineEvaluationMetrics]
    sample_records: List[SampleExperimentRecord]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "platform_info": self.platform_info,
            "tool_versions": self.tool_versions,
            "scanner_config": self.scanner_config,
            "total_cases": self.total_cases,
            "total_patches": self.total_patches,
            "dev_patches_count": self.dev_patches_count,
            "held_out_patches_count": self.held_out_patches_count,
            "metrics": [m.to_dict() for m in self.metrics],
            "sample_records": [s.to_dict() for s in self.sample_records],
        }
