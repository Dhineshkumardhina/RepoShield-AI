"""RepoShield AI Empirical Benchmark Framework.

A reproducible scientific evaluation framework for benchmarking evidence-based security-fix
verification against static analysis, unit test suites, and AI-as-a-judge baselines.
"""

from .models import (
    BenchmarkCaseDefinition,
    CandidatePatchDefinition,
    DatasetSplit,
    GroundTruthLabel,
    VerificationVerdict,
    BenchmarkPatchType,
    BaselineId,
    SampleExperimentRecord,
    BaselineEvaluationMetrics,
    BenchmarkSuiteSummary,
)

__all__ = [
    "BenchmarkCaseDefinition",
    "CandidatePatchDefinition",
    "DatasetSplit",
    "GroundTruthLabel",
    "VerificationVerdict",
    "BenchmarkPatchType",
    "BaselineId",
    "SampleExperimentRecord",
    "BaselineEvaluationMetrics",
    "BenchmarkSuiteSummary",
]
