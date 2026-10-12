"""Benchmark baselines module.

Implements:
1. Baseline A: Static Analysis Alone (SAST Delta)
2. Baseline B: Existing Unit Tests Alone (General Test Suite)
3. Baseline C: AI / LLM Judge Alone (Syntactic Heuristic)
4. Baseline D: RepoShield Multi-Tier Evidence-Based Verification Pipeline
"""
from .base import BaseVerificationBaseline, BaselineEvaluationOutcome
from .sast_alone import SastAloneBaseline
from .tests_alone import ExistingTestsAloneBaseline
from .targeted_tests_alone import TargetedTestsAloneBaseline
from .ai_judge import AiJudgeBaseline
from .combined_verifier import RepoShieldCombinedBaseline

__all__ = [
    "BaseVerificationBaseline",
    "BaselineEvaluationOutcome",
    "SastAloneBaseline",
    "ExistingTestsAloneBaseline",
    "TargetedTestsAloneBaseline",
    "AiJudgeBaseline",
    "RepoShieldCombinedBaseline",
]
