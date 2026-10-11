"""Baseline B: Existing Unit Tests Alone (General CI Test Suite).

Evaluates whether a candidate patch passes standard existing unit tests
without performing targeted security regression tests or static analysis.
"""
from pathlib import Path
import shutil
import time
from typing import Any, Dict

from .base import BaseVerificationBaseline, BaselineEvaluationOutcome, setup_temporary_sandbox
from ..models import BenchmarkCaseDefinition, CandidatePatchDefinition


class ExistingTestsAloneBaseline(BaseVerificationBaseline):
    """Evaluates patch purely through general unit test suite execution."""

    @property
    def baseline_id(self) -> str:
        return "B2_existing_tests"

    @property
    def baseline_name(self) -> str:
        return "Existing Unit Tests Alone (General Test Suite)"

    def evaluate_patch(
        self,
        case: BenchmarkCaseDefinition,
        patch: CandidatePatchDefinition,
        timeout_seconds: int = 20,
    ) -> BaselineEvaluationOutcome:
        start_time = time.perf_counter()
        from app.verification.runner import run_pytest_in_workspace

        patch_dir, patch_applied = setup_temporary_sandbox(case, patch.unified_diff)
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        if not patch_applied:
            shutil.rmtree(patch_dir, ignore_errors=True)
            return BaselineEvaluationOutcome(
                baseline_id=self.baseline_id,
                baseline_name=self.baseline_name,
                decision="FAILED",
                latency_ms=elapsed_ms,
                error_message="Patch failed to apply cleanly to source tree",
                evidence={"patch_applied": False}
            )

        if not case.existing_unit_test:
            shutil.rmtree(patch_dir, ignore_errors=True)
            return BaselineEvaluationOutcome(
                baseline_id=self.baseline_id,
                baseline_name=self.baseline_name,
                decision="INCONCLUSIVE",
                latency_ms=elapsed_ms,
                evidence={"rationale": "No existing unit test suite was configured for this case."}
            )

        outcome = run_pytest_in_workspace(
            patch_dir, test_target="tests/test_existing.py", timeout_seconds=timeout_seconds
        )
        shutil.rmtree(patch_dir, ignore_errors=True)
        total_latency = (time.perf_counter() - start_time) * 1000

        evidence: Dict[str, Any] = {
            "test_status": outcome.status,
            "passed_count": outcome.passed_count,
            "failed_count": outcome.failed_count,
            "error_message": outcome.error_message,
        }

        if outcome.status in ("skipped", "error", "timeout"):
            decision = "INCONCLUSIVE"
            evidence["rationale"] = f"Unit test execution was {outcome.status}: {outcome.error_message or 'No tests ran'}"
        elif outcome.status == "passed":
            decision = "VERIFIED"
            evidence["rationale"] = f"All existing unit tests passed ({outcome.passed_count} passed)."
        else:
            decision = "FAILED"
            evidence["rationale"] = f"Existing unit tests failed ({outcome.failed_count} failed)."

        return BaselineEvaluationOutcome(
            baseline_id=self.baseline_id,
            baseline_name=self.baseline_name,
            decision=decision,
            latency_ms=total_latency,
            error_message=outcome.error_message,
            evidence=evidence
        )
