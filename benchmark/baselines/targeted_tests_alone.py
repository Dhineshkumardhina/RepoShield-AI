"""Baseline B: Targeted Tests Alone (Security Exploit Regression Test).

Evaluates candidate patches solely through targeted security exploit tests
(asserting that specific attack payloads fail against patched code),
without static analysis delta or general unit test suite regressions.
"""
from pathlib import Path
import shutil
import time
from typing import Any, Dict

from .base import BaseVerificationBaseline, BaselineEvaluationOutcome, setup_temporary_sandbox
from ..models import BenchmarkCaseDefinition, CandidatePatchDefinition


class TargetedTestsAloneBaseline(BaseVerificationBaseline):
    """Evaluates patch purely through targeted security regression test execution."""

    @property
    def baseline_id(self) -> str:
        return "B2_targeted_tests"

    @property
    def baseline_name(self) -> str:
        return "Targeted Tests Alone (Exploit Regression Suite)"

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

        if not case.targeted_regression_test:
            shutil.rmtree(patch_dir, ignore_errors=True)
            return BaselineEvaluationOutcome(
                baseline_id=self.baseline_id,
                baseline_name=self.baseline_name,
                decision="INCONCLUSIVE",
                latency_ms=elapsed_ms,
                evidence={"rationale": "No targeted exploit regression test was configured for this case."}
            )

        # Write targeted exploit test into workspace
        test_file = patch_dir / "tests" / "test_targeted_exploit.py"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text(case.targeted_regression_test, encoding="utf-8")

        outcome = run_pytest_in_workspace(
            patch_dir, test_target="tests/test_targeted_exploit.py", timeout_seconds=timeout_seconds
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
            evidence["rationale"] = f"Targeted exploit test was {outcome.status}: {outcome.error_message or 'No tests ran'}"
        elif outcome.status == "passed":
            decision = "VERIFIED"
            evidence["rationale"] = f"Targeted security regression test passed ({outcome.passed_count} passed)."
        else:
            decision = "FAILED"
            evidence["rationale"] = f"Targeted security regression test failed: exploit succeeded ({outcome.failed_count} failed)."

        return BaselineEvaluationOutcome(
            baseline_id=self.baseline_id,
            baseline_name=self.baseline_name,
            decision=decision,
            latency_ms=total_latency,
            error_message=outcome.error_message,
            evidence=evidence
        )
