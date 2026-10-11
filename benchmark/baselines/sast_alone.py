"""Baseline A: Static Analysis Alone (SAST Delta).

Evaluates whether a candidate patch resolves a vulnerability by checking if
the target static analysis rule finding disappears between baseline and patched code.
"""
from pathlib import Path
import shutil
import time
from typing import Any, Dict

from .base import BaseVerificationBaseline, BaselineEvaluationOutcome, setup_temporary_sandbox
from ..models import BenchmarkCaseDefinition, CandidatePatchDefinition


class SastAloneBaseline(BaseVerificationBaseline):
    """Evaluates patch purely through static analysis delta."""

    @property
    def baseline_id(self) -> str:
        return "B1_sast_alone"

    @property
    def baseline_name(self) -> str:
        return "Static Analysis Alone (SAST Delta)"

    def evaluate_patch(
        self,
        case: BenchmarkCaseDefinition,
        patch: CandidatePatchDefinition,
        timeout_seconds: int = 20,
    ) -> BaselineEvaluationOutcome:
        start_time = time.perf_counter()
        from app.verification.runner import run_scanners_on_directory

        # 1. Setup and scan baseline workspace
        base_dir, _ = setup_temporary_sandbox(case)
        base_findings, base_meta, base_errs = run_scanners_on_directory(
            base_dir, scanner_names=["bandit"], timeout_seconds=timeout_seconds
        )

        # 2. Setup and scan patched workspace
        patch_dir, patch_applied = setup_temporary_sandbox(case, patch.unified_diff)
        patch_findings, patch_meta, patch_errs = run_scanners_on_directory(
            patch_dir, scanner_names=["bandit"], timeout_seconds=timeout_seconds
        )

        shutil.rmtree(base_dir, ignore_errors=True)
        shutil.rmtree(patch_dir, ignore_errors=True)
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        if not patch_applied:
            return BaselineEvaluationOutcome(
                baseline_id=self.baseline_id,
                baseline_name=self.baseline_name,
                decision="FAILED",
                latency_ms=elapsed_ms,
                error_message="Patch failed to apply cleanly to source tree",
                evidence={"patch_applied": False}
            )

        # Tool failure / timeout check
        if base_errs or patch_errs:
            err_msg = "; ".join(base_errs + patch_errs)
            return BaselineEvaluationOutcome(
                baseline_id=self.baseline_id,
                baseline_name=self.baseline_name,
                decision="INCONCLUSIVE",
                latency_ms=elapsed_ms,
                error_message=f"Scanner execution error/timeout: {err_msg}",
                evidence={"scanner_errors": base_errs + patch_errs}
            )

        target_rule = case.baseline_finding["rule_id"]
        base_had_target = any(f.scanner_rule_id == target_rule for f in base_findings)
        patch_has_target = any(f.scanner_rule_id == target_rule for f in patch_findings)

        evidence: Dict[str, Any] = {
            "target_rule": target_rule,
            "baseline_detected_rule": base_had_target,
            "patched_detected_rule": patch_has_target,
            "baseline_findings_count": len(base_findings),
            "patched_findings_count": len(patch_findings),
            "scanner_metadata": {**base_meta, **patch_meta},
        }

        if not base_had_target:
            # Epistemic honesty: SAST alone cannot evaluate fix if rule wasn't observed in baseline
            decision = "INCONCLUSIVE"
            evidence["rationale"] = f"Rule '{target_rule}' not observed in baseline; fix cannot be evaluated by SAST alone."
        elif patch_has_target:
            decision = "FAILED"
            evidence["rationale"] = f"Target finding rule '{target_rule}' persists in patched workspace."
        else:
            decision = "VERIFIED"
            evidence["rationale"] = f"Target finding rule '{target_rule}' resolved in patched workspace."

        return BaselineEvaluationOutcome(
            baseline_id=self.baseline_id,
            baseline_name=self.baseline_name,
            decision=decision,
            latency_ms=elapsed_ms,
            evidence=evidence
        )
