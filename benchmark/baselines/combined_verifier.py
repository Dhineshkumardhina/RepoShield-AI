"""Baseline D: RepoShield Multi-Tier Evidence-Based Verification Pipeline.

Integrates:
1. Unified diff validation & path traversal prevention.
2. Isolated temporary workspace sandboxing.
3. Differential SAST multi-scanner analysis.
4. 6-status regression finding comparator.
5. Existing unit test suite execution with test regression detection.
6. Targeted security exploit regression test execution.
7. Explicit epistemic decision logic without unjustified certainty.
"""
from pathlib import Path
import shutil
import time
from typing import Any, Dict, List

from .base import BaseVerificationBaseline, BaselineEvaluationOutcome, setup_temporary_sandbox
from ..models import BenchmarkCaseDefinition, CandidatePatchDefinition


class RepoShieldCombinedBaseline(BaseVerificationBaseline):
    """RepoShield AI Multi-Tier Evidence-Driven Verification Pipeline."""

    @property
    def baseline_id(self) -> str:
        return "B4_reposhield_pipeline"

    @property
    def baseline_name(self) -> str:
        return "RepoShield Combined Pipeline (Multi-Tier Evidence Gate)"

    def evaluate_patch(
        self,
        case: BenchmarkCaseDefinition,
        patch: CandidatePatchDefinition,
        timeout_seconds: int = 20,
    ) -> BaselineEvaluationOutcome:
        start_time = time.perf_counter()

        from app.verification.comparator import compare_verification_findings
        from app.verification.patch_parser import parse_unified_diff
        from app.verification.runner import run_pytest_in_workspace, run_scanners_on_directory
        from app.schemas.verification import FindingRegressionClassification

        # 1. Parse and validate unified diff
        parsed = parse_unified_diff(patch.unified_diff)
        if not parsed.is_valid:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return BaselineEvaluationOutcome(
                baseline_id=self.baseline_id,
                baseline_name=self.baseline_name,
                decision="INCONCLUSIVE",
                latency_ms=elapsed_ms,
                error_message=f"Invalid patch: {'; '.join(parsed.errors)}",
                evidence={"patch_valid": False, "patch_errors": parsed.errors}
            )

        # 2. Setup baseline workspace and run scanners
        base_dir, _ = setup_temporary_sandbox(case)
        base_findings, base_meta, base_errs = run_scanners_on_directory(
            base_dir, scanner_names=["bandit"], timeout_seconds=timeout_seconds
        )

        # Baseline tests (pre-patch baseline test capture)
        base_test_passed = True
        if case.existing_unit_test:
            base_test_out = run_pytest_in_workspace(
                base_dir, test_target="tests/test_existing.py", timeout_seconds=timeout_seconds
            )
            base_test_passed = (base_test_out.status == "passed")

        # 3. Setup patched workspace
        patch_dir, patch_applied = setup_temporary_sandbox(case, patch.unified_diff)
        if not patch_applied:
            shutil.rmtree(base_dir, ignore_errors=True)
            shutil.rmtree(patch_dir, ignore_errors=True)
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return BaselineEvaluationOutcome(
                baseline_id=self.baseline_id,
                baseline_name=self.baseline_name,
                decision="FAILED",
                latency_ms=elapsed_ms,
                error_message="Patch application failed in isolated sandbox",
                evidence={"patch_applied": False}
            )

        # 4. Run patched scanners
        patch_findings, patch_meta, patch_errs = run_scanners_on_directory(
            patch_dir, scanner_names=["bandit"], timeout_seconds=timeout_seconds
        )

        # 5. Differential Finding Comparison with 6-status taxonomy
        changed_files = [f.new_path for f in parsed.files] if parsed else []
        target_rule = case.baseline_finding.get("rule_id")
        target_category = case.vulnerability_category
        target_file = case.source_file
        target_line = case.baseline_finding.get("start_line")

        comparison = compare_verification_findings(
            original_finding_rule=target_rule,
            original_finding_category=target_category,
            original_finding_file=target_file,
            original_finding_line=target_line,
            baseline_findings=base_findings,
            patched_findings=patch_findings,
            changed_files=changed_files,
            scanner_errors=patch_errs,
            baseline_errors=base_errs,
        )

        # 6. Run existing unit tests on patched workspace
        test_regression_detected = False
        existing_tests_passed = True
        existing_test_log = ""
        if case.existing_unit_test:
            unit_out = run_pytest_in_workspace(
                patch_dir, test_target="tests/test_existing.py", timeout_seconds=timeout_seconds
            )
            existing_tests_passed = (unit_out.status == "passed")
            existing_test_log = unit_out.error_message or unit_out.status
            if base_test_passed and unit_out.status == "failed":
                test_regression_detected = True

        # 7. Run targeted security exploit regression test
        has_targeted_test = bool(case.targeted_regression_test)
        targeted_test_passed = True
        targeted_test_log = ""
        if has_targeted_test:
            reg_file = patch_dir / "tests" / "test_security_regression.py"
            reg_file.parent.mkdir(parents=True, exist_ok=True)
            reg_file.write_text(case.targeted_regression_test, encoding="utf-8")
            reg_out = run_pytest_in_workspace(
                patch_dir, test_target="tests/test_security_regression.py", timeout_seconds=timeout_seconds
            )
            targeted_test_passed = (reg_out.status == "passed")
            targeted_test_log = reg_out.error_message or reg_out.status

        shutil.rmtree(base_dir, ignore_errors=True)
        shutil.rmtree(patch_dir, ignore_errors=True)
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # 8. Decision Logic
        all_errors = base_errs + patch_errs
        has_tool_fault = len(all_errors) > 0
        has_new_scanner_regressions = len(comparison.new_findings) > 0
        target_classification = comparison.original_finding_classification
        persists = (target_classification == FindingRegressionClassification.STILL_PRESENT)
        partial_fix = (target_classification == FindingRegressionClassification.POTENTIALLY_REGRESSED)

        failure_reasons: List[str] = []
        if persists:
            failure_reasons.append("Original finding still present in patched code")
        if partial_fix:
            failure_reasons.append("Vulnerability pattern shifted or related finding remains in modified file (partial fix)")
        if has_new_scanner_regressions:
            failure_reasons.append(f"Patch introduced {len(comparison.new_findings)} new security finding(s)")
        if test_regression_detected:
            failure_reasons.append("Functional test regression: Unit tests passed in baseline but failed after patch")
        elif not existing_tests_passed and case.existing_unit_test:
            failure_reasons.append("Existing unit test suite failed")
        if has_targeted_test and not targeted_test_passed:
            failure_reasons.append("Targeted security regression test failed: Vulnerability exploit still succeeds")

        missing_evidence: List[str] = []
        if not has_targeted_test:
            missing_evidence.append("Targeted security exploit regression test not configured")
        if not case.existing_unit_test:
            missing_evidence.append("Existing unit test suite not configured")

        if failure_reasons:
            decision = "FAILED"
            final_rationale = "; ".join(failure_reasons)
        elif has_tool_fault or (target_classification == FindingRegressionClassification.INCOMPARABLE and not (has_targeted_test and targeted_test_passed)):
            decision = "INCONCLUSIVE"
            if has_tool_fault:
                final_rationale = f"Tool failure or timeout during analysis: {'; '.join(all_errors)}"
            else:
                final_rationale = "Baseline vulnerability was not observed by configured scanners and no passing targeted test was available; resolution cannot be certified."
                missing_evidence.append("Baseline vulnerability reproduction absent in baseline SAST scan")
        elif target_classification == FindingRegressionClassification.RESOLVED_BY_DEFINED_CHECKS or (has_targeted_test and targeted_test_passed):
            if existing_tests_passed:
                decision = "VERIFIED"
                final_rationale = "Target finding resolved under defined checks with all tests passing."
                if not (has_targeted_test and targeted_test_passed):
                    missing_evidence.append(
                        "A disappearing scanner finding alone does not establish that the vulnerability is impossible; no exploit test confirmed runtime elimination."
                    )
            else:
                decision = "FAILED"
                final_rationale = "Existing unit tests failed."
        else:
            decision = "INCONCLUSIVE"
            final_rationale = "Insufficient evidence to certify fix."

        evidence_dict = {
            "target_classification": target_classification.value if hasattr(target_classification, "value") else str(target_classification),
            "new_findings_count": len(comparison.new_findings),
            "test_regression_detected": test_regression_detected,
            "existing_tests_passed": existing_tests_passed,
            "targeted_test_passed": targeted_test_passed,
            "missing_evidence": missing_evidence,
            "rationale": final_rationale,
            "classified_findings": [
                {
                    "rule_id": cf.rule_id,
                    "classification": cf.classification.value if hasattr(cf.classification, "value") else str(cf.classification),
                    "reason": cf.classification_reason
                }
                for cf in comparison.classified_findings
            ]
        }

        return BaselineEvaluationOutcome(
            baseline_id=self.baseline_id,
            baseline_name=self.baseline_name,
            decision=decision,
            latency_ms=elapsed_ms,
            error_message="; ".join(all_errors) if all_errors else None,
            evidence=evidence_dict
        )
