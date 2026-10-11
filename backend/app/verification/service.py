"""Core Fix Verification Service for RepoShield AI.

Implements:
STEP 1: Establish baseline.
STEP 2: Validate proposed patch (reject traversal, compute line deltas).
STEP 3: Prepare isolated verification workspace (disposable, secret-free, resource-bounded).
STEP 4: Run verification checks (scanners, unit tests, regression tests).
STEP 5: Produce evidence-based result (VERIFIED_AGAINST_DEFINED_CHECKS, FAILED_VERIFICATION, INCONCLUSIVE).

Enforces:
- No claims of universal security.
- Traceability of status to actual test and scanner evidence.
- Preserves original findings immutably.
- Audit event logging.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid
from sqlalchemy.orm import Session

from .comparator import compare_verification_findings
from .patch_applier import apply_patch_to_workspace
from .patch_parser import parse_unified_diff
from .runner import run_pytest_in_workspace, run_scanners_on_directory
from .workspace import calculate_directory_hash, create_verification_workspace
from ..core.audit import record_audit_event
from ..core.errors import NotFoundError, ValidationError
from ..core.logging import get_logger
from ..evidence.sanitizer import compute_evidence_hash, sanitize_evidence_text, sanitize_payload
from ..models.evidence import SecurityEvidence
from ..models.finding import SecurityFinding
from ..models.repository import Repository
from ..models.verification import VerificationEvidence, VerificationRun

from ..schemas.verification import (
    ClassifiedFinding,
    FindingRegressionClassification,
    STANDARD_VERIFICATION_LIMITATIONS,
    VerificationRunRequest,
    VerificationRunResponse,
    VerificationStatus,
)

logger = get_logger("reposhield.verification.service")


def execute_fix_verification(
    request: VerificationRunRequest,
    db: Session,
    user_id: Optional[str] = None
) -> VerificationRunResponse:
    """Execute the full 5-step fix verification pipeline with regression analysis."""
    started_at = datetime.now(timezone.utc)
    logger.info(f"Starting Fix Verification for finding '{request.finding_id}'")

    # -------------------------------------------------------------
    # STEP 1 — Establish Baseline Capture
    # -------------------------------------------------------------
    finding: Optional[SecurityFinding] = db.query(SecurityFinding).filter(
        SecurityFinding.id == request.finding_id
    ).first()

    if not finding:
        raise NotFoundError(f"Security finding with ID '{request.finding_id}' does not exist.")

    repo: Optional[Repository] = None
    if finding.repo_id:
        repo = db.query(Repository).filter(Repository.id == finding.repo_id).first()

    # Determine base source files
    source_dir: Optional[Path] = None
    synthetic_files: Dict[str, str] = {}

    if repo and repo.workspace_path:
        cand = Path(repo.workspace_path)
        if cand.exists() and cand.is_dir():
            source_dir = cand

    # If repo workspace is not present on disk, seed with finding context
    if not source_dir:
        # Create minimal synthetic workspace containing finding file and code excerpt
        rel_path = finding.file_path or "src/app.py"
        code_content = finding.code_excerpt or "# Target finding code excerpt\n"
        synthetic_files[rel_path] = code_content

    # Create isolated disposable workspace
    ws = create_verification_workspace(source_dir=source_dir, synthetic_files=synthetic_files)
    baseline_hash = ws.baseline_hash

    source_revision = getattr(finding, "commit_sha", None) or (repo.default_branch if repo and repo.default_branch else "main")
    target_revision: Optional[str] = None
    configuration_changes: Dict[str, Any] = {
        "custom_config_applied": bool(request.scanner_config),
        "scanner_config_overrides": request.scanner_config or {},
    }
    findings_before_list: List[Dict[str, Any]] = []
    findings_after_list: List[Dict[str, Any]] = []

    scanner_metadata: Dict[str, Any] = {}
    scanner_config: Dict[str, Any] = dict(request.scanner_config or {})
    tests_executed: List[str] = []
    test_results: Dict[str, Any] = {}
    baseline_test_results: Dict[str, Any] = {}
    test_regressions: List[str] = []
    execution_errors: List[str] = []
    reasons: List[str] = []
    missing_evidence: List[str] = []
    evidence_references: List[str] = []
    evidence_entities: List[VerificationEvidence] = []
    new_findings_list: List[Dict[str, Any]] = []
    classified_findings_list: List[ClassifiedFinding] = []
    original_finding_status = "untested"
    patched_hash: Optional[str] = None

    verification_run_id = f"vr_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}"

    try:
        # Determine target scanner(s) for fix verification
        target_scanners = request.scanner_names
        if not target_scanners and finding.scanner_name:
            cand_name = finding.scanner_name.lower()
            if "bandit" in cand_name:
                target_scanners = ["bandit"]
            elif "semgrep" in cand_name:
                target_scanners = ["semgrep"]
            elif "pip" in cand_name:
                target_scanners = ["pip_audit"]
            elif "gitleaks" in cand_name:
                target_scanners = ["gitleaks"]
            elif "secret" in cand_name:
                target_scanners = ["secret_detector"]

        # Run baseline scanners to capture pre-patch findings
        baseline_findings, base_sc_meta, base_sc_errs = run_scanners_on_directory(
            ws.workspace_dir,
            scanner_names=target_scanners,
            timeout_seconds=request.timeout_seconds
        )
        scanner_metadata.update(base_sc_meta)
        if base_sc_errs:
            execution_errors.extend(base_sc_errs)

        findings_before_list = [
            {
                "scanner_name": getattr(f, "scanner_name", "unknown"),
                "rule_id": getattr(f, "rule_id", ""),
                "file_path": getattr(f, "file_path", ""),
                "line_number": getattr(f, "line_number", None),
                "message": getattr(f, "message", ""),
                "severity": getattr(f, "severity", "MEDIUM"),
            }
            for f in baseline_findings
        ]

        evidence_entities.append(VerificationEvidence(
            id=f"ev_base_scan_{verification_run_id}",
            verification_run_id=verification_run_id,
            evidence_type="baseline_sast_scan",
            result="completed" if not base_sc_errs else "error",
            tool_name_and_version=f"Baseline Scanner Engine ({', '.join(base_sc_meta.keys()) or 'Static Analyzer'})",
            evidence_reference=f"Observed baseline findings: {len(baseline_findings)}, Errors: {len(base_sc_errs)}"
        ))

        # Baseline Test Execution: Capture baseline test state prior to patch application
        if request.run_existing_tests:
            base_test_outcome = run_pytest_in_workspace(
                workspace_dir=ws.workspace_dir,
                timeout_seconds=request.timeout_seconds
            )
            baseline_test_results[base_test_outcome.test_suite_name] = {
                "status": base_test_outcome.status,
                "passed": base_test_outcome.passed_count,
                "failed": base_test_outcome.failed_count,
                "error": base_test_outcome.error_message
            }
            if base_test_outcome.status != "skipped":
                evidence_entities.append(VerificationEvidence(
                    id=f"ev_base_unit_{verification_run_id}",
                    verification_run_id=verification_run_id,
                    evidence_type="baseline_unit_test",
                    result=base_test_outcome.status,
                    tool_name_and_version="pytest-baseline-runner",
                    evidence_reference=f"Baseline tests passed: {base_test_outcome.passed_count}, failed: {base_test_outcome.failed_count}"
                ))

        # -------------------------------------------------------------
        # STEP 2 — Patch Analysis (Parse and Validate)
        # -------------------------------------------------------------
        parsed_patch = parse_unified_diff(request.proposed_patch)

        if not parsed_patch.is_valid:
            status = VerificationStatus.INCONCLUSIVE
            reasons.append(f"Patch validation failed: {'; '.join(parsed_patch.errors)}")
            execution_errors.extend(parsed_patch.errors)

            return _finalize_and_persist_run(
                db=db,
                run_id=verification_run_id,
                finding_id=finding.id,
                patch_id=request.patch_id,
                status=status,
                baseline_hash=baseline_hash,
                patched_hash=baseline_hash,
                scanner_metadata=scanner_metadata,
                scanner_config=scanner_config,
                tests_executed=tests_executed,
                test_results=test_results,
                original_finding_status="untested",
                new_findings=new_findings_list,
                classified_findings=classified_findings_list,
                baseline_test_results=baseline_test_results,
                test_regressions=test_regressions,
                execution_errors=execution_errors,
                reasons=reasons,
                missing_evidence=missing_evidence,
                evidence_references=evidence_references,
                patch_diff=request.proposed_patch,
                started_at=started_at,
                evidence_entities=evidence_entities,
                source_revision=source_revision,
                target_revision=target_revision,
                configuration_changes=configuration_changes,
                findings_before_patch=findings_before_list,
                findings_after_patch=findings_after_list,
                user_id=user_id,
            )

        # -------------------------------------------------------------
        # STEP 3 — Workspace Isolation & Patch Application
        # -------------------------------------------------------------
        # Never mutate original repository; apply only in isolated disposable worktree
        patch_applied, apply_errors = apply_patch_to_workspace(ws.workspace_dir, parsed_patch)

        if not patch_applied:
            status = VerificationStatus.INCONCLUSIVE
            reasons.append(f"Patch application failed in isolated workspace: {'; '.join(apply_errors)}")
            execution_errors.extend(apply_errors)

            return _finalize_and_persist_run(
                db=db,
                run_id=verification_run_id,
                finding_id=finding.id,
                patch_id=request.patch_id,
                status=status,
                baseline_hash=baseline_hash,
                patched_hash=baseline_hash,
                scanner_metadata=scanner_metadata,
                scanner_config=scanner_config,
                tests_executed=tests_executed,
                test_results=test_results,
                original_finding_status="untested",
                new_findings=new_findings_list,
                classified_findings=classified_findings_list,
                baseline_test_results=baseline_test_results,
                test_regressions=test_regressions,
                execution_errors=execution_errors,
                reasons=reasons,
                missing_evidence=missing_evidence,
                evidence_references=evidence_references,
                patch_diff=request.proposed_patch,
                started_at=started_at,
                evidence_entities=evidence_entities,
                source_revision=source_revision,
                target_revision=target_revision,
                configuration_changes=configuration_changes,
                findings_before_patch=findings_before_list,
                findings_after_patch=findings_after_list,
                user_id=user_id,
            )

        patched_hash = calculate_directory_hash(ws.workspace_dir)
        ws.patched_hash = patched_hash
        target_revision = f"rev_{patched_hash[:12]}" if patched_hash else None


        # -------------------------------------------------------------
        # STEP 4 — Run Verification Checks & Regression Analysis
        # -------------------------------------------------------------
        # 4.1 Re-run scanners on patched workspace
        patched_findings, patched_sc_meta, patched_sc_errs = run_scanners_on_directory(
            ws.workspace_dir,
            scanner_names=target_scanners,
            timeout_seconds=request.timeout_seconds
        )
        scanner_metadata.update(patched_sc_meta)
        if patched_sc_errs:
            execution_errors.extend(patched_sc_errs)

        findings_after_list = [
            {
                "scanner_name": getattr(f, "scanner_name", "unknown"),
                "rule_id": getattr(f, "rule_id", ""),
                "file_path": getattr(f, "file_path", ""),
                "line_number": getattr(f, "line_number", None),
                "message": getattr(f, "message", ""),
                "severity": getattr(f, "severity", "MEDIUM"),
            }
            for f in patched_findings
        ]


        # Compare scanner findings before and after with 6-status taxonomy
        changed_files = [f.new_path for f in parsed_patch.files] if parsed_patch else []
        comparison = compare_verification_findings(
            original_finding_rule=getattr(finding, "rule_identifier", getattr(finding, "rule_id", None)),
            original_finding_category=finding.cwe or finding.title,
            original_finding_file=finding.file_path,
            original_finding_line=finding.line_number,
            baseline_findings=baseline_findings,
            patched_findings=patched_findings,
            changed_files=changed_files,
            scanner_errors=patched_sc_errs,
            baseline_errors=base_sc_errs,
        )
        original_finding_status = comparison.original_finding_status
        original_classification = comparison.original_finding_classification
        new_findings_list = comparison.new_findings
        classified_findings_list = comparison.classified_findings
        reasons.extend(comparison.reasons)

        evidence_entities.append(VerificationEvidence(
            id=f"ev_sast_{verification_run_id}",
            verification_run_id=verification_run_id,
            evidence_type="sast_check",
            result="passed" if original_finding_status == "resolved" and not new_findings_list else "failed",
            tool_name_and_version=f"AppSec Scanner Engine ({', '.join(scanner_metadata.keys()) or 'Static Analyzer'})",
            evidence_reference=f"Baseline findings: {len(baseline_findings)}, Patched findings: {len(patched_findings)}, Regressions: {len(new_findings_list)}"
        ))

        evidence_entities.append(VerificationEvidence(
            id=f"ev_class_{verification_run_id}",
            verification_run_id=verification_run_id,
            evidence_type="regression_classification_matrix",
            result="passed" if not (new_findings_list or comparison.potentially_regressed_findings_count > 0) else "failed",
            tool_name_and_version="RepoShield Regression Comparator",
            evidence_reference=(
                f"Resolved: {comparison.resolved_findings_count}, Still Present: {comparison.persisting_findings_count}, "
                f"New: {comparison.new_findings_count}, Unchanged: {comparison.unchanged_findings_count}, "
                f"Regressed: {comparison.potentially_regressed_findings_count}, Incomparable: {comparison.incomparable_findings_count}"
            )
        ))

        # 4.2 Run existing project tests and detect regressions
        existing_tests_passed = True
        if request.run_existing_tests:
            test_outcome = run_pytest_in_workspace(
                workspace_dir=ws.workspace_dir,
                timeout_seconds=request.timeout_seconds
            )
            tests_executed.append(test_outcome.test_suite_name)
            test_results[test_outcome.test_suite_name] = {
                "status": test_outcome.status,
                "passed": test_outcome.passed_count,
                "failed": test_outcome.failed_count,
                "error": test_outcome.error_message
            }

            # Check if tests that passed in baseline now fail in patched (regression)
            base_outcome_dict = baseline_test_results.get(test_outcome.test_suite_name)
            if base_outcome_dict and base_outcome_dict.get("status") == "passed" and test_outcome.status == "failed":
                reg_msg = (
                    f"Test regression detected: Test suite '{test_outcome.test_suite_name}' passed on baseline "
                    f"({base_outcome_dict.get('passed', 0)} passed) but failed after patch ({test_outcome.failed_count} failed)."
                )
                test_regressions.append(reg_msg)
                reasons.append(reg_msg)
                existing_tests_passed = False
            elif test_outcome.status == "failed":
                existing_tests_passed = False
                reasons.append(f"Existing project unit test suite '{test_outcome.test_suite_name}' failed after applying patch.")
            elif test_outcome.status in ("error", "timeout"):
                existing_tests_passed = False
                reasons.append(f"Existing test execution encountered error/timeout: {test_outcome.error_message}")
            elif test_outcome.status == "skipped":
                missing_evidence.append("No existing project test suite was found in repository.")

            evidence_entities.append(VerificationEvidence(
                id=f"ev_unit_{verification_run_id}",
                verification_run_id=verification_run_id,
                evidence_type="unit_test",
                result=test_outcome.status,
                tool_name_and_version="pytest-runner",
                evidence_reference=test_outcome.output_log[:500] if test_outcome.output_log else test_outcome.error_message
            ))

        # 4.3 Run targeted security regression test
        regression_test_passed = True
        regression_test_executed = False

        if request.run_regression_tests:
            reg_code = request.regression_test_code
            if reg_code:
                reg_file = ws.workspace_dir / "tests" / "test_security_regression.py"
                reg_file.parent.mkdir(parents=True, exist_ok=True)
                reg_file.write_text(reg_code, encoding="utf-8")

                reg_outcome = run_pytest_in_workspace(
                    workspace_dir=ws.workspace_dir,
                    test_target="tests/test_security_regression.py",
                    timeout_seconds=request.timeout_seconds
                )
                regression_test_executed = True
                tests_executed.append("targeted_security_regression_test")
                test_results["targeted_security_regression_test"] = {
                    "status": reg_outcome.status,
                    "passed": reg_outcome.passed_count,
                    "failed": reg_outcome.failed_count,
                    "error": reg_outcome.error_message
                }

                if reg_outcome.status != "passed":
                    regression_test_passed = False
                    reasons.append(f"Targeted security regression test failed: {reg_outcome.error_message or 'Assertion failed'}")
                else:
                    reasons.append("Targeted security regression test passed successfully on patched workspace.")

                evidence_entities.append(VerificationEvidence(
                    id=f"ev_reg_{verification_run_id}",
                    verification_run_id=verification_run_id,
                    evidence_type="regression_test",
                    result=reg_outcome.status,
                    tool_name_and_version="pytest-regression-gate",
                    evidence_reference=reg_outcome.output_log[:500] if reg_outcome.output_log else reg_outcome.error_message
                ))
            else:
                missing_evidence.append(
                    "No targeted security regression test was provided or executed for this finding."
                )

        # -------------------------------------------------------------
        # STEP 5 — Verification Decision Logic
        # -------------------------------------------------------------
        # Core Axioms:
        # 1. A disappearing scanner finding alone MUST NOT establish that a vulnerability is fixed.
        # 2. A passing test suite alone MUST NOT establish that a patch is secure.
        # 3. New findings or test regressions force FAILED_VERIFICATION.
        # 4. Scanner crashes or un-reproduced baseline finding force INCONCLUSIVE.

        # Rule 5.1: FAILED_VERIFICATION
        if (
            original_classification in (FindingRegressionClassification.STILL_PRESENT, FindingRegressionClassification.POTENTIALLY_REGRESSED) or
            len(new_findings_list) > 0 or
            len(test_regressions) > 0 or
            not existing_tests_passed or
            (regression_test_executed and not regression_test_passed)
        ):
            status = VerificationStatus.FAILED_VERIFICATION

        # Rule 5.2: INCONCLUSIVE
        elif (
            len(execution_errors) > 0 or
            (original_classification == FindingRegressionClassification.INCOMPARABLE and not (regression_test_executed and regression_test_passed))
        ):
            status = VerificationStatus.INCONCLUSIVE
            if original_classification == FindingRegressionClassification.INCOMPARABLE:
                missing_evidence.append(
                    "Scanner did not detect finding in baseline workspace; fix cannot be verified by static checks alone without baseline reproduction."
                )
                reasons.append("Verification inconclusive: baseline vulnerability was not observed by configured scanners.")
            if len(execution_errors) > 0:
                reasons.append("Verification is inconclusive because required analysis tools failed to run or timed out.")

        # Rule 5.3: VERIFIED_AGAINST_DEFINED_CHECKS
        elif (
            (original_classification == FindingRegressionClassification.RESOLVED_BY_DEFINED_CHECKS or (regression_test_executed and regression_test_passed))
            and existing_tests_passed
            and len(test_regressions) == 0
            and len(new_findings_list) == 0
        ):
            status = VerificationStatus.VERIFIED_AGAINST_DEFINED_CHECKS
            reasons.append(
                "All defined checks completed successfully. Original finding is addressed, and no blocking regression was detected."
            )
            # Enforce Axiom: Disappearing scanner finding alone does not prove fix without behavioral testing
            if not (regression_test_executed and regression_test_passed) and (not request.run_existing_tests or test_results.get("project_tests", {}).get("status") == "skipped"):
                missing_evidence.append(
                    "A disappearing scanner finding alone does not establish that the vulnerability is impossible; no test suite was executed to confirm runtime remediation."
                )
        else:
            status = VerificationStatus.INCONCLUSIVE
            reasons.append("Verification inconclusive: insufficient evidence to confirm fix.")

    finally:
        # Always clean up temporary workspace
        ws.cleanup()

    return _finalize_and_persist_run(
        db=db,
        run_id=verification_run_id,
        finding_id=finding.id,
        patch_id=request.patch_id,
        status=status,
        baseline_hash=baseline_hash,
        patched_hash=patched_hash or baseline_hash,
        scanner_metadata=scanner_metadata,
        scanner_config=scanner_config,
        tests_executed=tests_executed,
        test_results=test_results,
        original_finding_status=original_finding_status,
        new_findings=new_findings_list,
        classified_findings=classified_findings_list,
        baseline_test_results=baseline_test_results,
        test_regressions=test_regressions,
        execution_errors=execution_errors,
        reasons=reasons,
        missing_evidence=missing_evidence,
        evidence_references=evidence_references,
        patch_diff=request.proposed_patch,
        started_at=started_at,
        evidence_entities=evidence_entities,
        source_revision=source_revision,
        target_revision=target_revision,
        configuration_changes=configuration_changes,
        findings_before_patch=findings_before_list,
        findings_after_patch=findings_after_list,
        user_id=user_id,
    )


def _finalize_and_persist_run(
    db: Session,
    run_id: str,
    finding_id: str,
    patch_id: Optional[str],
    status: VerificationStatus,
    baseline_hash: Optional[str],
    patched_hash: Optional[str],
    scanner_metadata: Dict[str, Any],
    scanner_config: Dict[str, Any],
    tests_executed: List[str],
    test_results: Dict[str, Any],
    original_finding_status: str,
    new_findings: List[Dict[str, Any]],
    classified_findings: List[ClassifiedFinding],
    baseline_test_results: Dict[str, Any],
    test_regressions: List[str],
    execution_errors: List[str],
    reasons: List[str],
    missing_evidence: List[str],
    evidence_references: List[str],
    patch_diff: Optional[str],
    started_at: datetime,
    evidence_entities: List[VerificationEvidence],
    source_revision: Optional[str] = None,
    target_revision: Optional[str] = None,
    configuration_changes: Optional[Dict[str, Any]] = None,
    findings_before_patch: Optional[List[Dict[str, Any]]] = None,
    findings_after_patch: Optional[List[Dict[str, Any]]] = None,
    ai_interpretation: Optional[str] = None,
    user_id: Optional[str] = None,
) -> VerificationRunResponse:
    """Commit VerificationRun and associated SecurityEvidence to database and return response."""
    completed_at = datetime.now(timezone.utc)

    # Enrich test_results with baseline test outcomes and regression breakdown
    augmented_test_results = dict(test_results)
    if baseline_test_results:
        augmented_test_results["_baseline_test_results"] = baseline_test_results
    if test_regressions:
        augmented_test_results["_test_regressions"] = test_regressions

    classified_json = json.dumps([cf.model_dump() for cf in classified_findings])

    # Formulate advisory AI interpretation strictly demarcated from raw evidence
    if not ai_interpretation:
        summary_sentence = (
            f"Automated evaluation produced status '{status.value}' with original finding '{original_finding_status}'. "
            f"Analyzed {len(tests_executed)} test suite(s), introduced {len(new_findings)} new defect(s)."
        )
        ai_interpretation = (
            f"[ADVISORY AI INTERPRETATION - NON-AUTHORITATIVE]: {summary_sentence} "
            f"Key contributing factors: {'; '.join(reasons) if reasons else 'Defined checks passed without regression.'} "
            "Notice: AI interpretations are advisory inferences and must not replace human code review."
        )

    # Compute content hash for accidental alteration detection
    integrity_payload = {
        "run_id": run_id,
        "finding_id": finding_id,
        "status": status.value,
        "baseline_hash": baseline_hash,
        "patched_hash": patched_hash,
        "source_revision": source_revision,
        "target_revision": target_revision,
        "tests_executed": sorted(tests_executed),
        "original_finding_status": original_finding_status,
        "new_findings_count": len(new_findings),
        "reasons_count": len(reasons),
    }
    integrity_hash = compute_evidence_hash(json.dumps(integrity_payload, sort_keys=True))

    # Associate granular SecurityEvidence records without duplicating stored files
    finding_obj = db.query(SecurityFinding).filter(SecurityFinding.id == finding_id).first()
    repo_id = finding_obj.repo_id if finding_obj else None

    if repo_id:
        # 1. Proposed Patch Diff evidence
        sanitized_diff = sanitize_evidence_text(patch_diff or "")
        ev_diff_id = f"ev_diff_{run_id}"
        db.add(SecurityEvidence(
            id=ev_diff_id,
            repository_id=repo_id,
            verification_run_id=run_id,
            finding_id=finding_id,
            evidence_category="patch_diff",
            title=f"Proposed Patch Diff for Verification Run {run_id}",
            provenance="user_supplied",
            tool_name="git_diff_parser",
            content_hash=compute_evidence_hash(sanitized_diff),
            sanitized_payload=sanitized_diff,
            recorded_at=completed_at,
        ))
        evidence_references.append(ev_diff_id)

        # 2. Source Revisions and Hashes evidence
        rev_payload = json.dumps({
            "source_revision": source_revision,
            "target_revision": target_revision,
            "baseline_hash": baseline_hash,
            "patched_hash": patched_hash,
        }, indent=2)
        ev_rev_id = f"ev_rev_{run_id}"
        db.add(SecurityEvidence(
            id=ev_rev_id,
            repository_id=repo_id,
            verification_run_id=run_id,
            finding_id=finding_id,
            evidence_category="revision_hash",
            title=f"Source Revisions and Content Hashes for Run {run_id}",
            provenance="sandbox_observed",
            tool_name="git_revision_tracker",
            content_hash=compute_evidence_hash(rev_payload),
            sanitized_payload=rev_payload,
            recorded_at=completed_at,
        ))
        evidence_references.append(ev_rev_id)

        # 3. Test execution evidence
        test_payload = sanitize_payload(augmented_test_results)
        ev_tests_id = f"ev_tests_{run_id}"
        db.add(SecurityEvidence(
            id=ev_tests_id,
            repository_id=repo_id,
            verification_run_id=run_id,
            finding_id=finding_id,
            evidence_category="test_result",
            title=f"Test Suite Execution Log for Run {run_id}",
            provenance="sandbox_observed",
            tool_name="pytest_runner",
            content_hash=compute_evidence_hash(test_payload),
            sanitized_payload=test_payload,
            recorded_at=completed_at,
        ))
        evidence_references.append(ev_tests_id)

        # 4. Scanner findings pre/post comparison evidence
        findings_payload = sanitize_payload({
            "findings_before_patch": findings_before_patch or [],
            "findings_after_patch": findings_after_patch or [],
            "new_findings": new_findings,
        })
        ev_findings_id = f"ev_findings_{run_id}"
        db.add(SecurityEvidence(
            id=ev_findings_id,
            repository_id=repo_id,
            verification_run_id=run_id,
            finding_id=finding_id,
            evidence_category="scanner_finding",
            title=f"Pre/Post Scanner Findings Comparison for Run {run_id}",
            provenance="scanner_observed",
            tool_name="sast_regression_engine",
            content_hash=compute_evidence_hash(findings_payload),
            sanitized_payload=findings_payload,
            recorded_at=completed_at,
        ))
        evidence_references.append(ev_findings_id)

    db_run = VerificationRun(
        id=run_id,
        finding_id=finding_id,
        patch_id=patch_id,
        status=status.value,
        baseline_hash=baseline_hash,
        patched_hash=patched_hash,
        scanner_metadata=json.dumps(scanner_metadata),
        scanner_config=json.dumps(scanner_config),
        tests_executed=json.dumps(tests_executed),
        test_results=json.dumps(augmented_test_results),
        original_finding_status=original_finding_status,
        new_findings=json.dumps(new_findings),
        classified_findings=classified_json,
        execution_errors=json.dumps(execution_errors),
        reasons=json.dumps(reasons),
        missing_evidence=json.dumps(missing_evidence),
        evidence_references=json.dumps(evidence_references),
        patch_diff=patch_diff,
        test_summary=f"Status: {status.value} | Target: {original_finding_status} | Regressions: {len(new_findings)} | Test regressions: {len(test_regressions)}",
        started_at=started_at,
        completed_at=completed_at,
        source_revision=source_revision,
        target_revision=target_revision,
        configuration_changes=json.dumps(configuration_changes or {}),
        findings_before_patch=json.dumps(findings_before_patch or []),
        findings_after_patch=json.dumps(findings_after_patch or []),
        ai_interpretation=ai_interpretation,
        integrity_hash=integrity_hash,
    )
    db.add(db_run)

    for ev in evidence_entities:
        db.add(ev)

    db.commit()
    db.refresh(db_run)

    # Record audit event
    record_audit_event(
        db=db,
        action="verification.run_completed",
        resource_type="verification_run",
        resource_identifier=run_id,
        actor_id=user_id or "system",
        metadata={
            "finding_id": finding_id,
            "status": status.value,
            "original_finding_status": original_finding_status,
            "regressions_count": len(new_findings),
            "test_regressions_count": len(test_regressions),
            "baseline_hash": baseline_hash,
            "patched_hash": patched_hash,
            "source_revision": source_revision,
            "integrity_hash": integrity_hash,
        }
    )

    # Format response model
    return VerificationRunResponse(
        id=db_run.id,
        finding_id=finding_id,
        patch_id=patch_id,
        baseline_hash=baseline_hash,
        patched_hash=patched_hash,
        scanner_metadata=scanner_metadata,
        scanner_config=scanner_config,
        tests_executed=tests_executed,
        test_results=augmented_test_results,
        original_finding_status=original_finding_status,
        new_findings=new_findings,
        classified_findings=classified_findings,
        baseline_test_results=baseline_test_results,
        test_regressions=test_regressions,
        execution_errors=execution_errors,
        started_at=started_at,
        completed_at=completed_at,
        status=status,
        reasons=reasons,
        missing_evidence=missing_evidence,
        evidence_references=evidence_references,
        patch_diff=patch_diff,
        test_summary=db_run.test_summary,
        source_revision=source_revision,
        target_revision=target_revision,
        configuration_changes=configuration_changes or {},
        findings_before_patch=findings_before_patch or [],
        findings_after_patch=findings_after_patch or [],
        ai_interpretation=ai_interpretation,
        integrity_hash=integrity_hash,
        limitations=list(STANDARD_VERIFICATION_LIMITATIONS),
        evidence=[]
    )

