"""Comprehensive End-to-End Validation Suite for Security-Fix Verification Workflow.

Validates all 10 core verification scenarios using controlled synthetic local fixtures:
1. Known vulnerability with an effective fix.
2. Known vulnerability with an ineffective fix.
3. Partially corrected vulnerability.
4. Finding that disappears because scanner configuration changed rather than code fixed.
5. Fix that introduces a security regression.
6. Fix that breaks expected application behavior (functional regression).
7. Scanner that is unavailable / not installed.
8. Scanner timeout or execution error.
9. Patch that touches an unrelated code path without fixing original flaw.
10. Insufficient evidence to determine whether fix works (epistemic modesty).
"""
from pathlib import Path
from typing import Tuple
from unittest.mock import patch
import pytest
from sqlalchemy.orm import Session

from app.models.evidence import SecurityEvidence
from app.models.finding import SecurityFinding
from app.models.repository import Repository
from app.models.user import User
from app.scanner.base import ScanJobResult, ScannerStatus
from app.scanner.bandit import BanditScannerAdapter
from app.schemas.verification import (
    FindingRegressionClassification,
    VerificationRunRequest,
    VerificationRunResponse,
    VerificationStatus,
)
from app.verification.service import execute_fix_verification
from tests.fixtures.security_verification.scenarios import (
    VERIFICATION_SCENARIOS,
    VerificationScenarioFixture,
)


def _setup_scenario_workspace(
    scenario: VerificationScenarioFixture,
    tmp_path: Path,
    db: Session,
    user: User,
) -> Tuple[Repository, SecurityFinding, VerificationRunRequest]:
    """Helper to stage isolated local repository workspace and persist initial finding."""
    # 1. Create clean isolated workspace on disk
    repo_root = tmp_path / scenario.scenario_id / "source"
    repo_root.mkdir(parents=True, exist_ok=True)

    # Write vulnerable source file
    vuln_file = repo_root / scenario.vulnerable_file_path
    vuln_file.parent.mkdir(parents=True, exist_ok=True)
    vuln_file.write_text(scenario.vulnerable_source_code, encoding="utf-8")

    # Write existing unit test file
    test_file = repo_root / scenario.existing_unit_test_path
    test_file.parent.mkdir(parents=True, exist_ok=True)
    test_file.write_text(scenario.existing_unit_test_code, encoding="utf-8")

    # 2. Persist Repository record
    repo = Repository(
        owner_id=user.id,
        name=f"repo-{scenario.scenario_id.lower()}",
        source_type="synthetic_fixture",
        workspace_path=str(repo_root.resolve()),
        default_branch="main",
        ingestion_status="completed",
        is_active=True,
    )
    db.add(repo)
    db.commit()
    db.refresh(repo)

    # 3. Persist original SecurityFinding record
    finding = SecurityFinding(
        repo_id=repo.id,
        scanner_identifier=scenario.scanner_name,
        scanner_name=scenario.scanner_name,
        rule_identifier=scenario.scanner_rule_id,
        cwe=scenario.cwe,
        title=scenario.name,
        category=scenario.cwe,
        severity="HIGH",
        confidence="HIGH",
        confidence_score=0.95,
        file_path=scenario.vulnerable_file_path,
        line_number=5,
        code_excerpt=scenario.vulnerable_source_code,
        status="open",
        finding_status="open",
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    # 4. Construct VerificationRunRequest
    req = VerificationRunRequest(
        finding_id=finding.id,
        proposed_patch=scenario.candidate_patch,
        scanner_names=scenario.scanner_names,
        scanner_config=scenario.scanner_config,
        run_existing_tests=scenario.run_existing_tests,
        run_regression_tests=scenario.run_regression_tests,
        regression_test_code=scenario.targeted_security_test_code,
        timeout_seconds=30,
    )

    return repo, finding, req


# =============================================================================
# SCENARIO 1: Known Vulnerability with an Effective Fix
# =============================================================================
def test_scenario_01_effective_fix(tmp_path: Path, db_session: Session, user_a: User):
    """Scenario 1: Verified fix resolves original finding and passes all tests without regression."""
    scenario = VERIFICATION_SCENARIOS["SCENARIO_01_EFFECTIVE_FIX"]
    repo, finding, req = _setup_scenario_workspace(scenario, tmp_path, db_session, user_a)

    result: VerificationRunResponse = execute_fix_verification(req, db=db_session, user_id=user_a.id)

    # 1. Assert overall verification status
    assert result.status == VerificationStatus.VERIFIED_AGAINST_DEFINED_CHECKS
    assert result.original_finding_status == "resolved"

    # 2. Assert regression classification
    target_class = next((cf for cf in result.classified_findings if cf.is_target_finding), None)
    assert target_class is not None
    assert target_class.classification == FindingRegressionClassification.RESOLVED_BY_DEFINED_CHECKS

    # 3. Assert zero security regressions and zero test regressions
    assert len(result.new_findings) == 0
    assert len(result.test_regressions) == 0

    # 4. Assert tests executed
    assert len(result.tests_executed) >= 2  # existing project test + targeted exploit test
    assert any("targeted" in t.lower() or "regression" in t.lower() or "neutralized" in t.lower() for t in result.tests_executed)

    # 5. Assert cryptographic evidence preservation
    assert result.baseline_hash is not None and len(result.baseline_hash) == 64
    assert result.patched_hash is not None and len(result.patched_hash) == 64
    assert result.baseline_hash != result.patched_hash
    assert len(result.evidence_references) >= 3
    persisted_evidence = db_session.query(SecurityEvidence).filter(SecurityEvidence.verification_run_id == result.id).all()
    assert len(persisted_evidence) >= 3
    assert any(e.evidence_category == "patch_diff" for e in persisted_evidence)
    assert any(e.evidence_category == "revision_hash" for e in persisted_evidence)
    assert any(e.evidence_category == "test_result" for e in persisted_evidence)


# =============================================================================
# SCENARIO 2: Known Vulnerability with an Ineffective Fix
# =============================================================================
def test_scenario_02_ineffective_fix(tmp_path: Path, db_session: Session, user_a: User):
    """Scenario 2: Ineffective fix (whitespace stripping) fails verification as finding persists."""
    scenario = VERIFICATION_SCENARIOS["SCENARIO_02_INEFFECTIVE_FIX"]
    repo, finding, req = _setup_scenario_workspace(scenario, tmp_path, db_session, user_a)

    result: VerificationRunResponse = execute_fix_verification(req, db=db_session, user_id=user_a.id)

    assert result.status == VerificationStatus.FAILED_VERIFICATION
    assert result.original_finding_status in ("persisting", "modified")

    target_class = next((cf for cf in result.classified_findings if cf.is_target_finding), None)
    assert target_class is not None
    assert target_class.classification in (
        FindingRegressionClassification.STILL_PRESENT,
        FindingRegressionClassification.POTENTIALLY_REGRESSED,
    )

    # Invariant: Must NOT be certified
    assert result.status != VerificationStatus.VERIFIED_AGAINST_DEFINED_CHECKS
    assert any(
        "still" in r.lower() or "regressed" in r.lower() or "without full resolution" in r.lower() or "persisting" in r.lower()
        for r in result.reasons
    )


# =============================================================================
# SCENARIO 3: Partially Corrected Vulnerability
# =============================================================================
def test_scenario_03_partially_corrected_vulnerability(tmp_path: Path, db_session: Session, user_a: User):
    """Scenario 3: Partially fixed vulnerability (multi-parameter) fails verification."""
    scenario = VERIFICATION_SCENARIOS["SCENARIO_03_PARTIAL_FIX"]
    repo, finding, req = _setup_scenario_workspace(scenario, tmp_path, db_session, user_a)

    result: VerificationRunResponse = execute_fix_verification(req, db=db_session, user_id=user_a.id)

    assert result.status == VerificationStatus.FAILED_VERIFICATION
    assert result.original_finding_status in ("persisting", "modified")

    # Invariant: Must NEVER claim verified when sink is partially open
    assert result.status != VerificationStatus.VERIFIED_AGAINST_DEFINED_CHECKS


# =============================================================================
# SCENARIO 4: Finding Disappears Due to Scanner Config Override (Evasion)
# =============================================================================
def test_scenario_04_scanner_configuration_change_evasion(tmp_path: Path, db_session: Session, user_a: User):
    """Scenario 4: Finding absent because scanner rule was skipped evaluates to INCONCLUSIVE."""
    scenario = VERIFICATION_SCENARIOS["SCENARIO_04_SCANNER_CONFIG_EVASION"]
    repo, finding, req = _setup_scenario_workspace(scenario, tmp_path, db_session, user_a)

    result: VerificationRunResponse = execute_fix_verification(req, db=db_session, user_id=user_a.id)

    # Invariant: Configuration change evasion must yield INCONCLUSIVE, not VERIFIED
    assert result.status == VerificationStatus.INCONCLUSIVE
    assert result.original_finding_status == "untested"

    target_class = next((cf for cf in result.classified_findings if cf.is_target_finding), None)
    assert target_class is not None
    assert target_class.classification == FindingRegressionClassification.INCOMPARABLE

    # Explicit missing evidence recorded
    assert any("baseline" in ev.lower() for ev in result.missing_evidence)
    assert any("baseline" in r.lower() for r in result.reasons)


# =============================================================================
# SCENARIO 5: Fix Introduces a Security Regression
# =============================================================================
def test_scenario_05_fix_introduces_security_regression(tmp_path: Path, db_session: Session, user_a: User):
    """Scenario 5: Patch resolves SQL injection but introduces command injection -> FAILED."""
    scenario = VERIFICATION_SCENARIOS["SCENARIO_05_SECURITY_REGRESSION"]
    repo, finding, req = _setup_scenario_workspace(scenario, tmp_path, db_session, user_a)

    result: VerificationRunResponse = execute_fix_verification(req, db=db_session, user_id=user_a.id)

    assert result.status == VerificationStatus.FAILED_VERIFICATION
    assert len(result.new_findings) >= 1

    # Check that new finding was classified as NEW
    new_class = next((cf for cf in result.classified_findings if cf.classification == FindingRegressionClassification.NEW), None)
    assert new_class is not None

    # Invariant: New finding blocks fix certification
    assert any("regression" in r.lower() or "new security finding" in r.lower() for r in result.reasons)


# =============================================================================
# SCENARIO 6: Fix Breaks Expected Application Behavior (Functional Regression)
# =============================================================================
def test_scenario_06_fix_breaks_application_behavior(tmp_path: Path, db_session: Session, user_a: User):
    """Scenario 6: Security fix breaks existing unit test suite -> FAILED_VERIFICATION."""
    scenario = VERIFICATION_SCENARIOS["SCENARIO_06_FUNCTIONAL_REGRESSION"]
    repo, finding, req = _setup_scenario_workspace(scenario, tmp_path, db_session, user_a)

    result: VerificationRunResponse = execute_fix_verification(req, db=db_session, user_id=user_a.id)

    assert result.status == VerificationStatus.FAILED_VERIFICATION
    assert len(result.test_regressions) >= 1
    assert any("test regression detected" in r.lower() for r in result.reasons)


# =============================================================================
# SCENARIO 7: Scanner is Unavailable / Not Installed
# =============================================================================
def test_scenario_07_scanner_unavailable(tmp_path: Path, db_session: Session, user_a: User):
    """Scenario 7: Requested scanner is not installed -> INCONCLUSIVE with explicit error."""
    scenario = VERIFICATION_SCENARIOS["SCENARIO_07_SCANNER_UNAVAILABLE"]
    repo, finding, req = _setup_scenario_workspace(scenario, tmp_path, db_session, user_a)

    result: VerificationRunResponse = execute_fix_verification(req, db=db_session, user_id=user_a.id)

    # Invariant: Missing tool must NOT be misreported as verification pass
    assert result.status == VerificationStatus.INCONCLUSIVE
    assert len(result.execution_errors) >= 1
    assert any("not installed" in err.lower() or "not available" in err.lower() for err in result.execution_errors)


# =============================================================================
# SCENARIO 8: Scanner Execution Error or Timeout
# =============================================================================
def test_scenario_08_scanner_timeout_or_execution_error(tmp_path: Path, db_session: Session, user_a: User):
    """Scenario 8: Scanner timeout/crash is captured as execution error -> INCONCLUSIVE."""
    scenario = VERIFICATION_SCENARIOS["SCENARIO_08_SCANNER_TIMEOUT_ERROR"]
    repo, finding, req = _setup_scenario_workspace(scenario, tmp_path, db_session, user_a)

    # Deterministically simulate scanner timeout without stalling the test runner
    mock_timeout = ScanJobResult(
        scanner_name="Bandit Python SAST",
        scanner_version="1.9.4",
        category="sast",
        status=ScannerStatus.TIMEOUT,
        execution_time_seconds=30.0,
        error_message="Bandit subprocess exceeded 30s timeout limit during AST evaluation.",
    )

    with patch.object(BanditScannerAdapter, "scan", return_value=mock_timeout):
        result: VerificationRunResponse = execute_fix_verification(req, db=db_session, user_id=user_a.id)

    assert result.status == VerificationStatus.INCONCLUSIVE
    assert len(result.execution_errors) >= 1
    assert any("timeout" in err.lower() for err in result.execution_errors)
    assert any("failed to run or timed out" in r.lower() for r in result.reasons)


# =============================================================================
# SCENARIO 9: Patch Touches Unrelated Code Path
# =============================================================================
def test_scenario_09_patch_touches_unrelated_code_path(tmp_path: Path, db_session: Session, user_a: User):
    """Scenario 9: Patch modifies README.md; vulnerable code path remains untouched -> FAILED."""
    scenario = VERIFICATION_SCENARIOS["SCENARIO_09_UNRELATED_PATCH_PATH"]
    repo, finding, req = _setup_scenario_workspace(scenario, tmp_path, db_session, user_a)

    # Write initial README.md so patch can apply cleanly
    (Path(repo.workspace_path) / "README.md").write_text("# User Service\n", encoding="utf-8")

    result: VerificationRunResponse = execute_fix_verification(req, db=db_session, user_id=user_a.id)

    assert result.status == VerificationStatus.FAILED_VERIFICATION
    assert result.original_finding_status == "persisting"

    target_class = next((cf for cf in result.classified_findings if cf.is_target_finding), None)
    assert target_class is not None
    assert target_class.classification in (
        FindingRegressionClassification.UNCHANGED,
        FindingRegressionClassification.STILL_PRESENT,
    )


# =============================================================================
# SCENARIO 10: Insufficient Evidence to Determine Whether Fix Works
# =============================================================================
def test_scenario_10_insufficient_evidence_inconclusive(tmp_path: Path, db_session: Session, user_a: User):
    """Scenario 10: Target finding was never reproduced in baseline -> INCONCLUSIVE with missing evidence."""
    scenario = VERIFICATION_SCENARIOS["SCENARIO_10_INSUFFICIENT_EVIDENCE"]
    repo, finding, req = _setup_scenario_workspace(scenario, tmp_path, db_session, user_a)

    result: VerificationRunResponse = execute_fix_verification(req, db=db_session, user_id=user_a.id)

    # Invariant: Incomparable baseline evidence forces INCONCLUSIVE
    assert result.status == VerificationStatus.INCONCLUSIVE
    assert result.original_finding_status == "untested"
    assert len(result.missing_evidence) >= 1
    assert any("baseline" in ev.lower() for ev in result.missing_evidence)
