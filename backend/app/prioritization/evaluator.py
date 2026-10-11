"""Evaluator module synthesizing finding evidence into ContextualRiskAssessment."""
import json
import re
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session

from ..models.analysis import FindingAnalysis
from ..models.finding import SecurityFinding
from ..models.patch import PatchProposal
from ..models.validation import FindingValidation
from ..models.verification import VerificationRun
from .schemas import (
    ComponentCategory,
    ContextualRiskAssessment,
    EnvironmentContext,
    EvidenceCompleteness,
    RemediationLinkage,
    RemediationReadiness,
)
from .scoring import calculate_contextual_risk_score

SENSITIVE_PATTERNS = re.compile(
    r"(password|secret|private[_-]?key|token|credential|api[_-]?key|bearer|jwt|credit[_-]?card|ssn|auth_token)",
    re.IGNORECASE,
)

TEST_PATH_PATTERNS = re.compile(
    r"(tests?\/|test_|__tests__|mocks?\/|fixtures?\/|samples?\/|docs?\/)",
    re.IGNORECASE,
)

ENTRYPOINT_PATH_PATTERNS = re.compile(
    r"(routes?\/|controllers?\/|endpoints?\/|views?\/|api\/|handlers?\/|server\.py|app\.py|main\.py)",
    re.IGNORECASE,
)

CORE_SECURITY_PATTERNS = re.compile(
    r"(auth|login|oauth|jwt|crypto|security|permission|session|rbac|token|credential|authenticator|authoriz)",
    re.IGNORECASE,
)

UTILITY_PATH_PATTERNS = re.compile(
    r"(utils?\/|helpers?\/|scripts?\/|tools?\/|cli\/|tasks?\/)",
    re.IGNORECASE,
)


def detect_affected_component(finding: SecurityFinding) -> str:
    """Categorizes the affected architectural component strictly from observable path and rule evidence."""
    file_path = finding.file_path or ""
    metadata_text = f"{file_path} {finding.rule_identifier or ''} {finding.cwe or ''} {finding.title or ''}"

    if TEST_PATH_PATTERNS.search(file_path):
        return ComponentCategory.TEST_OR_MOCK_FIXTURE.value
    if CORE_SECURITY_PATTERNS.search(metadata_text):
        return ComponentCategory.CORE_SECURITY_BOUNDARY.value
    if ENTRYPOINT_PATH_PATTERNS.search(file_path):
        return ComponentCategory.PUBLIC_INGRESS_API.value
    if UTILITY_PATH_PATTERNS.search(file_path):
        return ComponentCategory.INTERNAL_UTILITY.value
    return ComponentCategory.BUSINESS_LOGIC.value


def extract_remediation_linkage(
    finding: SecurityFinding,
    db: Session,
) -> Tuple[str, RemediationLinkage]:
    """Extracts candidate patch proposals, verification status, and AI recommendations linked to finding."""
    # 1. Check latest verification run
    latest_run = (
        db.query(VerificationRun)
        .filter(VerificationRun.finding_id == finding.id)
        .order_by(VerificationRun.created_at.desc())
        .first()
    )

    # 2. Check patch proposals
    latest_patch = (
        db.query(PatchProposal)
        .filter(PatchProposal.finding_id == finding.id)
        .order_by(PatchProposal.created_at.desc())
        .first()
    )

    # 3. Check AI analysis recommendations
    latest_analysis = (
        db.query(FindingAnalysis)
        .filter(FindingAnalysis.finding_id == finding.id)
        .order_by(FindingAnalysis.created_at.desc())
        .first()
    )

    recommendations: List[str] = []
    suggested_tests: List[str] = []
    analysis_id: Optional[str] = None
    if latest_analysis:
        analysis_id = latest_analysis.id
        try:
            if latest_analysis.suggested_remediation:
                recs = json.loads(latest_analysis.suggested_remediation)
                if isinstance(recs, list):
                    recommendations = [str(r) for r in recs]
        except Exception:
            pass
        try:
            if latest_analysis.suggested_targeted_tests:
                tests = json.loads(latest_analysis.suggested_targeted_tests)
                if isinstance(tests, list):
                    suggested_tests = [str(t) for t in tests]
        except Exception:
            pass

    # Determine readiness
    if latest_run and latest_run.status == "VERIFIED_AGAINST_DEFINED_CHECKS":
        readiness = RemediationReadiness.VERIFIED_FIX_READY.value
    elif latest_run and latest_run.status == "FAILED_VERIFICATION":
        readiness = RemediationReadiness.PATCH_FAILED_TESTS.value
    elif latest_patch:
        readiness = RemediationReadiness.PATCH_PENDING_REVIEW.value
    elif recommendations:
        readiness = RemediationReadiness.ANALYSIS_AVAILABLE.value
    else:
        readiness = RemediationReadiness.NEEDS_INVESTIGATION.value

    diff_preview: Optional[str] = None
    if latest_patch and latest_patch.proposed_diff_reference:
        diff_preview = latest_patch.proposed_diff_reference[:300]
    elif latest_run and latest_run.patch_diff:
        diff_preview = latest_run.patch_diff[:300]

    linkage = RemediationLinkage(
        finding_id=finding.id,
        patch_proposal_id=latest_patch.id if latest_patch else None,
        verification_run_id=latest_run.id if latest_run else None,
        verification_status=latest_run.status if latest_run else "NOT_TESTED",
        analysis_id=analysis_id,
        recommendations=recommendations,
        suggested_targeted_tests=suggested_tests,
        patch_diff_preview=diff_preview,
    )

    return readiness, linkage


def evaluate_finding_risk(
    finding: SecurityFinding,
    db: Session,
    env_context: Optional[EnvironmentContext] = None,
) -> ContextualRiskAssessment:
    """Evaluates contextual risk for a security finding strictly based on available evidence."""
    if env_context is None:
        env_context = EnvironmentContext()

    missing_context: List[str] = []

    # 1. Sensitive Data Analysis
    searchable_text = f"{finding.title} {finding.rule_identifier or ''} {finding.cwe or ''} {finding.code_excerpt or ''}"
    sensitive_data_involved = bool(SENSITIVE_PATTERNS.search(searchable_text))
    if not sensitive_data_involved:
        missing_context.append("No explicit secret, credential, or PII keyword pattern detected in finding metadata.")

    # 2. Affected Component Analysis
    affected_component = detect_affected_component(finding)

    # 3. Reachability Analysis (Strictly truth-in-evidence)
    file_path = finding.file_path or ""
    if TEST_PATH_PATTERNS.search(file_path):
        reachability_status = "test_fixture"
    elif ENTRYPOINT_PATH_PATTERNS.search(file_path):
        reachability_status = "entrypoint_route"
    else:
        reachability_status = "unproven"
        missing_context.append("Call graph or execution trace reachability is unproven by static scanner output.")

    # 4. Dependency Exposure Analysis
    is_dependency = (
        (finding.category or "").lower() in ("dependency", "sca")
        or (finding.scanner_name or "").lower() in ("pip-audit", "npm-audit", "snyk")
    )
    if is_dependency:
        if "dev" in file_path.lower():
            dependency_exposure = "transitive_dev"
        else:
            dependency_exposure = "direct_production"
    else:
        dependency_exposure = "non_dependency"

    # 5. Auth Context
    if env_context.auth_context and env_context.auth_context != "unknown":
        auth_posture = env_context.auth_context
    elif finding.code_excerpt and re.search(r"(@login_required|@requires_auth|get_current_user|is_authenticated)", finding.code_excerpt):
        auth_posture = "authenticated_user"
    else:
        auth_posture = "unknown"
        missing_context.append("Authentication / authorization wrapper context could not be inferred from excerpt.")

    # 6. Verification & Remediation Linkage
    remediation_readiness, linkage = extract_remediation_linkage(finding=finding, db=db)
    verification_status = linkage.verification_status or "NOT_TESTED"

    # 7. Finding Validation Record
    latest_val = (
        db.query(FindingValidation)
        .filter(FindingValidation.finding_id == finding.id)
        .order_by(FindingValidation.recorded_at.desc())
        .first()
    )
    val_status = latest_val.assessment_status if latest_val else "UNREVIEWED"
    if val_status == "INSUFFICIENT_EVIDENCE":
        missing_context.append("Evidence-driven validation recorded INSUFFICIENT_EVIDENCE status.")

    # 8. Evidence Completeness
    has_excerpt = bool(finding.code_excerpt and len(finding.code_excerpt.strip()) > 5)
    has_line = bool(finding.line_number and finding.line_number > 0)
    
    if has_excerpt and has_line and reachability_status != "unproven" and env_context.environment != "unknown":
        completeness = EvidenceCompleteness.COMPLETE
    elif has_excerpt and has_line and reachability_status != "unproven":
        completeness = EvidenceCompleteness.PARTIAL
    elif has_excerpt and has_line:
        completeness = EvidenceCompleteness.PARTIAL
    elif val_status == "INSUFFICIENT_EVIDENCE":
        completeness = EvidenceCompleteness.INSUFFICIENT
        missing_context.append("Validation marked evidence as insufficient for confirmation.")
    else:
        completeness = EvidenceCompleteness.MINIMAL
        missing_context.append("Code excerpt or precise line number is incomplete in finding record.")

    # 9. Calculate Deterministic Score with Floor Protection
    priority_score, contextual_priority, factors = calculate_contextual_risk_score(
        scanner_severity=finding.severity,
        confidence_label=finding.confidence,
        confidence_score=finding.confidence_score if finding.confidence_score is not None else 0.95,
        sensitive_data_involved=sensitive_data_involved,
        reachability_status=reachability_status,
        dependency_exposure=dependency_exposure,
        auth_context=auth_posture,
        env_context=env_context,
        affected_component=affected_component,
        finding_validation_status=val_status,
        remediation_status=remediation_readiness,
    )

    floor_applied = any("Severe Finding Protection Floor" in f.name for f in factors)
    inv_rec: Optional[str] = None
    if floor_applied:
        inv_rec = (
            f"Severe scanner finding ({finding.severity}) preserved at {contextual_priority.value} priority. "
            "Because runtime reachability or environmental exposure is unproven, conduct dynamic exploit verification "
            "or call graph tracing before de-prioritizing."
        )
    elif completeness in (EvidenceCompleteness.MINIMAL, EvidenceCompleteness.INSUFFICIENT):
        inv_rec = (
            "Contextual evidence is insufficient to verify execution path or runtime reachability. "
            "Conduct dynamic exploit verification or manual code audit."
        )
    elif reachability_status == "unproven":
        inv_rec = (
            "Runtime reachability is unproven from static analysis alone. "
            "Verify whether the affected function is invoked from active routing entrypoints."
        )

    return ContextualRiskAssessment(
        finding_id=finding.id,
        repo_id=finding.repo_id,
        original_scanner_severity=finding.severity,
        contextual_priority=contextual_priority,
        evidence_completeness=completeness,
        verification_status=verification_status,
        priority_score=priority_score,
        sensitive_data_involved=sensitive_data_involved,
        reachability_evidence=reachability_status,
        dependency_exposure=dependency_exposure,
        auth_context=auth_posture,
        affected_component=affected_component,
        remediation_readiness=remediation_readiness,
        floor_protection_applied=floor_applied,
        investigation_recommendation=inv_rec,
        factors=factors,
        missing_context=missing_context,
        remediation_linkage=linkage,
    )
