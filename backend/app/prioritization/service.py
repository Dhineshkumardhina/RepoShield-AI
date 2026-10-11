"""Service module managing Contextual Risk Prioritization and the Remediation Queue."""
from typing import List, Optional
from sqlalchemy.orm import Session

from ..models.finding import SecurityFinding
from ..models.repository import Repository
from .evaluator import evaluate_finding_risk
from .schemas import (
    ContextualRiskAssessment,
    RemediationQueueItem,
    RemediationReadiness,
    RepoShieldPriority,
)


def get_suggested_action(
    assessment: ContextualRiskAssessment,
) -> str:
    """Computes transparent, actionable next step for triage engineering."""
    readiness = assessment.remediation_readiness
    priority = assessment.contextual_priority.value
    
    if readiness == RemediationReadiness.VERIFIED_FIX_READY.value:
        return f"[{priority}] Deploy verified fix: Candidate patch passed targeted regression and exploit tests."
    elif readiness == RemediationReadiness.PATCH_FAILED_TESTS.value:
        return f"[{priority}] Rework candidate patch: Fix attempt failed tests or introduced regression."
    elif readiness == RemediationReadiness.PATCH_PENDING_REVIEW.value:
        return f"[{priority}] Review proposed diff and trigger automated sandboxed fix verification."
    elif readiness == RemediationReadiness.ANALYSIS_AVAILABLE.value:
        return f"[{priority}] Inspect AI analysis recommendations and generate targeted fix."
    elif assessment.floor_protection_applied:
        return f"[{priority}] High-priority triage required: Evidence missing to prove reachability; manual investigation advised."
    else:
        return f"[{priority}] Triage finding: Validate entrypoint exposure and draft security patch."


def build_remediation_queue(
    user_id: str,
    db: Session,
    repo_id: Optional[str] = None,
    priority_filter: Optional[str] = None,
    severity_filter: Optional[str] = None,
    readiness_filter: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
) -> List[RemediationQueueItem]:
    """Builds a prioritized, evidence-backed remediation queue for repositories owned by user."""
    # 1. Base query strictly scoped to tenant ownership
    query = (
        db.query(SecurityFinding, Repository.name)
        .join(Repository, SecurityFinding.repo_id == Repository.id)
        .filter(Repository.owner_id == user_id)
    )

    if repo_id:
        query = query.filter(SecurityFinding.repo_id == repo_id)

    if severity_filter:
        query = query.filter(SecurityFinding.severity == severity_filter.upper())

    # Only include non-remediated findings in active triage queue
    query = query.filter(SecurityFinding.status.notin_(["remediated", "false_positive"]))

    raw_items = query.all()

    queue: List[RemediationQueueItem] = []

    for finding, repo_name in raw_items:
        assessment = evaluate_finding_risk(finding=finding, db=db)

        # Apply Contextual Priority filter if specified
        if priority_filter and assessment.contextual_priority.value != priority_filter.upper():
            continue

        # Apply Remediation Readiness filter if specified
        if readiness_filter and assessment.remediation_readiness.upper() != readiness_filter.upper():
            continue

        suggested_action = get_suggested_action(assessment)

        queue_item = RemediationQueueItem(
            finding_id=finding.id,
            repo_id=finding.repo_id,
            repo_name=repo_name,
            title=finding.title,
            file_path=finding.file_path,
            line_number=finding.line_number,
            cwe=finding.cwe or finding.rule_identifier or "CWE-General",
            scanner_name=finding.scanner_name,
            original_scanner_severity=finding.severity,
            contextual_priority=assessment.contextual_priority,
            priority_score=assessment.priority_score,
            affected_component=assessment.affected_component,
            remediation_status=RemediationReadiness(assessment.remediation_readiness),
            evidence_completeness=assessment.evidence_completeness,
            evidence_limitations=assessment.missing_context,
            suggested_action=suggested_action,
            linkage=assessment.remediation_linkage,
        )
        queue.append(queue_item)

    # 2. Sort by Triage Priority Order:
    # Top priority: Highest priority_score
    # Secondary: Actionable items (VERIFIED_FIX_READY) promoted for rapid remediation
    def triage_sort_key(item: RemediationQueueItem):
        readiness_boost = 10.0 if item.remediation_status == RemediationReadiness.VERIFIED_FIX_READY else 0.0
        return (item.priority_score + readiness_boost, item.priority_score)

    queue.sort(key=triage_sort_key, reverse=True)

    # 3. Apply pagination
    return queue[skip : skip + limit]
