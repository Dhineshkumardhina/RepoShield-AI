"""Security findings API endpoints with ownership enforcement."""
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from ....core.audit import record_audit_event
from ....core.auth import (
    get_current_user,
    verify_finding_ownership,
    verify_repository_ownership,
)
from ....core.errors import NotFoundError
from ....db.session import get_db
from ....models.finding import SecurityFinding
from ....models.repository import Repository
from ....models.user import User
from ....prioritization.evaluator import evaluate_finding_risk
from ....prioritization.schemas import (
    ContextualRiskAssessment,
    EnvironmentContext,
    RemediationQueueItem,
)
from ....prioritization.service import build_remediation_queue
from ....schemas.finding import SecurityFindingCreate, SecurityFindingRead

router = APIRouter()


@router.get(
    "",
    response_model=List[SecurityFindingRead],
    summary="List security findings for repositories owned by the current user with contextual priority filtering",
)
def list_findings(
    repo_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None, description="Original scanner severity filter: CRITICAL, HIGH, MEDIUM, LOW"),
    priority: Optional[str] = Query(None, description="RepoShield contextual priority filter: CRITICAL, HIGH, MEDIUM, LOW"),
    cwe: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[SecurityFindingRead]:
    # If a specific repository is requested, enforce that the user owns it
    if repo_id:
        verify_repository_ownership(repo_id=repo_id, current_user=current_user, db=db)
        query = db.query(SecurityFinding).filter(SecurityFinding.repo_id == repo_id)
    else:
        # Only return findings from repositories owned by this user
        query = (
            db.query(SecurityFinding)
            .join(Repository, SecurityFinding.repo_id == Repository.id)
            .filter(Repository.owner_id == current_user.id)
        )

    if severity:
        query = query.filter(SecurityFinding.severity == severity.upper())
    if cwe:
        query = query.filter(SecurityFinding.cwe.ilike(f"%{cwe}%"))
    if status_filter:
        query = query.filter(SecurityFinding.status == status_filter)

    raw_findings = query.all()

    # Populate contextual risk metadata and apply priority filter if requested
    results: List[SecurityFindingRead] = []
    for f in raw_findings:
        assessment = evaluate_finding_risk(finding=f, db=db)
        
        if priority and assessment.contextual_priority.value != priority.upper():
            continue

        read_item = SecurityFindingRead(
            id=f.id,
            repo_id=f.repo_id,
            scan_id=f.scan_id,
            scanner_identifier=f.scanner_identifier,
            scanner_name=f.scanner_name,
            rule_identifier=f.rule_identifier,
            cwe=f.cwe,
            title=f.title,
            category=f.category,
            severity=f.severity,
            confidence=f.confidence,
            confidence_score=f.confidence_score,
            file_path=f.file_path,
            line_number=f.line_number,
            line_information=f.line_information,
            evidence_reference=f.evidence_reference,
            status=f.status,
            finding_status=f.finding_status,
            code_excerpt=f.code_excerpt,
            pr_number=f.pr_number,
            contextual_priority=assessment.contextual_priority.value,
            priority_score=assessment.priority_score,
            evidence_completeness=assessment.evidence_completeness.value,
            remediation_readiness=assessment.remediation_readiness,
            created_at=f.created_at,
            updated_at=f.updated_at,
        )
        results.append(read_item)

    return results[skip : skip + limit]


@router.post(
    "",
    response_model=SecurityFindingRead,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a security finding into a user-owned repository",
)
def create_finding(
    finding_in: SecurityFindingCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SecurityFinding:
    # Verify the target repository exists and is owned by the current user
    verify_repository_ownership(repo_id=finding_in.repo_id, current_user=current_user, db=db)

    scanner_id = finding_in.scanner_identifier or finding_in.scanner_name or "Semgrep OSS"
    rule_id = finding_in.rule_identifier or finding_in.cwe or "CWE-General"
    finding_stat = finding_in.finding_status or finding_in.status or "open"

    finding = SecurityFinding(
        repo_id=finding_in.repo_id,
        scan_id=finding_in.scan_id,
        scanner_identifier=scanner_id,
        scanner_name=scanner_id,
        rule_identifier=rule_id,
        cwe=rule_id,
        title=finding_in.title,
        category=finding_in.category or "vulnerability",
        severity=finding_in.severity,
        confidence=finding_in.confidence or "HIGH",
        confidence_score=finding_in.confidence_score,
        file_path=finding_in.file_path,
        line_number=finding_in.line_number,
        line_information=finding_in.line_information or str(finding_in.line_number),
        evidence_reference=finding_in.evidence_reference,
        finding_status=finding_stat,
        status=finding_stat,
        code_excerpt=finding_in.code_excerpt,
        pr_number=finding_in.pr_number,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    record_audit_event(
        db=db,
        action="FINDING_INGESTED",
        resource_type="finding",
        resource_identifier=finding.id,
        actor_id=current_user.id,
        metadata={"repo_id": finding.repo_id, "severity": finding.severity},
    )

    return finding


@router.get(
    "/remediation-queue",
    response_model=List[RemediationQueueItem],
    summary="Get prioritized remediation queue ordered by contextual risk and fix readiness",
)
def list_findings_remediation_queue(
    repo_id: Optional[str] = Query(None),
    priority: Optional[str] = Query(None, description="Contextual priority filter: CRITICAL, HIGH, MEDIUM, LOW"),
    severity: Optional[str] = Query(None, description="Original scanner severity filter: CRITICAL, HIGH, MEDIUM, LOW"),
    readiness: Optional[str] = Query(None, description="Remediation status: VERIFIED_FIX_READY, PATCH_PENDING_REVIEW, etc."),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[RemediationQueueItem]:
    if repo_id:
        verify_repository_ownership(repo_id=repo_id, current_user=current_user, db=db)

    return build_remediation_queue(
        user_id=current_user.id,
        db=db,
        repo_id=repo_id,
        priority_filter=priority,
        severity_filter=severity,
        readiness_filter=readiness,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/{finding_id}",
    response_model=SecurityFindingRead,
    summary="Get security finding details by ID, enforcing tenant authorization",
)
def get_finding(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SecurityFinding:
    # verify_finding_ownership will raise 404 if not found, 403 if repo belongs to another user
    finding = verify_finding_ownership(finding_id=finding_id, current_user=current_user, db=db)
    return finding


@router.get(
    "/{finding_id}/prioritization",
    response_model=ContextualRiskAssessment,
    summary="Evaluate transparent contextual risk prioritization for a finding",
)
def get_finding_prioritization(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ContextualRiskAssessment:
    finding = verify_finding_ownership(finding_id=finding_id, current_user=current_user, db=db)
    return evaluate_finding_risk(finding=finding, db=db)


@router.post(
    "/{finding_id}/prioritize",
    response_model=ContextualRiskAssessment,
    summary="Evaluate tailored contextual risk prioritization with user-supplied environment context",
)
def prioritize_finding_with_environment(
    finding_id: str,
    env_context: EnvironmentContext,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ContextualRiskAssessment:
    finding = verify_finding_ownership(finding_id=finding_id, current_user=current_user, db=db)
    return evaluate_finding_risk(finding=finding, db=db, env_context=env_context)

