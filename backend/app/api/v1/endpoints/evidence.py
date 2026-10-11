"""Security evidence management and report generation API endpoints."""
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.orm import Session

from ....core.audit import record_audit_event
from ....core.auth import get_current_user, verify_repository_ownership
from ....db.session import get_db
from ....evidence.schemas import (
    EvidenceIntegrityResponse,
    ReportExportFormat,
    SecurityEvidenceCreate,
    SecurityEvidenceRead,
    SecurityReportResponse,
    VerificationRunIntegrityResponse,
)
from ....evidence.service import (
    generate_findings_report,
    generate_verification_report,
    get_evidence_by_id,
    list_repository_evidence,
    record_security_evidence,
    verify_evidence_record_integrity,
    verify_verification_run_integrity,
)
from ....models.user import User

router = APIRouter()


@router.get(
    "",
    response_model=List[SecurityEvidenceRead],
    summary="List security evidence records for a repository, enforcing tenant ownership",
)
def list_evidence(
    repo_id: str = Query(..., description="Repository ID"),
    category: Optional[str] = Query(None, description="Optional evidence category filter"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return list_repository_evidence(
        db=db,
        repository_id=repo_id,
        current_user=current_user,
        category=category,
        skip=skip,
        limit=limit,
    )


@router.post(
    "",
    response_model=SecurityEvidenceRead,
    status_code=status.HTTP_201_CREATED,
    summary="Record a security evidence artifact for a repository",
)
def create_evidence(
    evidence_in: SecurityEvidenceCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    verify_repository_ownership(repo_id=evidence_in.repository_id, current_user=current_user, db=db)
    
    evidence = record_security_evidence(
        db=db,
        repository_id=evidence_in.repository_id,
        evidence_category=evidence_in.evidence_category.value,
        title=evidence_in.title,
        tool_name=evidence_in.tool_name,
        raw_payload=evidence_in.raw_payload,
        tool_version=evidence_in.tool_version,
        scan_id=evidence_in.scan_id,
        verification_run_id=evidence_in.verification_run_id,
        finding_id=evidence_in.finding_id,
        provenance=evidence_in.provenance.value,
        checks_not_performed=evidence_in.checks_not_performed,
    )
    
    record_audit_event(
        db=db,
        action="EVIDENCE_RECORDED",
        resource_type="evidence",
        resource_identifier=evidence.id,
        actor_id=current_user.id,
        metadata={"repo_id": evidence.repository_id, "category": evidence.evidence_category},
    )
    
    return evidence


@router.get(
    "/reports/findings",
    response_model=SecurityReportResponse,
    summary="Generate human-readable Security Findings Report with contextual risk prioritization",
)
def export_findings_report(
    repo_id: str = Query(..., description="Repository ID"),
    report_format: ReportExportFormat = Query(ReportExportFormat.MARKDOWN, alias="format"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return generate_findings_report(
        db=db,
        repository_id=repo_id,
        current_user=current_user,
        format=report_format,
    )


@router.get(
    "/reports/findings/download",
    summary="Download Security Findings Report with Content-Disposition attachment",
)
def download_findings_report(
    repo_id: str = Query(..., description="Repository ID"),
    report_format: ReportExportFormat = Query(ReportExportFormat.MARKDOWN, alias="format"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    report = generate_findings_report(
        db=db,
        repository_id=repo_id,
        current_user=current_user,
        format=report_format,
    )
    
    record_audit_event(
        db=db,
        action="FINDINGS_REPORT_DOWNLOADED",
        resource_type="report",
        resource_identifier=repo_id,
        actor_id=current_user.id,
        metadata={"format": report_format.value},
    )

    ext = "json" if report_format == ReportExportFormat.JSON else "md"
    media_type = "application/json; charset=utf-8" if report_format == ReportExportFormat.JSON else "text/markdown; charset=utf-8"
    
    return Response(
        content=report.content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="findings_report_{repo_id}.{ext}"'},
    )


@router.get(
    "/reports/verification/{verification_run_id}",
    response_model=SecurityReportResponse,
    summary="Generate human-readable Fix Verification Report with full step-by-step evidence",
)
def export_verification_report(
    verification_run_id: str,
    report_format: ReportExportFormat = Query(ReportExportFormat.MARKDOWN, alias="format"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return generate_verification_report(
        db=db,
        verification_run_id=verification_run_id,
        current_user=current_user,
        format=report_format,
    )


@router.get(
    "/reports/verification/{verification_run_id}/download",
    summary="Download Fix Verification Report with Content-Disposition attachment",
)
def download_verification_report(
    verification_run_id: str,
    report_format: ReportExportFormat = Query(ReportExportFormat.MARKDOWN, alias="format"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    report = generate_verification_report(
        db=db,
        verification_run_id=verification_run_id,
        current_user=current_user,
        format=report_format,
    )

    record_audit_event(
        db=db,
        action="VERIFICATION_REPORT_DOWNLOADED",
        resource_type="verification_report",
        resource_identifier=verification_run_id,
        actor_id=current_user.id,
        metadata={"format": report_format.value},
    )

    if report_format == ReportExportFormat.SARIF:
        ext = "sarif"
        media_type = "application/sarif+json; charset=utf-8"
    elif report_format == ReportExportFormat.JSON:
        ext = "json"
        media_type = "application/json; charset=utf-8"
    else:
        ext = "md"
        media_type = "text/markdown; charset=utf-8"

    return Response(
        content=report.content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="verification_report_{verification_run_id}.{ext}"'},
    )


@router.get(
    "/verification-runs/{verification_run_id}/verify-integrity",
    response_model=VerificationRunIntegrityResponse,
    summary="Verify cryptographic integrity of a verification run record",
)
def verify_run_integrity(
    verification_run_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return verify_verification_run_integrity(
        db=db,
        verification_run_id=verification_run_id,
        current_user=current_user,
    )


@router.get(
    "/{evidence_id}/verify-integrity",
    response_model=EvidenceIntegrityResponse,
    summary="Verify cryptographic integrity of an individual evidence artifact",
)
def verify_individual_evidence_integrity(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return verify_evidence_record_integrity(
        db=db,
        evidence_id=evidence_id,
        current_user=current_user,
    )


@router.get(
    "/{evidence_id}",
    response_model=SecurityEvidenceRead,
    summary="Get security evidence details by ID, enforcing tenant ownership",
)
def get_evidence(
    evidence_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    evidence = get_evidence_by_id(db=db, evidence_id=evidence_id, current_user=current_user)

    record_audit_event(
        db=db,
        action="EVIDENCE_ACCESSED",
        resource_type="evidence",
        resource_identifier=evidence.id,
        actor_id=current_user.id,
        metadata={"repo_id": evidence.repository_id, "category": evidence.evidence_category},
    )

    return evidence

