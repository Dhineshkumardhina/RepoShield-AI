import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from ....core.audit import record_audit_event
from ....core.auth import get_current_user, verify_repository_ownership
from ....core.errors import ForbiddenError, NotFoundError
from ....db.session import get_db
from ....models.repository import Repository
from ....models.scan import Scan
from ....models.user import User
from ....schemas.scan import ScanCreate, ScanRead, ScanResultDetail, ScannerToolInfo
from ....scanner.registry import scanner_registry
from ....scanner.runner import run_security_scan

router = APIRouter()


@router.get(
    "/tools",
    response_model=List[ScannerToolInfo],
    summary="List available security scanning engines and their versions",
)
def get_available_tools(
    current_user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    return scanner_registry.describe_scanners()


@router.get(
    "",
    response_model=List[ScanRead],
    summary="List security scans for repositories owned by the current user",
)
def list_scans(
    repository_id: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[Scan]:
    if repository_id:
        verify_repository_ownership(repo_id=repository_id, current_user=current_user, db=db)
        query = db.query(Scan).filter(Scan.repository_id == repository_id)
    else:
        query = (
            db.query(Scan)
            .join(Repository, Scan.repository_id == Repository.id)
            .filter(Repository.owner_id == current_user.id)
        )

    if status_filter:
        query = query.filter(Scan.status == status_filter)

    return query.offset(skip).limit(limit).all()


@router.post(
    "",
    response_model=ScanRead,
    status_code=status.HTTP_201_CREATED,
    summary="Initiate a security scan on a user-owned repository",
)
def create_scan(
    scan_in: ScanCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    # Verify target repository belongs to user
    repo = verify_repository_ownership(repo_id=scan_in.repository_id, current_user=current_user, db=db)

    # Enforce concurrency limits and daily scan quotas
    from ....core.quotas import check_scan_concurrency_and_quota
    check_scan_concurrency_and_quota(user=current_user, db=db)

    scan = Scan(
        repository_id=scan_in.repository_id,
        status="pending",
        scanner_configuration=scan_in.scanner_configuration,
        summary=scan_in.summary or f"Automated scan for {repo.name}",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    record_audit_event(
        db=db,
        action="SCAN_TRIGGERED",
        resource_type="scan",
        resource_identifier=scan.id,
        actor_id=current_user.id,
        metadata={"repository_id": scan.repository_id},
    )

    # Execute real security scanning engine
    scan = run_security_scan(
        repo=repo,
        scan=scan,
        db=db,
        selected_tools=scan_in.tools,
        timeout_per_tool=scan_in.timeout_seconds or 60,
    )

    return scan


@router.get(
    "/{scan_id}/results",
    response_model=ScanResultDetail,
    summary="Get detailed scanner results and tool execution reports for a scan",
)
def get_scan_results(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanResultDetail:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise NotFoundError(f"Scan with id '{scan_id}' not found.")

    repo = db.query(Repository).filter(Repository.id == scan.repository_id).first()
    if not repo or repo.owner_id != current_user.id:
        record_audit_event(
            db=db,
            action="UNAUTHORIZED_SCAN_ACCESS_BLOCKED",
            resource_type="scan",
            resource_identifier=scan_id,
            actor_id=current_user.id,
        )
        raise ForbiddenError("You do not have permission to access scans for this repository.")

    summary_obj = {}
    if scan.summary:
        try:
            summary_obj = json.loads(scan.summary)
        except Exception:
            summary_obj = {"raw": scan.summary}

    scanners_list = summary_obj.get("scanners", [])
    total_findings = summary_obj.get("total_findings", len(scan.findings))
    health_score_after = summary_obj.get("health_score_after", repo.health_score)

    return ScanResultDetail(
        id=scan.id,
        repository_id=scan.repository_id,
        status=scan.status,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        raw_summary=scan.summary,
        total_findings=total_findings,
        scanners=scanners_list,
        health_score_after=health_score_after,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanRead,
    summary="Get scan details by ID, enforcing repository ownership",
)
def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise NotFoundError(f"Scan with id '{scan_id}' not found.")

    repo = db.query(Repository).filter(Repository.id == scan.repository_id).first()
    if not repo or repo.owner_id != current_user.id:
        record_audit_event(
            db=db,
            action="UNAUTHORIZED_SCAN_ACCESS_BLOCKED",
            resource_type="scan",
            resource_identifier=scan_id,
            actor_id=current_user.id,
        )
        raise ForbiddenError("You do not have permission to access scans for this repository.")

    return scan

