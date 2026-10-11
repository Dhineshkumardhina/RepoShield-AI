"""Contextual Risk Prioritization & Remediation Queue API Endpoints."""
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ....core.auth import get_current_user, verify_repository_ownership
from ....db.session import get_db
from ....models.user import User
from ....prioritization.schemas import RemediationQueueItem
from ....prioritization.service import build_remediation_queue

router = APIRouter()


@router.get(
    "/remediation-queue",
    response_model=List[RemediationQueueItem],
    summary="Get prioritized remediation queue ordered by contextual risk and fix readiness",
    description=(
        "Returns security findings prioritized by RepoShield Contextual Priority and fix actionability. "
        "Separates raw scanner severity from contextual priority, includes transparent evidence limitations, "
        "and links directly to candidate patches, test verifications, and AI recommendations."
    ),
)
def get_remediation_queue(
    repo_id: Optional[str] = Query(None, description="Filter by specific repository ID owned by user"),
    priority: Optional[str] = Query(None, description="Filter by contextual priority: CRITICAL, HIGH, MEDIUM, LOW"),
    severity: Optional[str] = Query(None, description="Filter by original scanner severity: CRITICAL, HIGH, MEDIUM, LOW"),
    readiness: Optional[str] = Query(None, description="Filter by remediation status: VERIFIED_FIX_READY, PATCH_PENDING_REVIEW, etc."),
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
