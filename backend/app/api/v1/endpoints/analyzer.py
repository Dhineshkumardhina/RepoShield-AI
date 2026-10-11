from typing import List, Optional
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from ....analyzer.service import analyze_finding_service, get_finding_analyses_for_finding
from ....core.auth import get_current_user, get_current_user_optional, verify_finding_ownership
from ....core.errors import ForbiddenError, UnauthorizedError
from ....db.session import get_db
from ....models.finding import SecurityFinding
from ....models.user import User
from ....schemas.analyzer import FindingAnalysisRequest, FindingAnalysisResponse

router = APIRouter()


@router.post(
    "/analyze-finding",
    response_model=FindingAnalysisResponse,
    summary="Analyze finding with security guards, prompt injection defense, and bounded context",
)
def analyze_finding(
    payload: FindingAnalysisRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> FindingAnalysisResponse:
    """Analyze a security finding using Gemini or deterministic AppSec engine.

    Enforces:
    - User authentication and operator consent.
    - Tenant ownership check if finding exists in repository.
    - Zero execution of repository scripts.
    - Defense against prompt injection in comments and READMEs.
    - Secret redaction in evidence and context.
    - Exploitability claim moderation.
    - Separate storage in finding_analyses table without mutating original scanner finding.
    """
    if payload.finding_id:
        stored_finding = db.query(SecurityFinding).filter(SecurityFinding.id == payload.finding_id).first()
        if stored_finding:
            verify_finding_ownership(finding_id=stored_finding.id, current_user=current_user, db=db)

    return analyze_finding_service(
        payload=payload,
        db=db,
        current_user_id=current_user.id,
    )


@router.get(
    "/findings/{finding_id}/analyses",
    response_model=List[FindingAnalysisResponse],
    summary="Get all historical AI analyses stored for a specific finding",
)
def get_finding_analyses(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[FindingAnalysisResponse]:
    """Retrieve historical AI analyst reports for a finding, enforcing tenant ownership."""
    verify_finding_ownership(finding_id=finding_id, current_user=current_user, db=db)
    return get_finding_analyses_for_finding(finding_id=finding_id, db=db)

