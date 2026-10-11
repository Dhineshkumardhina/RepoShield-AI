"""API endpoints for Evidence-Driven Vulnerability Validation."""
from typing import List, Optional
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from ....core.auth import get_current_user, verify_finding_ownership
from ....core.errors import NotFoundError
from ....db.session import get_db
from ....models.user import User
from ....schemas.validation import FindingValidationRequest, FindingValidationResponse
from ....validation.service import (
    get_finding_validation_service,
    list_finding_validations_service,
    validate_finding_service,
)

router = APIRouter()


@router.post(
    "/{finding_id}/validate",
    response_model=FindingValidationResponse,
    status_code=status.HTTP_200_OK,
    summary="Perform evidence-driven validation assessment on a security finding",
)
def validate_finding(
    finding_id: str,
    request: Optional[FindingValidationRequest] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FindingValidationResponse:
    """Assess an existing scanner finding against observable code evidence.
    
    Enforces:
    - User authentication and repository tenant ownership.
    - Zero mutation of the original scanner finding or original severity.
    - Deterministic evidentiary evaluation (AST, constants, test fixtures, sanitizers).
    - Prompt-injection defense on untrusted source commentary.
    - Optional bounded AI assistant reasoning.
    """
    verify_finding_ownership(finding_id=finding_id, current_user=current_user, db=db)
    return validate_finding_service(
        finding_id=finding_id,
        db=db,
        current_user_id=current_user.id,
        request=request,
    )


@router.get(
    "/{finding_id}/validation",
    response_model=FindingValidationResponse,
    summary="Get the latest evidence validation assessment for a finding",
)
def get_latest_validation(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> FindingValidationResponse:
    """Retrieve the latest evidence-backed validation assessment for a finding."""
    verify_finding_ownership(finding_id=finding_id, current_user=current_user, db=db)
    result = get_finding_validation_service(
        finding_id=finding_id,
        db=db,
        current_user_id=current_user.id,
    )
    if not result:
        raise NotFoundError("FindingValidation", f"for finding {finding_id}")
    return result


@router.get(
    "/{finding_id}/validations",
    response_model=List[FindingValidationResponse],
    summary="Get all historical validation assessments for a finding",
)
def get_validation_history(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[FindingValidationResponse]:
    """Retrieve all historical validation assessments recorded for a finding."""
    verify_finding_ownership(finding_id=finding_id, current_user=current_user, db=db)
    return list_finding_validations_service(
        finding_id=finding_id,
        db=db,
        current_user_id=current_user.id,
    )
