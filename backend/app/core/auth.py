"""Authentication and authorization dependencies for FastAPI endpoints."""
from typing import Optional
from fastapi import Depends, Request
from sqlalchemy.orm import Session

from .audit import record_audit_event
from .config import settings
from .errors import AccountInactiveError, ForbiddenError, NotFoundError, UnauthorizedError
from .logging import get_logger
from .security import decode_access_token
from ..db.session import get_db
from ..models.finding import SecurityFinding
from ..models.repository import Repository
from ..models.user import User

logger = get_logger("reposhield.auth")


def extract_token(request: Request) -> Optional[str]:
    """Extract authentication token from Authorization header or HTTP-only cookie."""
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        if token:
            return token

    cookie_token = request.cookies.get(settings.COOKIE_NAME)
    if cookie_token and cookie_token.strip():
        return cookie_token.strip()

    return None


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """Dependency that authenticates the user via bearer token or HTTP-only session cookie."""
    token = extract_token(request)
    if not token:
        raise UnauthorizedError("Authentication credentials were not provided. Sign in to proceed.")

    payload = decode_access_token(token)
    user_id: Optional[str] = payload.get("sub")
    if not user_id:
        raise UnauthorizedError("Malformed authentication credentials.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise UnauthorizedError("User account no longer exists.")

    if user.account_status != "active":
        raise AccountInactiveError("This account is currently inactive or suspended.")

    return user


def get_current_user_optional(
    request: Request,
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Optional authentication dependency; returns None if not authenticated."""
    token = extract_token(request)
    if not token:
        return None
    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        if not user_id:
            return None
        user = db.query(User).filter(User.id == user_id).first()
        if user and user.account_status == "active":
            return user
        return None
    except Exception:
        return None


def verify_repository_ownership(
    repo_id: str,
    current_user: User,
    db: Session,
) -> Repository:
    """Enforces strict multi-tenant ownership check on repositories."""
    repo = db.query(Repository).filter(Repository.id == repo_id).first()
    if not repo:
        raise NotFoundError(f"Repository with id '{repo_id}' not found.")

    if repo.owner_id != current_user.id:
        record_audit_event(
            db=db,
            action="UNAUTHORIZED_REPO_ACCESS_BLOCKED",
            resource_type="repository",
            resource_identifier=repo_id,
            actor_id=current_user.id,
            metadata={"owner_id": repo.owner_id},
        )
        raise ForbiddenError("You do not have permission to access this repository.")

    return repo


def verify_finding_ownership(
    finding_id: str,
    current_user: User,
    db: Session,
) -> SecurityFinding:
    """Enforces strict multi-tenant ownership check on findings."""
    finding = db.query(SecurityFinding).filter(SecurityFinding.id == finding_id).first()
    if not finding:
        raise NotFoundError(f"Security finding with id '{finding_id}' not found.")

    # Cross-reference finding's repository ownership
    repo = db.query(Repository).filter(Repository.id == finding.repo_id).first()
    if not repo or repo.owner_id != current_user.id:
        record_audit_event(
            db=db,
            action="UNAUTHORIZED_FINDING_ACCESS_BLOCKED",
            resource_type="finding",
            resource_identifier=finding_id,
            actor_id=current_user.id,
            metadata={"repo_id": finding.repo_id},
        )
        raise ForbiddenError("You do not have permission to access findings for this repository.")

    return finding
