"""GitHub and CI/CD Integrations API endpoints."""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, Request, status
from sqlalchemy.orm import Session

from ....core.auth import get_current_user
from ....core.errors import ForbiddenError, SecurityPolicyViolationError
from ....db.session import get_db
from ....integrations.github.schemas import (
    CIEvaluationRequest,
    CIEvaluationResponse,
    GitHubInstallationRegisterRequest,
    GitHubInstallationResponse,
    PullRequestScanResponse,
    PullRequestScanTriggerRequest,
    PullRequestSummaryPublishRequest,
    RepositoryGitHubLinkRequest,
    RepositoryGitHubLinkResponse,
)
from ....integrations.github.service import (
    evaluate_ci_security_gate,
    get_pr_scan_details,
    handle_incoming_webhook,
    link_repository_to_github,
    list_user_github_installations,
    publish_pr_summary_comment,
    register_github_installation,
    revoke_github_installation,
    trigger_pr_security_scan,
)
from ....models.user import User

router = APIRouter()


@router.post(
    "/github/installations",
    response_model=GitHubInstallationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a GitHub App installation with encrypted credentials",
)
def register_installation(
    payload: GitHubInstallationRegisterRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> GitHubInstallationResponse:
    """Register and store GitHub App installation with least-privilege permission validation."""
    return register_github_installation(current_user=current_user, payload=payload, db=db)


@router.get(
    "/github/installations",
    response_model=List[GitHubInstallationResponse],
    summary="List active GitHub App installations for the current user",
)
def list_installations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[GitHubInstallationResponse]:
    """Retrieve all active GitHub App installations owned by the current tenant."""
    return list_user_github_installations(current_user=current_user, db=db)


@router.delete(
    "/github/installations/{installation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a GitHub App installation",
)
def revoke_installation(
    installation_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Deactivates GitHub integration credentials and marks installation as revoked."""
    revoke_github_installation(installation_id=installation_id, current_user=current_user, db=db)
    return None


@router.post(
    "/github/installations/{installation_id}/revoke",
    response_model=GitHubInstallationResponse,
    summary="Revoke a GitHub App installation (POST alias)",
)
def revoke_installation_post(
    installation_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> GitHubInstallationResponse:
    """Deactivates GitHub integration credentials and marks installation as revoked."""
    return revoke_github_installation(installation_id=installation_id, current_user=current_user, db=db)


@router.post(
    "/github/repositories/link",
    response_model=RepositoryGitHubLinkResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Connect a RepoShield repository to a GitHub repository",
)
@router.post(
    "/github/links",
    response_model=RepositoryGitHubLinkResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Connect a RepoShield repository to a GitHub repository (alias)",
)
def link_repository(
    payload: RepositoryGitHubLinkRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> RepositoryGitHubLinkResponse:
    """Binds a repository to a GitHub repository with explicit operator commenting policy."""
    return link_repository_to_github(current_user=current_user, payload=payload, db=db)


@router.post(
    "/github/pr-scans",
    response_model=PullRequestScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger security analysis on a pull request commit reference",
)
@router.post(
    "/github/scans/pr",
    response_model=PullRequestScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger security analysis on a pull request commit reference (alias)",
)
def create_pr_scan(
    payload: PullRequestScanTriggerRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PullRequestScanResponse:
    """Analyze changed files and categorize findings into NEW, RESOLVED, UNCHANGED, and REGRESSED."""
    return trigger_pr_security_scan(current_user=current_user, payload=payload, db=db)


@router.get(
    "/github/pr-scans/{pr_scan_id}",
    response_model=PullRequestScanResponse,
    summary="Get pull request security analysis report",
)
def get_pr_scan(
    pr_scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PullRequestScanResponse:
    """Inspect categorized findings, commit SHA associations, and scanner execution records."""
    return get_pr_scan_details(pr_scan_id=pr_scan_id, current_user=current_user, db=db)


@router.post(
    "/github/pr-scans/{pr_scan_id}/publish",
    response_model=PullRequestScanResponse,
    summary="Publish pull request security summary comment to GitHub",
)
def publish_pr_summary(
    pr_scan_id: str,
    payload: PullRequestSummaryPublishRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PullRequestScanResponse:
    """Publish actionable Markdown summary to GitHub PR, enforcing permission and consent gating."""
    if not payload.publish_comment:
        raise SecurityPolicyViolationError("Publishing aborted: operator toggle publish_comment is False.")
    return publish_pr_summary_comment(current_user=current_user, pr_scan_id=pr_scan_id, db=db)


@router.post(
    "/github/webhook",
    summary="Ingest and process GitHub webhook events",
)
async def github_webhook(
    request: Request,
    db: Session = Depends(get_db),
    x_github_event: str = Header("ping", alias="X-GitHub-Event"),
    x_github_delivery: Optional[str] = Header(None, alias="X-GitHub-Delivery"),
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
) -> Dict[str, Any]:
    """Secure webhook endpoint enforcing HMAC signature validation and replay defense."""
    raw_body = await request.body()
    return handle_incoming_webhook(
        event_type=x_github_event,
        delivery_id=x_github_delivery,
        signature_header=x_hub_signature_256,
        raw_payload=raw_body,
        db=db,
    )


@router.post(
    "/ci/evaluate",
    response_model=CIEvaluationResponse,
    summary="Evaluate CI pipeline commit against security gate policies",
)
@router.post(
    "/github/ci/evaluate",
    response_model=CIEvaluationResponse,
    summary="Evaluate CI pipeline commit against security gate policies (alias)",
)
def evaluate_ci_gate(
    payload: CIEvaluationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CIEvaluationResponse:
    """Evaluate head commit against base commit, returning machine-readable CI gate verdict and exit code."""
    return evaluate_ci_security_gate(current_user=current_user, payload=payload, db=db)

