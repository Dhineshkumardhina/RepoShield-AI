"""GitHub REST API Client supporting App Installations and Fine-Grained Tokens."""
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import httpx

from ...core.errors import AppSecException, ForbiddenError, RevokedCredentialError, UnauthorizedError
from ...core.logging import get_logger

logger = get_logger("reposhield.github.client")


class GitHubAPIError(AppSecException):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message=message, code="GITHUB_API_ERROR", status_code=status_code)


class GitHubClient:
    """Client for interacting with the GitHub API with least-privilege token authentication."""

    def __init__(
        self,
        token: Optional[str] = None,
        base_url: str = "https://api.github.com",
        timeout_seconds: float = 10.0,
    ):
        self.token = token
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout_seconds

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "RepoShield-AI-AppSec-Gate",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def verify_credentials(self) -> Dict[str, Any]:
        """Verify that current authentication token is active and not revoked."""
        if not self.token:
            raise UnauthorizedError("No GitHub authentication token provided.")

        url = f"{self.base_url}/user"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.get(url, headers=self._get_headers())
                if res.status_code == 401:
                    raise RevokedCredentialError("GitHub credentials have expired or were revoked.")
                elif res.status_code == 403:
                    raise ForbiddenError("GitHub API rate limit exceeded or access forbidden.")
                elif res.status_code >= 400:
                    raise GitHubAPIError(f"GitHub API error ({res.status_code}): {res.text[:200]}")
                return res.json()
        except httpx.RequestError as exc:
            raise GitHubAPIError(f"Network error contacting GitHub API: {str(exc)}")

    def post_pr_comment(
        self,
        repo_full_name: str,
        pr_number: int,
        comment_body: str,
    ) -> Dict[str, Any]:
        """Post a security markdown comment to a pull request."""
        if not self.token:
            raise UnauthorizedError("Authentication token is required to post GitHub comments.")

        url = f"{self.base_url}/repos/{repo_full_name}/issues/{pr_number}/comments"
        payload = {"body": comment_body}

        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(url, headers=self._get_headers(), json=payload)
                if res.status_code == 401:
                    raise UnauthorizedError("GitHub token invalid or revoked while publishing comment.")
                elif res.status_code == 403:
                    raise ForbiddenError("Permission denied: ensure 'pull_requests: write' is granted to the installation.")
                elif res.status_code >= 400:
                    raise GitHubAPIError(f"Failed to post PR comment ({res.status_code}): {res.text[:200]}")
                return res.json()
        except httpx.RequestError as exc:
            raise GitHubAPIError(f"Network failure posting PR comment: {str(exc)}")


# Alias for backwards compatibility
GitHubAPIClient = GitHubClient
