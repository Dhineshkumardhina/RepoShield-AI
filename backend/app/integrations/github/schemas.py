"""Pydantic schemas for GitHub App & CI/CD integration."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator


class FindingClassification(str, Enum):
    NEW = "NEW"
    RESOLVED = "RESOLVED"
    UNCHANGED = "UNCHANGED"
    REGRESSED = "REGRESSED"


class GitHubInstallationRegisterRequest(BaseModel):
    installation_id: str = Field(..., description="GitHub App Installation ID")
    app_id: Optional[str] = Field(default=None, description="GitHub App ID")
    account_login: str = Field(..., description="GitHub organization or user login name")
    account_type: str = Field(default="User", description="'User' or 'Organization'")
    auth_mode: str = Field(default="github_app", description="'github_app' or 'scoped_token'")
    auth_type: Optional[str] = Field(default=None, description="Alias for auth_mode")
    access_token: Optional[str] = Field(default=None, description="Installation or personal access token (will be encrypted)")
    raw_credential: Optional[str] = Field(default=None, description="Alias for access_token")
    private_key_pem: Optional[str] = Field(default=None, description="App private key PEM (will be encrypted)")
    webhook_secret: Optional[str] = Field(default=None, description="Webhook shared secret")
    permissions: Optional[Dict[str, str]] = Field(default_factory=dict, description="Granted permissions mapping")
    granted_permissions: Optional[Dict[str, str]] = Field(default=None, description="Alias for permissions")

    @model_validator(mode="before")
    @classmethod
    def normalize_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "raw_credential" in data and "access_token" not in data:
                data["access_token"] = data["raw_credential"]
            if "granted_permissions" in data and "permissions" not in data:
                data["permissions"] = data["granted_permissions"]
            if "auth_type" in data and "auth_mode" not in data:
                data["auth_mode"] = data["auth_type"]
        return data


class GitHubInstallationResponse(BaseModel):
    id: str
    owner_id: str
    installation_id: str
    app_id: Optional[str] = None
    account_login: str
    account_type: str
    auth_mode: str
    is_active: bool
    permissions_granted: Optional[Dict[str, str]] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RepositoryGitHubLinkRequest(BaseModel):
    repository_id: str = Field(..., description="RepoShield repository ID")
    installation_id: Optional[str] = Field(default=None, description="GitHub integration ID")
    github_integration_id: Optional[str] = Field(default=None, description="Alias for installation_id")
    github_repo_full_name: str = Field(..., pattern=r"^[a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\.]+$", description="GitHub repository 'owner/repo'")
    default_branch: str = Field(default="main", pattern=r"^[a-zA-Z0-9_\-\./]+$", description="Default branch")
    auto_scan_on_pr: bool = Field(default=True, description="Automatically evaluate PR webhook events")
    publish_pr_comments: bool = Field(default=False, description="Explicit operator authorization to publish PR comment summaries")
    block_pr_on_critical: bool = Field(default=False, description="Block PR check run if critical findings are detected")

    @model_validator(mode="before")
    @classmethod
    def normalize_link_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "github_integration_id" in data and "installation_id" not in data:
                data["installation_id"] = data["github_integration_id"]
        return data


class RepositoryGitHubLinkResponse(BaseModel):
    id: str
    repository_id: str
    integration_id: str
    github_repo_full_name: str
    default_branch: str
    auto_scan_on_pr: bool
    publish_pr_comments: bool
    block_pr_on_critical: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PullRequestScanTriggerRequest(BaseModel):
    repository_id: Optional[str] = Field(default=None, description="RepoShield repository ID")
    link_id: Optional[str] = Field(default=None, description="Link ID")
    pr_number: int = Field(..., ge=1, description="Pull Request number")
    head_commit_sha: Optional[str] = Field(default=None, pattern=r"^[a-fA-F0-9]{7,40}$", description="Head commit SHA being evaluated")
    head_sha: Optional[str] = Field(default=None, description="Alias for head_commit_sha")
    base_commit_sha: Optional[str] = Field(default=None, pattern=r"^[a-fA-F0-9]{7,40}$", description="Base commit SHA target")
    base_sha: Optional[str] = Field(default=None, description="Alias for base_commit_sha")
    pr_title: Optional[str] = Field(default=None, description="Pull request title (treated as untrusted text)")
    head_branch: Optional[str] = Field(default="feature", description="PR head branch")
    base_branch: Optional[str] = Field(default="main", description="PR base branch")
    changed_files: Optional[List[str]] = Field(default=None, description="Explicit list of changed relative paths")
    selected_tools: Optional[List[str]] = Field(default=None, description="Specific scanners to run")

    @model_validator(mode="before")
    @classmethod
    def normalize_pr_scan_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "head_sha" in data and "head_commit_sha" not in data:
                data["head_commit_sha"] = data["head_sha"]
            if "base_sha" in data and "base_commit_sha" not in data:
                data["base_commit_sha"] = data["base_sha"]
        return data


# Convenient schema aliases
GitHubInstallationCreate = GitHubInstallationRegisterRequest
LinkRepoGitHubRequest = RepositoryGitHubLinkRequest
PRScanTriggerRequest = PullRequestScanTriggerRequest


class CategorizedPRFinding(BaseModel):
    classification: FindingClassification
    scanner_name: str
    rule_id: str
    category: Optional[str] = "Security"
    severity: str
    file_path: str
    line_number: Optional[int] = None
    message: str
    commit_sha: Optional[str] = "HEAD"
    code_excerpt: Optional[str] = None
    finding_id: Optional[str] = None
    detail_url: Optional[str] = None


class PRVerificationSummary(BaseModel):
    finding_id: str = Field(..., description="ID of the target security finding")
    finding_title: Optional[str] = Field(default=None, description="Human-readable title or CWE of the finding")
    rule_id: Optional[str] = Field(default=None, description="Scanner rule or vulnerability ID")
    file_path: Optional[str] = Field(default=None, description="Target file path")
    status: str = Field(..., description="Verification status (VERIFIED_AGAINST_DEFINED_CHECKS, FAILED_VERIFICATION, INCONCLUSIVE)")
    patch_summary: Optional[str] = Field(default=None, description="Summary of patch applied")
    patch_diff: Optional[str] = Field(default=None, description="Unified diff excerpt")
    evidence_items: List[str] = Field(default_factory=list, description="List of concrete test/scanner verification evidence items")
    evidence_report_link: Optional[str] = Field(default=None, description="Link to complete verification evidence run")
    finding_detail_link: Optional[str] = Field(default=None, description="Link to complete finding detail report")


class PullRequestScanResponse(BaseModel):
    id: str
    repository_id: str
    pr_number: int
    pr_title: Optional[str]
    head_commit_sha: str
    base_commit_sha: str
    status: str
    changed_files: List[str]
    new_findings_count: int
    resolved_findings_count: int
    unchanged_findings_count: int
    regressed_findings_count: int
    findings: List[CategorizedPRFinding]
    summary_published: bool
    summary_comment_id: Optional[str] = None
    incomplete_checks: List[str]
    failed_checks: List[str] = Field(default_factory=list)
    unavailable_checks: List[str] = Field(default_factory=list)
    verifications: List[PRVerificationSummary] = Field(default_factory=list)
    reproduction_command: Optional[str] = None
    report_links: Dict[str, str] = Field(default_factory=dict)
    started_at: datetime
    completed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class PullRequestSummaryPublishRequest(BaseModel):
    publish_comment: bool = Field(default=True, description="Explicit operator authorization to publish summary to GitHub PR")


class CIEvaluationRequest(BaseModel):
    repository_id: Optional[str] = Field(default=None, description="RepoShield repository ID or name")
    head_commit_sha: str = Field(..., pattern=r"^[a-fA-F0-9]{7,40}$", description="Head commit SHA being evaluated")
    base_commit_sha: Optional[str] = Field(default=None, pattern=r"^[a-fA-F0-9]{7,40}$", description="Base commit SHA target")
    pr_number: Optional[int] = Field(default=None, ge=1, description="Pull Request number if associated")
    changed_files: Optional[List[str]] = Field(default_factory=list, description="Explicit list of changed relative paths")
    fail_on_severity: Optional[str] = Field(default="HIGH", description="Severity threshold: CRITICAL, HIGH, MEDIUM, LOW")
    require_all_checks: bool = Field(default=True, description="Fail the gate if any configured checks are unavailable/skipped")
    selected_tools: Optional[List[str]] = Field(default=None, description="Specific scanners to evaluate")
    include_verification_evidence: bool = Field(default=True, description="Query and attach fix verification records")


class CIEvaluationResponse(BaseModel):
    repository_id: Optional[str] = None
    repository_name: Optional[str] = None
    head_commit_sha: str
    base_commit_sha: Optional[str] = None
    pr_number: Optional[int] = None
    gate_status: str = Field(..., description="Overall gate status: 'PASS', 'FAIL', or 'INCOMPLETE'")
    exit_code: int = Field(..., description="Standard CI exit code: 0 (PASS), 1 (FAIL), 2 (INCOMPLETE)")
    gate_passed: bool = Field(..., description="Whether CI pipeline gate passed successfully")
    summary_markdown: str = Field(..., description="Actionable pull request security markdown summary")
    new_findings_count: int = 0
    resolved_findings_count: int = 0
    regressed_findings_count: int = 0
    unchanged_findings_count: int = 0
    failed_checks: List[str] = Field(default_factory=list, description="Executed checks that detected security violations")
    unavailable_checks: List[str] = Field(default_factory=list, description="Configured checks that were omitted or unavailable")
    findings: List[CategorizedPRFinding] = Field(default_factory=list, description="Categorized finding details")
    verifications: List[PRVerificationSummary] = Field(default_factory=list, description="Candidate fix verifications and evidence")
    reproduction_command: str = Field(..., description="Command for developers to reproduce results locally")
    report_links: Dict[str, str] = Field(default_factory=dict, description="Links to full findings and evidence reports")
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(from_attributes=True)
