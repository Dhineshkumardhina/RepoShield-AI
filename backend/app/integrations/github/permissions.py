"""Least-privilege permission matrix and validation for GitHub integration.

LEAST-PRIVILEGE PERMISSION SPECIFICATION:
1. 'contents': 'read'
   Rationale: Required to checkout code at specific base/head commit revisions and evaluate
   changed source files.
2. 'pull_requests': 'read' (or 'write' ONLY when operator explicitly enables PR commenting)
   Rationale: Read PR branch refs, base sha, and changed files list. 'write' is required ONLY
   to post security finding summary comments onto pull requests.
3. 'metadata': 'read'
   Rationale: Mandatory base permission for all GitHub Apps to resolve repository metadata.

PROHIBITED / UNNECESSARY PERMISSIONS (Strictly NOT requested):
- 'administration': write (prohibited - no repo setting modification)
- 'actions': write (prohibited - no CI tampering)
- 'secrets': read/write (prohibited - no secret reading)
- 'deployments': write (prohibited - RepoShield never deploys unreviewed code)
- 'single_file': write (prohibited - RepoShield never auto-merges or writes to main)
"""
from typing import Any, Dict, List, Optional, Tuple


LEAST_PRIVILEGE_PERMISSIONS_READONLY = {
    "contents": "read",
    "pull_requests": "read",
    "metadata": "read",
}

LEAST_PRIVILEGE_PERMISSIONS_COMMENTING = {
    "contents": "read",
    "pull_requests": "write",
    "metadata": "read",
}

DISALLOWED_HIGH_RISK_PERMISSIONS = {
    "administration",
    "actions",
    "secrets",
    "deployments",
    "security_events",
    "members",
    "organization_administration",
}


def evaluate_installation_permissions(
    granted_permissions: Dict[str, str],
    require_pr_commenting: bool = False,
) -> Tuple[bool, List[str], List[str]]:
    """Validate that granted permissions satisfy least-privilege requirements without excessive access.
    
    Returns:
        (is_valid, missing_permissions, excessive_warnings)
    """
    missing: List[str] = []
    excessive: List[str] = []

    # Check contents read
    contents_perm = granted_permissions.get("contents", "none")
    if contents_perm not in ("read", "write"):
        missing.append("contents: read (required to access commit revision trees)")

    # Check pull_requests permission
    pr_perm = granted_permissions.get("pull_requests", "none")
    if require_pr_commenting:
        if pr_perm != "write":
            missing.append("pull_requests: write (required to post security summary comments)")
    else:
        if pr_perm not in ("read", "write"):
            missing.append("pull_requests: read (required to inspect PR branch and commit context)")

    # Check for excessive or high-risk permissions
    for perm_name in granted_permissions:
        if perm_name in DISALLOWED_HIGH_RISK_PERMISSIONS:
            excessive.append(
                f"Excessive permission '{perm_name}' granted. RepoShield follows least-privilege and does not need this."
            )

    is_valid = len(missing) == 0
    return is_valid, missing, excessive


def get_excessive_permissions(granted_permissions: Dict[str, str]) -> List[str]:
    """Return list of permissions that exceed the least-privilege matrix."""
    return [
        perm for perm in granted_permissions
        if perm in DISALLOWED_HIGH_RISK_PERMISSIONS
    ]


def evaluate_permissions(
    granted_permissions: Dict[str, str],
    required_write: bool = False,
) -> Dict[str, Any]:
    """Helper returning structured evaluation result dictionary."""
    is_valid, missing, excessive = evaluate_installation_permissions(
        granted_permissions, require_pr_commenting=required_write
    )
    return {
        "is_sufficient": is_valid,
        "missing": missing,
        "excessive": excessive,
    }


def is_permission_sufficient(
    granted_permissions: Dict[str, str],
    required_scope: str,
    required_level: str = "read",
) -> bool:
    """Check if a specific scope is granted at or above the required level."""
    granted_level = granted_permissions.get(required_scope, "none")
    if required_level == "read":
        return granted_level in ("read", "write")
    elif required_level == "write":
        return granted_level == "write"
    return False
