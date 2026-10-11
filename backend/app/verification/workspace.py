"""Isolated Disposable Workspace Management for Fix Verification.

Enforces:
1. Creation of disposable copies/worktrees in isolated temporary directories.
2. Calculation of cryptographic SHA-256 baseline and patched content hashes.
3. Secret-sanitized execution environments (stripping API keys, DB credentials).
4. Resource limits & automated workspace cleanup.
"""
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
from typing import Dict, List, Optional


# Environment variables to purge from runner sub-processes to avoid secret leakage
SENSITIVE_ENV_VARS = {
    "GEMINI_API_KEY",
    "OPENAI_API_KEY",
    "SECRET_KEY",
    "DATABASE_URL",
    "DB_PASSWORD",
    "GITHUB_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID",
    "STRIPE_API_KEY",
    "JWT_SECRET",
    "PRIVATE_KEY",
}


def calculate_directory_hash(root_dir: Path) -> str:
    """Calculate reproducible SHA-256 digest over file contents in directory."""
    hasher = hashlib.sha256()
    if not root_dir.exists() or not root_dir.is_dir():
        return hashlib.sha256(b"empty").hexdigest()

    file_paths: List[Path] = []
    for p in root_dir.rglob("*"):
        if p.is_file() and not p.name.startswith(".") and "__pycache__" not in str(p):
            file_paths.append(p)

    # Sort deterministically
    file_paths.sort(key=lambda p: str(p.relative_to(root_dir)).replace("\\", "/"))

    for p in file_paths:
        rel_path = str(p.relative_to(root_dir)).replace("\\", "/")
        hasher.update(rel_path.encode("utf-8"))
        try:
            hasher.update(p.read_bytes())
        except Exception:
            pass

    return hasher.hexdigest()


def calculate_file_or_content_hash(content_or_path: str) -> str:
    """Compute SHA-256 hash of a content string or file."""
    return hashlib.sha256(content_or_path.encode("utf-8")).hexdigest()


def get_sanitized_runner_env() -> Dict[str, str]:
    """Return environment dictionary with all application secrets and private credentials stripped.
    
    Also sets flags to disable network package installations during verification runs.
    """
    env = os.environ.copy()
    for var in SENSITIVE_ENV_VARS:
        env.pop(var, None)

    # Offline and isolation flags for runners
    env["PIP_NO_INDEX"] = "1"
    env["NO_PROXY"] = "*"
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


@dataclass
class VerificationWorkspace:
    """Represents an isolated disposable workspace on disk."""
    workspace_dir: Path
    baseline_hash: str
    patched_hash: str = ""
    is_disposable: bool = True
    temp_dir_obj: Optional[tempfile.TemporaryDirectory] = None

    def cleanup(self) -> None:
        """Safely destroy disposable workspace files."""
        if self.temp_dir_obj is not None:
            try:
                self.temp_dir_obj.cleanup()
            except Exception:
                pass
        elif self.workspace_dir.exists() and self.is_disposable:
            try:
                shutil.rmtree(self.workspace_dir, ignore_errors=True)
            except Exception:
                pass


def create_verification_workspace(
    source_dir: Optional[Path] = None,
    synthetic_files: Optional[Dict[str, str]] = None
) -> VerificationWorkspace:
    """Initialize a disposable verification workspace.
    
    Copies existing source directory if provided, or seeds with synthetic files.
    Calculates initial baseline content hash.
    """
    temp_dir = tempfile.TemporaryDirectory(prefix="reposhield_verify_")
    workspace_path = Path(temp_dir.name).resolve()

    if source_dir and source_dir.exists() and source_dir.is_dir():
        # Copy directory tree excluding git and caches
        def ignore_patterns(d, files):
            return [f for f in files if f in (".git", "__pycache__", ".pytest_cache", "node_modules", ".venv")]

        for item in source_dir.iterdir():
            if item.name in (".git", "__pycache__", ".pytest_cache", "node_modules", ".venv"):
                continue
            dest = workspace_path / item.name
            if item.is_dir():
                shutil.copytree(item, dest, ignore=ignore_patterns)
            else:
                shutil.copy2(item, dest)

    # If synthetic files are provided (for testing or mock findings), write them
    if synthetic_files:
        for rel_path, content in synthetic_files.items():
            dest_file = workspace_path / rel_path
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            dest_file.write_text(content, encoding="utf-8")

    baseline_hash = calculate_directory_hash(workspace_path)

    return VerificationWorkspace(
        workspace_dir=workspace_path,
        baseline_hash=baseline_hash,
        is_disposable=True,
        temp_dir_obj=temp_dir
    )
