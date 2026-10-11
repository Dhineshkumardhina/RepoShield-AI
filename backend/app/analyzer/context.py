"""Bounded, permission-checked source-code context retrieval.

Strictly protects against:
1. Path traversal attacks (e.g. `../../etc/passwd`).
2. Symlinks pointing outside repository workspace.
3. Giant file memory/token exhaustion.
4. Exposure of unredacted secrets in context.
"""
from dataclasses import dataclass
import os
from pathlib import Path
from typing import Optional

from ..core.errors import NotFoundError, ValidationError
from ..core.logging import get_logger
from ..models.repository import Repository
from ..scanner.base import redact_secrets

logger = get_logger("reposhield.analyzer.context")

MAX_CONTEXT_CHARS = 10000
MAX_WINDOW_LINES = 25


@dataclass
class SourceContext:
    file_path: str
    target_line: int
    start_line: int
    end_line: int
    code_excerpt: str
    is_truncated: bool
    total_lines: int


def get_bounded_source_context(
    repo: Repository,
    file_path: str,
    target_line: int = 1,
    window_lines: int = 15,
) -> Optional[SourceContext]:
    """Safely retrieve a bounded source snippet surrounding target_line within the repository workspace."""
    if not repo.workspace_path:
        logger.debug(f"Repo {repo.id} has no workspace_path set")
        return None

    workspace_root = Path(repo.workspace_path).resolve()
    if not workspace_root.exists() or not workspace_root.is_dir():
        logger.warning(f"Workspace directory does not exist: {workspace_root}")
        return None

    # Sanitize and validate file_path against path traversal
    clean_rel = os.path.normpath(file_path.replace("\\", "/")).lstrip("/")
    if ".." in clean_rel.split(os.sep) or ".." in clean_rel.split("/"):
        raise ValidationError(f"Path traversal detected in context lookup: {file_path}")

    target_file = (workspace_root / clean_rel).resolve()

    # Verify resolved path is strictly within workspace_root
    try:
        target_file.relative_to(workspace_root)
    except ValueError:
        raise ValidationError(f"Illegal file access outside repository workspace: {file_path}")

    if not target_file.exists() or not target_file.is_file():
        logger.debug(f"Target file not found in workspace: {target_file}")
        return None

    try:
        with open(target_file, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as exc:
        logger.error(f"Error reading source file {target_file}: {exc}")
        return None

    total_lines = len(lines)
    if total_lines == 0:
        return SourceContext(
            file_path=clean_rel,
            target_line=target_line,
            start_line=1,
            end_line=1,
            code_excerpt="",
            is_truncated=False,
            total_lines=0,
        )

    clamped_target = max(1, min(target_line, total_lines))
    clamped_window = min(window_lines, MAX_WINDOW_LINES)

    start_idx = max(0, clamped_target - 1 - clamped_window)
    end_idx = min(total_lines, clamped_target + clamped_window)

    selected_lines = lines[start_idx:end_idx]
    is_truncated = (start_idx > 0) or (end_idx < total_lines)

    # Format with line numbers for AI analyst clarity
    numbered_lines = []
    for idx, line in enumerate(selected_lines, start=start_idx + 1):
        indicator = " >> " if idx == clamped_target else "    "
        numbered_lines.append(f"{idx:4d}{indicator}| {line.rstrip()}")

    raw_text = "\n".join(numbered_lines)
    if len(raw_text) > MAX_CONTEXT_CHARS:
        raw_text = raw_text[:MAX_CONTEXT_CHARS] + "\n... [Context truncated due to size limit]"
        is_truncated = True

    # Strictly redact secrets
    sanitized_excerpt = redact_secrets(raw_text) or ""

    return SourceContext(
        file_path=clean_rel,
        target_line=clamped_target,
        start_line=start_idx + 1,
        end_line=end_idx,
        code_excerpt=sanitized_excerpt,
        is_truncated=is_truncated,
        total_lines=total_lines,
    )
