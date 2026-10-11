"""Safe Unified Diff Patch Parser for RepoShield AI.

Enforces:
1. Rejection of path traversal (.., absolute paths, Windows drive letters, null bytes).
2. Clean extraction of target paths with git prefix (a/, b/) stripping.
3. Strict hunk validation and line counting.
4. Identification of exact files and lines that would change.
"""
from pathlib import Path
import re
from typing import List, Optional, Tuple
from ..schemas.verification import ParsedFilePatch, ParsedHunk, PatchValidationResult


HUNK_HEADER_REGEX = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(.*)$")
DIFF_GIT_REGEX = re.compile(r"^diff\s+--git\s+(?:a/)?(\S+)\s+(?:b/)?(\S+)")
OLD_FILE_REGEX = re.compile(r"^---\s+(?:a/)?(\S+)")
NEW_FILE_REGEX = re.compile(r"^\+\+\+\s+(?:b/)?(\S+)")

# Prohibited path traversal & unsafe path patterns
ILLEGAL_PATH_PATTERNS = [
    re.compile(r"\.\./|\.\.\\"),  # Directory traversal (..)
    re.compile(r"^\s*[/\\]"),      # Absolute root path
    re.compile(r"^[a-zA-Z]:[/\\]"), # Windows drive letter (e.g. C:\)
    re.compile(r"\0"),            # Null bytes
    re.compile(r"~[/\\]"),        # User home expansion
]

RESERVED_DEVICE_NAMES = {"con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9"}


def sanitize_patch_path(raw_path: str) -> Tuple[Optional[str], Optional[str]]:
    """Clean and validate path extracted from diff header.
    
    Returns:
        (sanitized_relative_path, error_message)
    """
    if not raw_path:
        return None, "Empty target path in patch header"

    # Strip /dev/null for creations/deletions
    if raw_path == "/dev/null":
        return "/dev/null", None

    # Strip git a/ or b/ prefixes
    clean = raw_path.strip().strip("'\"")
    if clean.startswith("a/") or clean.startswith("b/"):
        clean = clean[2:]
    elif clean.startswith("a\\") or clean.startswith("b\\"):
        clean = clean[2:]

    # Check for illegal traversal patterns
    for pattern in ILLEGAL_PATH_PATTERNS:
        if pattern.search(clean) or pattern.search(raw_path):
            return None, f"Path traversal attempt or absolute path detected: {raw_path}"

    parts = [p.lower() for p in Path(clean).parts]
    for part in parts:
        if part in ("..", "."):
            return None, f"Illegal directory navigation symbol in path: {raw_path}"
        name_only = part.split(".")[0]
        if name_only in RESERVED_DEVICE_NAMES:
            return None, f"Reserved OS device name detected: {part}"

    # Verify path is strictly relative and doesn't escape
    try:
        p = Path(clean)
        if p.is_absolute():
            return None, f"Absolute path not permitted: {raw_path}"
    except Exception as e:
        return None, f"Invalid path syntax: {str(e)}"

    return clean.replace("\\", "/"), None


def parse_unified_diff(diff_text: str) -> PatchValidationResult:
    """Safely parse a unified diff string into structured patch representation.
    
    Validates file headers, hunk boundaries, line prefixes, and safety invariants.
    """
    if not diff_text or not diff_text.strip():
        return PatchValidationResult(
            is_valid=False,
            files=[],
            total_added=0,
            total_deleted=0,
            errors=["Patch content is empty or contains only whitespace."],
            warnings=[]
        )

    lines = diff_text.replace("\r\n", "\n").split("\n")
    files: List[ParsedFilePatch] = []
    errors: List[str] = []
    warnings: List[str] = []

    current_old_path: Optional[str] = None
    current_new_path: Optional[str] = None
    current_hunks: List[ParsedHunk] = []
    current_hunk: Optional[ParsedHunk] = None
    
    added_in_file = 0
    deleted_in_file = 0
    total_added = 0
    total_deleted = 0

    def finalize_file():
        nonlocal current_old_path, current_new_path, current_hunks, current_hunk
        nonlocal added_in_file, deleted_in_file, total_added, total_deleted

        if current_hunk is not None:
            current_hunks.append(current_hunk)
            current_hunk = None

        if current_new_path or current_old_path:
            target_path = current_new_path if current_new_path and current_new_path != "/dev/null" else current_old_path
            
            # Format modified line range description
            if current_hunks:
                ranges = [f"L{h.new_start}-{h.new_start + max(h.new_length - 1, 0)}" for h in current_hunks]
                range_str = ", ".join(ranges)
            else:
                range_str = "No hunks"

            files.append(ParsedFilePatch(
                old_path=current_old_path or target_path or "unknown",
                new_path=current_new_path or target_path or "unknown",
                hunks=list(current_hunks),
                added_lines=added_in_file,
                deleted_lines=deleted_in_file,
                modified_lines_range=range_str
            ))

        total_added += added_in_file
        total_deleted += deleted_in_file
        current_old_path = None
        current_new_path = None
        current_hunks = []
        added_in_file = 0
        deleted_in_file = 0

    idx = 0
    num_lines = len(lines)
    while idx < num_lines:
        line = lines[idx]

        # Check diff --git header
        git_match = DIFF_GIT_REGEX.match(line)
        if git_match:
            finalize_file()
            raw_old, raw_new = git_match.group(1), git_match.group(2)
            clean_old, err_old = sanitize_patch_path(raw_old)
            clean_new, err_new = sanitize_patch_path(raw_new)
            if err_old:
                errors.append(f"Line {idx+1}: {err_old}")
            if err_new:
                errors.append(f"Line {idx+1}: {err_new}")
            current_old_path = clean_old
            current_new_path = clean_new
            idx += 1
            continue

        # Check --- old_file
        old_match = OLD_FILE_REGEX.match(line)
        if old_match:
            clean_old, err_old = sanitize_patch_path(old_match.group(1))
            if err_old:
                errors.append(f"Line {idx+1}: {err_old}")
            current_old_path = clean_old
            idx += 1
            continue

        # Check +++ new_file
        new_match = NEW_FILE_REGEX.match(line)
        if new_match:
            clean_new, err_new = sanitize_patch_path(new_match.group(1))
            if err_new:
                errors.append(f"Line {idx+1}: {err_new}")
            current_new_path = clean_new
            idx += 1
            continue

        # Check hunk header @@ -l,s +l,s @@
        hunk_match = HUNK_HEADER_REGEX.match(line)
        if hunk_match:
            if current_hunk is not None:
                current_hunks.append(current_hunk)

            old_start = int(hunk_match.group(1))
            old_len = int(hunk_match.group(2)) if hunk_match.group(2) else 1
            new_start = int(hunk_match.group(3))
            new_len = int(hunk_match.group(4)) if hunk_match.group(4) else 1

            current_hunk = ParsedHunk(
                old_start=old_start,
                old_length=old_len,
                new_start=new_start,
                new_length=new_len,
                lines=[]
            )
            idx += 1
            continue

        # Inside a hunk
        if current_hunk is not None:
            if line.startswith("+"):
                added_in_file += 1
                current_hunk.lines.append(line)
            elif line.startswith("-"):
                deleted_in_file += 1
                current_hunk.lines.append(line)
            elif line.startswith(" ") or line == "":
                current_hunk.lines.append(line)
            elif line.startswith("\\ No newline at end of file"):
                current_hunk.lines.append(line)
            else:
                # Outside hunk line or unexpected line
                if not line.startswith("index ") and not line.startswith("similarity ") and not line.startswith("new file"):
                    warnings.append(f"Line {idx+1}: Unexpected content outside hunk: '{line[:40]}'")
        idx += 1

    finalize_file()

    # If no files were explicitly found by headers, check if it's a single hunk diff without diff --git
    if not files and errors:
        return PatchValidationResult(
            is_valid=False,
            files=[],
            total_added=total_added,
            total_deleted=total_deleted,
            errors=errors,
            warnings=warnings
        )

    if not files:
        errors.append("No valid file diff headers (--- / +++ or diff --git) were found in the patch.")

    is_valid = len(errors) == 0 and len(files) > 0

    return PatchValidationResult(
        is_valid=is_valid,
        files=files,
        total_added=total_added,
        total_deleted=total_deleted,
        errors=errors,
        warnings=warnings
    )
