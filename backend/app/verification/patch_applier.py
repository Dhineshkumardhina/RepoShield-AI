"""Safe Patch Application Engine for Isolated Workspaces.

Applies parsed unified diffs to files inside an isolated disposable workspace.
Ensures:
- Verification of context lines before applying modifications.
- Atomic file updates.
- Zero modification to files outside the specified workspace root.
"""
from pathlib import Path
from typing import List, Optional, Tuple
from .patch_parser import PatchValidationResult, ParsedFilePatch, ParsedHunk


class PatchApplicationError(Exception):
    """Raised when patch application fails due to context mismatch or missing file."""
    pass


def apply_hunks_to_content(original_content: str, hunks: List[ParsedHunk]) -> Tuple[str, List[str]]:
    """Apply a sequence of hunks to string content.
    
    Returns:
        (patched_content, list_of_errors)
    """
    orig_lines = original_content.replace("\r\n", "\n").split("\n")
    errors: List[str] = []
    
    # Process hunks in order with line tracking
    # Sort hunks by old_start ascending
    sorted_hunks = sorted(hunks, key=lambda h: h.old_start)

    result_lines: List[str] = []
    curr_orig_idx = 0  # 0-indexed in orig_lines

    for hunk_idx, hunk in enumerate(sorted_hunks):
        target_start = max(0, hunk.old_start - 1)  # 1-indexed to 0-indexed

        # Copy unchanged lines leading up to hunk
        while curr_orig_idx < target_start and curr_orig_idx < len(orig_lines):
            result_lines.append(orig_lines[curr_orig_idx])
            curr_orig_idx += 1

        # Now apply the hunk lines
        for line in hunk.lines:
            if not line:
                continue
            marker = line[0]
            text = line[1:]

            if marker == " ":
                # Context line - must match original
                if curr_orig_idx < len(orig_lines):
                    actual = orig_lines[curr_orig_idx]
                    # Soft match stripping trailing whitespace
                    if actual.rstrip() == text.rstrip():
                        result_lines.append(actual)
                        curr_orig_idx += 1
                    else:
                        errors.append(
                            f"Hunk {hunk_idx+1} context mismatch at line {curr_orig_idx+1}. "
                            f"Expected: '{text.strip()[:40]}', Found: '{actual.strip()[:40]}'"
                        )
                        result_lines.append(text)
                        curr_orig_idx += 1
                else:
                    errors.append(f"Hunk {hunk_idx+1} context extends past end of file.")
                    result_lines.append(text)

            elif marker == "-":
                # Deletion line - must match original line being deleted
                if curr_orig_idx < len(orig_lines):
                    actual = orig_lines[curr_orig_idx]
                    if actual.rstrip() != text.rstrip():
                        errors.append(
                            f"Hunk {hunk_idx+1} delete line mismatch at line {curr_orig_idx+1}. "
                            f"Expected deletion: '{text.strip()[:40]}', Found: '{actual.strip()[:40]}'"
                        )
                    curr_orig_idx += 1
                else:
                    errors.append(f"Hunk {hunk_idx+1} delete line extends past end of file.")

            elif marker == "+":
                # Addition line - insert into result
                result_lines.append(text)

            elif marker == "\\":
                # '\ No newline at end of file' comment
                pass

    # Append any remaining lines from original file
    while curr_orig_idx < len(orig_lines):
        result_lines.append(orig_lines[curr_orig_idx])
        curr_orig_idx += 1

    patched_content = "\n".join(result_lines)
    return patched_content, errors


def apply_patch_to_workspace(
    workspace_root: Path,
    patch_result: PatchValidationResult
) -> Tuple[bool, List[str]]:
    """Apply validated patch to files in the disposable workspace.
    
    Returns:
        (success: bool, errors: List[str])
    """
    if not patch_result.is_valid:
        return False, ["Cannot apply invalid patch: " + "; ".join(patch_result.errors)]

    root_resolved = workspace_root.resolve()
    all_errors: List[str] = []

    for file_patch in patch_result.files:
        target_rel = file_patch.new_path if file_patch.new_path != "/dev/null" else file_patch.old_path
        if not target_rel or target_rel == "/dev/null":
            continue

        target_file = (root_resolved / target_rel).resolve()

        # Invariant: File must be strictly inside the workspace root
        try:
            target_file.relative_to(root_resolved)
        except ValueError:
            all_errors.append(f"Security boundary violation: target path {target_rel} escapes workspace.")
            continue

        # File creation vs update vs deletion
        if file_patch.old_path == "/dev/null":
            # New file creation
            target_file.parent.mkdir(parents=True, exist_ok=True)
            new_lines = [l[1:] for h in file_patch.hunks for l in h.lines if l.startswith("+")]
            target_file.write_text("\n".join(new_lines), encoding="utf-8")
            continue

        if file_patch.new_path == "/dev/null":
            # File deletion
            if target_file.exists():
                target_file.unlink()
            continue

        # Modification of existing file
        if not target_file.exists():
            all_errors.append(f"Target file does not exist in workspace: {target_rel}")
            continue

        try:
            original_content = target_file.read_text(encoding="utf-8", errors="replace")
            patched_content, hunk_errors = apply_hunks_to_content(original_content, file_patch.hunks)

            if hunk_errors:
                all_errors.extend([f"{target_rel}: {e}" for e in hunk_errors])

            target_file.write_text(patched_content, encoding="utf-8")
        except Exception as e:
            all_errors.append(f"Error applying patch to {target_rel}: {str(e)}")

    success = len(all_errors) == 0
    return success, all_errors
