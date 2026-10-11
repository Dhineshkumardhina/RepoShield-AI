"""Dataset Deduplication and Split Integrity Validator.

Detects duplicate or overlapping examples across benchmark cases:
1. Identifier collisions (case_id, patch_id).
2. Content hash collisions (identical source code or patch diffs across cases).
3. Data leakage between development and held-out partitions.
"""
from dataclasses import dataclass, field
import hashlib
from typing import Any, Dict, List, Set, Tuple

from .models import BenchmarkCaseDefinition


@dataclass
class DeduplicationIssue:
    issue_type: str  # id_collision, content_duplicate, diff_duplicate, split_leakage
    severity: str    # error, warning
    message: str
    affected_ids: List[str] = field(default_factory=list)


@dataclass
class DeduplicationReport:
    total_cases_analyzed: int = 0
    total_patches_analyzed: int = 0
    unique_cases: int = 0
    unique_patches: int = 0
    issues: List[DeduplicationIssue] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return any(i.severity == "error" for i in self.issues)


def calculate_content_digest(content: str) -> str:
    """Compute normalized SHA-256 hash ignoring trailing whitespace."""
    clean = "\n".join(line.rstrip() for line in content.strip().splitlines())
    return hashlib.sha256(clean.encode("utf-8")).hexdigest()


def validate_dataset_uniqueness_and_splits(
    cases: List[BenchmarkCaseDefinition],
) -> DeduplicationReport:
    """Analyze benchmark cases for duplicates, overlaps, and split leakage."""
    report = DeduplicationReport(total_cases_analyzed=len(cases))
    
    seen_case_ids: Dict[str, str] = {}
    seen_patch_ids: Dict[str, Tuple[str, str]] = {}  # patch_id -> (case_id, split)
    seen_code_hashes: Dict[str, List[str]] = {}       # hash -> list of case_ids
    seen_diff_hashes: Dict[str, List[Tuple[str, str]]] = {} # hash -> list of (case_id, patch_id)

    dev_case_hashes: Set[str] = set()
    held_out_case_hashes: Set[str] = set()
    dev_patch_diffs: Set[str] = set()
    held_out_patch_diffs: Set[str] = set()

    for case in cases:
        # 1. Case ID collisions
        if case.case_id in seen_case_ids:
            report.issues.append(DeduplicationIssue(
                issue_type="id_collision",
                severity="error",
                message=f"Duplicate case_id '{case.case_id}' detected.",
                affected_ids=[case.case_id]
            ))
        seen_case_ids[case.case_id] = case.split

        # 2. Source code duplicate check
        code_hash = calculate_content_digest(case.vulnerable_code)
        if code_hash in seen_code_hashes:
            seen_code_hashes[code_hash].append(case.case_id)
            report.issues.append(DeduplicationIssue(
                issue_type="content_duplicate",
                severity="warning",
                message=f"Identical vulnerable source code shared between cases: {seen_code_hashes[code_hash]}",
                affected_ids=seen_code_hashes[code_hash]
            ))
        else:
            seen_code_hashes[code_hash] = [case.case_id]

        if case.split == "dev":
            dev_case_hashes.add(code_hash)
        else:
            held_out_case_hashes.add(code_hash)

        # 3. Patch analysis
        for patch in case.candidate_patches:
            report.total_patches_analyzed += 1

            # Patch ID collisions
            if patch.patch_id in seen_patch_ids:
                prev_case, _ = seen_patch_ids[patch.patch_id]
                report.issues.append(DeduplicationIssue(
                    issue_type="id_collision",
                    severity="error",
                    message=f"Duplicate patch_id '{patch.patch_id}' across cases '{prev_case}' and '{case.case_id}'.",
                    affected_ids=[prev_case, case.case_id]
                ))
            seen_patch_ids[patch.patch_id] = (case.case_id, case.split)

            # Diff duplicates
            diff_hash = calculate_content_digest(patch.unified_diff)
            if diff_hash in seen_diff_hashes:
                seen_diff_hashes[diff_hash].append((case.case_id, patch.patch_id))
                report.issues.append(DeduplicationIssue(
                    issue_type="diff_duplicate",
                    severity="warning",
                    message=f"Identical unified diff found in multiple patches: {seen_diff_hashes[diff_hash]}",
                    affected_ids=[p[1] for p in seen_diff_hashes[diff_hash]]
                ))
            else:
                seen_diff_hashes[diff_hash] = [(case.case_id, patch.patch_id)]

            if case.split == "dev":
                dev_patch_diffs.add(diff_hash)
            else:
                held_out_patch_diffs.add(diff_hash)

    # 4. Check split contamination / leakage
    overlap_cases = dev_case_hashes.intersection(held_out_case_hashes)
    if overlap_cases:
        report.issues.append(DeduplicationIssue(
            issue_type="split_leakage",
            severity="error",
            message=f"Data leakage detected: {len(overlap_cases)} source code file(s) exist in both 'dev' and 'held_out' splits.",
            affected_ids=list(seen_case_ids.keys())
        ))

    overlap_diffs = dev_patch_diffs.intersection(held_out_patch_diffs)
    if overlap_diffs:
        report.issues.append(DeduplicationIssue(
            issue_type="split_leakage",
            severity="error",
            message=f"Data leakage detected: {len(overlap_diffs)} candidate patch diff(s) exist in both 'dev' and 'held_out' splits.",
            affected_ids=list(seen_patch_ids.keys())
        ))

    report.unique_cases = len(seen_case_ids)
    report.unique_patches = len(seen_patch_ids)
    return report
