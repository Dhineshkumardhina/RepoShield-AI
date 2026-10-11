"""Comparison Engine for Baseline vs Patched Verification Results.

Evaluates and classifies all scanner findings across baseline and patched workspaces:
1. NEW: Findings introduced in patched workspace that did not exist in baseline.
2. RESOLVED_BY_DEFINED_CHECKS: Target or baseline findings confirmed reproduced in baseline
   and no longer reported in patched workspace.
3. STILL_PRESENT: Baseline findings that remain detected in patched workspace under same rule/file.
4. UNCHANGED: Pre-existing findings in unmodified files present in both baseline and patched workspaces.
5. POTENTIALLY_REGRESSED: Findings in modified files that shifted line/sink/rule or represent partial fixes.
6. INCOMPARABLE: Scanners errored/timed out, or baseline finding was never reproduced in baseline workspace.
"""
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ..scanner.base import NormalizedFinding
from ..schemas.verification import (
    CLASSIFICATION_RULE_DEFINITIONS,
    ClassifiedFinding,
    FindingRegressionClassification,
)


@dataclass
class FindingComparisonResult:
    """Detailed comparison result spanning all 6 regression classification categories."""
    original_finding_status: str  # resolved, persisting, modified, untested (backward compatibility)
    original_finding_classification: FindingRegressionClassification
    original_finding_present_in_baseline: bool
    original_finding_present_in_patched: bool
    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    classified_findings: List[ClassifiedFinding] = field(default_factory=list)
    resolved_findings_count: int = 0
    persisting_findings_count: int = 0
    new_findings_count: int = 0
    unchanged_findings_count: int = 0
    potentially_regressed_findings_count: int = 0
    incomparable_findings_count: int = 0
    total_baseline_findings: int = 0
    total_patched_findings: int = 0
    reasons: List[str] = field(default_factory=list)


def normalize_file_path(path: Optional[str]) -> str:
    """Normalize file paths for cross-platform comparison."""
    if not path:
        return ""
    return path.replace("\\", "/").strip("/").lower()


def normalize_category_string(s: Optional[str]) -> str:
    """Normalize category string by removing non-alphanumeric characters for robust comparison."""
    if not s:
        return ""
    return re.sub(r"[^a-z0-9]", "", s.lower())


def categories_match(c1: Optional[str], c2: Optional[str]) -> bool:
    """Check whether two vulnerability categories or CWE identifiers match."""
    if not c1 or not c2:
        return False
    norm1 = normalize_category_string(c1)
    norm2 = normalize_category_string(c2)
    return norm1 in norm2 or norm2 in norm1


def is_matching_finding(
    finding: NormalizedFinding,
    target_rule_id: Optional[str] = None,
    target_category: Optional[str] = None,
    target_file: Optional[str] = None,
    target_line: Optional[int] = None
) -> bool:
    """Check whether a scanner finding corresponds to the target finding being verified."""
    file_matches = True
    if target_file and finding.file_path:
        norm_t = normalize_file_path(target_file)
        norm_f = normalize_file_path(finding.file_path)
        file_matches = norm_t in norm_f or norm_f in norm_t

    rule_matches = True
    if target_rule_id and finding.scanner_rule_id:
        rule_matches = target_rule_id.lower() == finding.scanner_rule_id.lower()
    elif target_category and finding.vulnerability_category:
        rule_matches = categories_match(target_category, finding.vulnerability_category)

    return file_matches and rule_matches


def findings_are_equivalent(
    f1: NormalizedFinding,
    f2: NormalizedFinding,
    line_tolerance: int = 10
) -> bool:
    """Determine whether two findings from different scan runs represent the same occurrence."""
    p1 = normalize_file_path(f1.file_path)
    p2 = normalize_file_path(f2.file_path)
    if p1 != p2:
        return False

    r1 = (f1.scanner_rule_id or "").lower()
    r2 = (f2.scanner_rule_id or "").lower()

    return bool(r1 and r2 and r1 == r2)


def compare_verification_findings(
    original_finding_rule: Optional[str],
    original_finding_category: Optional[str],
    original_finding_file: Optional[str],
    original_finding_line: Optional[int],
    baseline_findings: List[NormalizedFinding],
    patched_findings: List[NormalizedFinding],
    changed_files: Optional[List[str]] = None,
    scanner_errors: Optional[List[str]] = None,
    baseline_errors: Optional[List[str]] = None,
) -> FindingComparisonResult:
    """Compare baseline findings against patched findings and classify into the 6 taxonomies.

    Taxonomy:
    - NEW: Introduced in patched workspace.
    - RESOLVED_BY_DEFINED_CHECKS: Observed in baseline, no longer detected in patched.
    - STILL_PRESENT: Remained detected in patched workspace with same rule/file.
    - UNCHANGED: Non-target baseline findings in unmodified files persisting without alteration.
    - POTENTIALLY_REGRESSED: Partial fix or finding shifted line/sink/rule in modified file.
    - INCOMPARABLE: Scanner errored, timed out, or baseline finding not observed in baseline.
    """
    reasons: List[str] = []
    norm_changed_files: Set[str] = {
        normalize_file_path(f) for f in (changed_files or [])
    }
    all_errors = list(scanner_errors or []) + list(baseline_errors or [])
    has_scanner_fault = len(all_errors) > 0

    # 1. Identify Target Finding in Baseline
    baseline_target_matches = [
        f for f in baseline_findings
        if is_matching_finding(f, original_finding_rule, original_finding_category, original_finding_file, original_finding_line)
    ]
    present_in_baseline = len(baseline_target_matches) > 0

    # 2. Identify Target Finding in Patched
    patched_target_matches = [
        f for f in patched_findings
        if is_matching_finding(f, original_finding_rule, original_finding_category, original_finding_file, original_finding_line)
    ]
    present_in_patched = len(patched_target_matches) > 0

    # 3. Classify Target Finding
    if has_scanner_fault:
        target_classification = FindingRegressionClassification.INCOMPARABLE
        target_status_compat = "untested"
        reasons.append(
            "Classification is INCOMPARABLE: Scanner execution error or timeout occurred during analysis."
        )
    elif not present_in_baseline:
        target_classification = FindingRegressionClassification.INCOMPARABLE
        target_status_compat = "untested"
        reasons.append(
            "Classification is INCOMPARABLE: Target finding was not reproduced in baseline workspace by configured scanners. "
            "Resolution cannot be claimed through static checks alone without baseline reproduction."
        )
    elif present_in_patched:
        # Check if line shifted significantly or rule changed indicating potential mutation / partial fix
        exact_line_match = any(
            original_finding_line and abs((p.start_line or 0) - original_finding_line) <= 2
            for p in patched_target_matches
        )
        if exact_line_match or not original_finding_line:
            target_classification = FindingRegressionClassification.STILL_PRESENT
            target_status_compat = "persisting"
            reasons.append(
                f"Classification is STILL_PRESENT: Original finding remains reported by scanner rules ({len(patched_target_matches)} instances still detected)."
            )
        else:
            target_classification = FindingRegressionClassification.POTENTIALLY_REGRESSED
            target_status_compat = "modified"
            reasons.append(
                "Classification is POTENTIALLY_REGRESSED: Vulnerability pattern shifted lines or sink structure in modified file without full resolution."
            )
    else:
        # Check if another finding in the modified file shares the same category (partial fix)
        norm_target_file = normalize_file_path(original_finding_file)
        related_patched_findings = [
            f for f in patched_findings
            if normalize_file_path(f.file_path) == norm_target_file
            and categories_match(original_finding_category, f.vulnerability_category)
        ]
        if related_patched_findings:
            target_classification = FindingRegressionClassification.POTENTIALLY_REGRESSED
            target_status_compat = "modified"
            reasons.append(
                f"Classification is POTENTIALLY_REGRESSED: Target finding disappeared under rule '{original_finding_rule}', "
                f"but related vulnerability '{related_patched_findings[0].scanner_rule_id}' remains in modified file (partial fix)."
            )
        else:
            target_classification = FindingRegressionClassification.RESOLVED_BY_DEFINED_CHECKS
            target_status_compat = "resolved"
            reasons.append(
                "Classification is RESOLVED_BY_DEFINED_CHECKS: Target finding was confirmed in baseline and is no longer reported in patched workspace."
            )

    # 4. Classify All Individual Findings (Baseline & Patched)
    classified_findings: List[ClassifiedFinding] = []
    matched_patched_indices: Set[int] = set()

    for b_idx, b in enumerate(baseline_findings):
        is_target = is_matching_finding(b, original_finding_rule, original_finding_category, original_finding_file, original_finding_line)
        b_file_norm = normalize_file_path(b.file_path)
        is_in_changed_file = b_file_norm in norm_changed_files or not norm_changed_files

        # Find matching patched finding
        matched_p_idx: Optional[int] = None
        for p_idx, p in enumerate(patched_findings):
            if p_idx in matched_patched_indices:
                continue
            if findings_are_equivalent(b, p):
                matched_p_idx = p_idx
                matched_patched_indices.add(p_idx)
                break

        if has_scanner_fault:
            c_status = FindingRegressionClassification.INCOMPARABLE
            c_reason = "Scanner failure during analysis."
        elif matched_p_idx is not None:
            p_match = patched_findings[matched_p_idx]
            if is_in_changed_file:
                if b.start_line != p_match.start_line:
                    c_status = FindingRegressionClassification.POTENTIALLY_REGRESSED
                    c_reason = f"Finding shifted from line {b.start_line} to {p_match.start_line} in modified file."
                else:
                    c_status = FindingRegressionClassification.STILL_PRESENT
                    c_reason = CLASSIFICATION_RULE_DEFINITIONS["STILL_PRESENT"]
            else:
                c_status = FindingRegressionClassification.UNCHANGED
                c_reason = CLASSIFICATION_RULE_DEFINITIONS["UNCHANGED"]
        else:
            # Finding disappeared in patched
            c_status = FindingRegressionClassification.RESOLVED_BY_DEFINED_CHECKS
            c_reason = CLASSIFICATION_RULE_DEFINITIONS["RESOLVED_BY_DEFINED_CHECKS"]

        b_dict = {
            "rule_id": b.scanner_rule_id,
            "scanner": b.scanner_name,
            "category": b.vulnerability_category,
            "severity": b.severity,
            "file_path": b.file_path,
            "line": b.start_line,
            "message": b.scanner_message,
        }
        p_dict = None
        if matched_p_idx is not None:
            p_found = patched_findings[matched_p_idx]
            p_dict = {
                "rule_id": p_found.scanner_rule_id,
                "scanner": p_found.scanner_name,
                "category": p_found.vulnerability_category,
                "severity": p_found.severity,
                "file_path": p_found.file_path,
                "line": p_found.start_line,
                "message": p_found.scanner_message,
            }

        classified_findings.append(ClassifiedFinding(
            rule_id=b.scanner_rule_id or "UNKNOWN",
            scanner_name=b.scanner_name or "Static Analyzer",
            vulnerability_category=b.vulnerability_category or "Vulnerability",
            severity=b.severity or "MEDIUM",
            file_path=b.file_path or "",
            line_number=b.start_line,
            message=b.scanner_message or "",
            classification=c_status,
            classification_reason=c_reason,
            is_target_finding=is_target,
            baseline_match=b_dict,
            patched_match=p_dict,
        ))

    # 5. Process Unmatched Patched Findings (NEW findings / regressions)
    new_findings: List[Dict[str, Any]] = []
    for p_idx, p in enumerate(patched_findings):
        if p_idx in matched_patched_indices:
            continue

        p_dict = {
            "rule_id": p.scanner_rule_id,
            "scanner": p.scanner_name,
            "category": p.vulnerability_category,
            "severity": p.severity,
            "file_path": p.file_path,
            "line": p.start_line,
            "message": p.scanner_message,
        }
        new_findings.append(p_dict)

        classified_findings.append(ClassifiedFinding(
            rule_id=p.scanner_rule_id or "UNKNOWN",
            scanner_name=p.scanner_name or "Static Analyzer",
            vulnerability_category=p.vulnerability_category or "Security Defect",
            severity=p.severity or "HIGH",
            file_path=p.file_path or "",
            line_number=p.start_line,
            message=p.scanner_message or "",
            classification=FindingRegressionClassification.NEW,
            classification_reason=CLASSIFICATION_RULE_DEFINITIONS["NEW"],
            is_target_finding=False,
            baseline_match=None,
            patched_match=p_dict,
        ))

    if new_findings:
        reasons.append(
            f"Blocking regression detected: Patch introduced {len(new_findings)} new security finding(s) (NEW)."
        )

    # If the target finding was not in baseline at all and has no classified finding entry yet, add an entry
    if not present_in_baseline and original_finding_rule:
        target_clf = ClassifiedFinding(
            rule_id=original_finding_rule,
            scanner_name="Configured Scanner",
            vulnerability_category=original_finding_category or "Target Finding",
            severity="HIGH",
            file_path=original_finding_file or "",
            line_number=original_finding_line,
            message="Target finding specified for verification.",
            classification=FindingRegressionClassification.INCOMPARABLE,
            classification_reason=CLASSIFICATION_RULE_DEFINITIONS["INCOMPARABLE"],
            is_target_finding=True,
            baseline_match=None,
            patched_match=None,
        )
        classified_findings.insert(0, target_clf)

    # Compute metric counts
    resolved_count = sum(1 for c in classified_findings if c.classification == FindingRegressionClassification.RESOLVED_BY_DEFINED_CHECKS)
    still_present_count = sum(1 for c in classified_findings if c.classification == FindingRegressionClassification.STILL_PRESENT)
    new_count = len(new_findings)
    unchanged_count = sum(1 for c in classified_findings if c.classification == FindingRegressionClassification.UNCHANGED)
    regressed_count = sum(1 for c in classified_findings if c.classification == FindingRegressionClassification.POTENTIALLY_REGRESSED)
    incomparable_count = sum(1 for c in classified_findings if c.classification == FindingRegressionClassification.INCOMPARABLE)

    return FindingComparisonResult(
        original_finding_status=target_status_compat,
        original_finding_classification=target_classification,
        original_finding_present_in_baseline=present_in_baseline,
        original_finding_present_in_patched=present_in_patched,
        new_findings=new_findings,
        classified_findings=classified_findings,
        resolved_findings_count=resolved_count,
        persisting_findings_count=still_present_count,
        new_findings_count=new_count,
        unchanged_findings_count=unchanged_count,
        potentially_regressed_findings_count=regressed_count,
        incomparable_findings_count=incomparable_count,
        total_baseline_findings=len(baseline_findings),
        total_patched_findings=len(patched_findings),
        reasons=reasons,
    )

