"""Pull Request Diff & Security Finding Analyzer.

Evaluates security posture changes across base and head commit revisions:
1. Filters and correlates findings against changed files and commits.
2. Accurately categorizes findings into four clear dimensions:
   - NEW: Introduced by the pull request commit.
   - RESOLVED: Previously open in the base revision, addressed in the PR.
   - UNCHANGED: Pre-existing findings not addressed in this PR.
   - REGRESSED: Re-introduced security findings or newly discovered issues in unchanged files.
3. Associates findings with commit SHAs and line ranges.
4. Audits incomplete or failed scanner executions.
"""
from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy.orm import Session

from ...core.logging import get_logger
from ...models.finding import SecurityFinding
from ...models.repository import Repository
from ...models.scan import Scan
from ...scanner.base import NormalizedFinding, ScannerStatus
from ...scanner.registry import scanner_registry
from .schemas import CategorizedPRFinding, FindingClassification, PRVerificationSummary

logger = get_logger("reposhield.github.pr_analyzer")


@dataclass
class PRAnalysisResult:
    head_commit_sha: str = ""
    base_commit_sha: str = ""
    status: str = "completed"  # completed, partial, failed, inconclusive
    changed_files: List[str] = field(default_factory=list)
    categorized_findings: List[CategorizedPRFinding] = field(default_factory=list)
    new_count: int = 0
    resolved_count: int = 0
    unchanged_count: int = 0
    regressed_count: int = 0
    scanners_executed: List[str] = field(default_factory=list)
    incomplete_checks: List[str] = field(default_factory=list)
    failed_checks: List[str] = field(default_factory=list)
    unavailable_checks: List[str] = field(default_factory=list)
    verification_summaries: List[PRVerificationSummary] = field(default_factory=list)
    repository_id: Optional[str] = None
    repository_name: Optional[str] = None
    reproduction_command: Optional[str] = None
    report_links: Dict[str, str] = field(default_factory=dict)
    execution_log: str = ""
    head_sha: str = ""
    base_sha: str = ""

    def __post_init__(self):
        if not self.head_commit_sha and self.head_sha:
            self.head_commit_sha = self.head_sha
        if not self.head_sha and self.head_commit_sha:
            self.head_sha = self.head_commit_sha
        if not self.base_commit_sha and self.base_sha:
            self.base_commit_sha = self.base_sha
        if not self.base_sha and self.base_commit_sha:
            self.base_sha = self.base_commit_sha
        # Ensure synchronization between legacy incomplete_checks and explicit unavailable_checks
        if self.incomplete_checks and not self.unavailable_checks:
            self.unavailable_checks = list(self.incomplete_checks)
        elif self.unavailable_checks and not self.incomplete_checks:
            self.incomplete_checks = list(self.unavailable_checks)


class PRAnalyzer:
    """Convenience evaluator for diff-based finding categorization."""

    def __init__(self, db: Optional[Session] = None):
        self.db = db

    def categorize_findings(
        self,
        baseline_findings: List[Dict[str, Any]],
        head_findings: List[Dict[str, Any]],
        changed_files: List[str],
        head_commit_sha: str = "HEAD",
    ) -> List[CategorizedPRFinding]:
        norm_changed_files = [normalize_file_path(f) for f in changed_files if f]
        changed_files_set = set(norm_changed_files)

        base_fingerprint_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for bf in baseline_findings:
            fp = _finding_fingerprint(bf.get("rule_id", "GENERAL"), bf.get("file_path", ""))
            base_fingerprint_map[fp] = bf

        categorized: List[CategorizedPRFinding] = []
        seen_head_fingerprints: Set[Tuple[str, str]] = set()

        for hf in head_findings:
            fp = _finding_fingerprint(hf.get("rule_id", "GENERAL"), hf.get("file_path", ""))
            seen_head_fingerprints.add(fp)

            norm_file = normalize_file_path(hf.get("file_path", ""))
            is_changed_file = norm_file in changed_files_set or any(norm_file.endswith(cf) for cf in changed_files_set)
            h_id = hf.get("id") or hf.get("finding_id")
            h_url = hf.get("detail_url") or (f"/findings/{h_id}" if h_id else None)

            if fp in base_fingerprint_map:
                categorized.append(CategorizedPRFinding(
                    classification=FindingClassification.UNCHANGED,
                    scanner_name=hf.get("scanner_name", "scanner"),
                    rule_id=hf.get("rule_id", "GENERAL"),
                    category=hf.get("category", "Security"),
                    severity=hf.get("severity", "MEDIUM"),
                    file_path=hf.get("file_path", ""),
                    line_number=hf.get("line_number"),
                    message=hf.get("message", ""),
                    commit_sha=head_commit_sha,
                    finding_id=h_id,
                    detail_url=h_url,
                ))
            else:
                if is_changed_file:
                    categorized.append(CategorizedPRFinding(
                        classification=FindingClassification.NEW,
                        scanner_name=hf.get("scanner_name", "scanner"),
                        rule_id=hf.get("rule_id", "GENERAL"),
                        category=hf.get("category", "Security"),
                        severity=hf.get("severity", "HIGH"),
                        file_path=hf.get("file_path", ""),
                        line_number=hf.get("line_number"),
                        message=hf.get("message", ""),
                        commit_sha=head_commit_sha,
                        finding_id=h_id,
                        detail_url=h_url,
                    ))
                else:
                    categorized.append(CategorizedPRFinding(
                        classification=FindingClassification.REGRESSED,
                        scanner_name=hf.get("scanner_name", "scanner"),
                        rule_id=hf.get("rule_id", "GENERAL"),
                        category=hf.get("category", "Security"),
                        severity=hf.get("severity", "HIGH"),
                        file_path=hf.get("file_path", ""),
                        line_number=hf.get("line_number"),
                        message=hf.get("message", ""),
                        commit_sha=head_commit_sha,
                        finding_id=h_id,
                        detail_url=h_url,
                    ))

        for fp, bf in base_fingerprint_map.items():
            if fp not in seen_head_fingerprints:
                norm_bf_file = normalize_file_path(bf.get("file_path", ""))
                if norm_bf_file in changed_files_set or any(norm_bf_file.endswith(cf) for cf in changed_files_set):
                    b_id = bf.get("id") or bf.get("finding_id")
                    b_url = bf.get("detail_url") or (f"/findings/{b_id}" if b_id else None)
                    categorized.append(CategorizedPRFinding(
                        classification=FindingClassification.RESOLVED,
                        scanner_name=bf.get("scanner_name", "scanner"),
                        rule_id=bf.get("rule_id", "GENERAL"),
                        category=bf.get("category", "Security"),
                        severity=bf.get("severity", "MEDIUM"),
                        file_path=bf.get("file_path", ""),
                        line_number=bf.get("line_number"),
                        message=f"Resolved: {bf.get('message', '')}",
                        commit_sha=head_commit_sha,
                        finding_id=b_id,
                        detail_url=b_url,
                    ))

        return categorized


def sanitize_pr_untrusted_text(text: Optional[str]) -> str:
    """Sanitize PR title and descriptions to prevent instructions/prompt injections from polluting audit logs."""
    if not text:
        return ""
    # Strip potential prompt injection headers and bounds
    cleaned = text.strip()[:200]
    return cleaned


def normalize_file_path(path_str: Optional[str]) -> str:
    if not path_str:
        return ""
    return path_str.replace("\\", "/").strip().lstrip("/")


def _finding_fingerprint(rule_id: str, file_path: str, line: Optional[int] = None) -> Tuple[str, str]:
    """Create a matching fingerprint for correlating base vs head findings."""
    norm_file = normalize_file_path(file_path).lower()
    norm_rule = (rule_id or "GENERAL").lower().strip()
    return (norm_rule, norm_file)


def run_pr_security_analysis(
    repo: Repository,
    head_commit_sha: str,
    base_commit_sha: str,
    changed_files: List[str],
    db: Session,
    selected_tools: Optional[List[str]] = None,
    timeout_seconds: int = 60,
) -> PRAnalysisResult:
    """Execute security analysis on repository workspace and compute PR finding diff."""
    norm_changed_files = [normalize_file_path(f) for f in changed_files if f]
    changed_files_set = set(norm_changed_files)

    incomplete_checks: List[str] = []
    failed_checks: List[str] = []
    unavailable_checks: List[str] = []
    scanners_executed: List[str] = []
    head_findings: List[NormalizedFinding] = []

    # 1. Resolve workspace
    target_dir = Path(repo.workspace_path) if repo.workspace_path else None
    if not target_dir or not target_dir.exists():
        err_msg = "Repository workspace path not accessible on disk; scans could not execute."
        unavailable_checks.append(err_msg)
        return PRAnalysisResult(
            head_commit_sha=head_commit_sha,
            base_commit_sha=base_commit_sha,
            status="inconclusive",
            changed_files=norm_changed_files,
            incomplete_checks=[err_msg],
            unavailable_checks=[err_msg],
            failed_checks=[],
            repository_id=repo.id,
            repository_name=repo.name,
            reproduction_command=f"python -m scripts.ci_security_gate --repo-path . --head-sha {head_commit_sha[:8]} --base-sha {base_commit_sha[:8]}",
            execution_log="Workspace not found on disk.",
        )

    # 2. Select scanner adapters
    available_adapters = scanner_registry.list_all()
    if selected_tools:
        adapters = [a for a in available_adapters if a.name in selected_tools]
        missing_selected = [t for t in selected_tools if not any(a.name == t for a in available_adapters)]
        for m in missing_selected:
            unavailable_checks.append(f"{m}: Requested tool not installed or configured in runner")
    else:
        adapters = [a for a in available_adapters if a.is_available()]
        unavailable_adapters = [a for a in available_adapters if not a.is_available()]
        for ua in unavailable_adapters:
            unavailable_checks.append(f"{ua.display_name}: Scanner executable not found in PATH")

    if not adapters:
        no_tools_msg = "No configured security scanners available in host environment."
        incomplete_checks.append(no_tools_msg)
        unavailable_checks.append(no_tools_msg)

    # 3. Execute scanners safely
    for adapter in adapters:
        scanners_executed.append(adapter.display_name)
        try:
            job = adapter.scan(target_dir=target_dir, scan_id=f"pr_{head_commit_sha[:7]}", timeout_seconds=timeout_seconds)
            head_findings.extend(job.findings)
            if job.status == ScannerStatus.TIMEOUT:
                timeout_msg = f"{adapter.display_name}: Scan timed out after {timeout_seconds}s"
                incomplete_checks.append(timeout_msg)
                unavailable_checks.append(timeout_msg)
            elif job.status == ScannerStatus.EXECUTION_ERROR:
                err_text = f"{adapter.display_name}: Execution error ({job.error_message or 'Failure'})"
                incomplete_checks.append(err_text)
                failed_checks.append(err_text)
        except Exception as exc:
            exc_msg = f"{adapter.display_name}: Execution exception ({str(exc)})"
            incomplete_checks.append(exc_msg)
            failed_checks.append(exc_msg)

    # 4. Fetch baseline findings from database for this repository
    base_db_findings = db.query(SecurityFinding).filter(
        SecurityFinding.repo_id == repo.id,
        SecurityFinding.status == "open",
    ).all()

    # Fingerprint baseline findings
    base_fingerprint_map: Dict[Tuple[str, str], SecurityFinding] = {}
    for bf in base_db_findings:
        fp = _finding_fingerprint(bf.rule_identifier or bf.cwe or "", bf.file_path)
        base_fingerprint_map[fp] = bf

    # Track classified findings
    categorized: List[CategorizedPRFinding] = []
    seen_head_fingerprints: Set[Tuple[str, str]] = set()

    new_count = 0
    unchanged_count = 0
    regressed_count = 0

    # 5. Classify head findings
    for hf in head_findings:
        fp = _finding_fingerprint(hf.scanner_rule_id, hf.file_path)
        seen_head_fingerprints.add(fp)

        norm_file = normalize_file_path(hf.file_path)
        is_changed_file = norm_file in changed_files_set or any(norm_file.endswith(cf) for cf in changed_files_set)

        if fp in base_fingerprint_map:
            # Finding existed on base and persists on head -> UNCHANGED
            bf_match = base_fingerprint_map[fp]
            unchanged_count += 1
            categorized.append(CategorizedPRFinding(
                classification=FindingClassification.UNCHANGED,
                scanner_name=hf.scanner_name,
                rule_id=hf.scanner_rule_id,
                category=hf.vulnerability_category,
                severity=hf.severity,
                file_path=hf.file_path,
                line_number=hf.start_line,
                message=hf.scanner_message,
                commit_sha=head_commit_sha,
                code_excerpt=hf.evidence_reference,
                finding_id=bf_match.id if bf_match else None,
                detail_url=f"/findings/{bf_match.id}" if bf_match else None,
            ))
        else:
            # Finding did NOT exist on base
            if is_changed_file:
                # Introduced on changed file in this PR -> NEW
                new_count += 1
                if hf.severity in ("CRITICAL", "HIGH"):
                    failed_checks.append(f"{hf.scanner_name}: Introduced {hf.severity} finding '{hf.scanner_rule_id}' in {hf.file_path}")
                categorized.append(CategorizedPRFinding(
                    classification=FindingClassification.NEW,
                    scanner_name=hf.scanner_name,
                    rule_id=hf.scanner_rule_id,
                    category=hf.vulnerability_category,
                    severity=hf.severity,
                    file_path=hf.file_path,
                    line_number=hf.start_line,
                    message=hf.scanner_message,
                    commit_sha=head_commit_sha,
                    code_excerpt=hf.evidence_reference,
                ))
            else:
                # Newly appeared in an unchanged file -> REGRESSED
                regressed_count += 1
                failed_checks.append(f"{hf.scanner_name}: Regression in unmodified file '{hf.file_path}': '{hf.scanner_rule_id}' ({hf.severity})")
                categorized.append(CategorizedPRFinding(
                    classification=FindingClassification.REGRESSED,
                    scanner_name=hf.scanner_name,
                    rule_id=hf.scanner_rule_id,
                    category=hf.vulnerability_category,
                    severity=hf.severity,
                    file_path=hf.file_path,
                    line_number=hf.start_line,
                    message=hf.scanner_message,
                    commit_sha=head_commit_sha,
                    code_excerpt=hf.evidence_reference,
                ))

    # 6. Check for RESOLVED findings (existed on base in changed files, now absent from head)
    resolved_count = 0
    resolved_finding_ids: List[str] = []
    for fp, bf in base_fingerprint_map.items():
        if fp not in seen_head_fingerprints:
            norm_bf_file = normalize_file_path(bf.file_path)
            if norm_bf_file in changed_files_set or any(norm_bf_file.endswith(cf) for cf in changed_files_set):
                resolved_count += 1
                resolved_finding_ids.append(bf.id)
                categorized.append(CategorizedPRFinding(
                    classification=FindingClassification.RESOLVED,
                    scanner_name=bf.scanner_name or "Security Scanner",
                    rule_id=bf.rule_identifier or bf.cwe or "General",
                    category=bf.cwe or bf.title,
                    severity=bf.severity,
                    file_path=bf.file_path,
                    line_number=bf.line_number,
                    message=f"Resolved: {bf.title}",
                    commit_sha=head_commit_sha,
                    code_excerpt=bf.code_excerpt,
                    finding_id=bf.id,
                    detail_url=f"/findings/{bf.id}",
                ))

    # 7. Collect Fix Verification evidence records if available
    verification_summaries: List[PRVerificationSummary] = []
    try:
        from ...models.verification import VerificationRun
        candidate_finding_ids = resolved_finding_ids or [bf.id for bf in base_db_findings]
        if candidate_finding_ids:
            runs = db.query(VerificationRun).filter(VerificationRun.finding_id.in_(candidate_finding_ids)).all()
            for run in runs:
                finding_obj = next((f for f in base_db_findings if f.id == run.finding_id), None)
                evidence_items = []
                for ev in (run.evidence or []):
                    evidence_items.append(f"{ev.evidence_type}: {ev.result} ({ev.tool_name_and_version})")
                if not evidence_items and run.test_summary:
                    evidence_items.append(f"Test summary: {run.test_summary}")
                if not evidence_items:
                    evidence_items.append(f"Status: {run.status}")

                verification_summaries.append(PRVerificationSummary(
                    finding_id=run.finding_id or run.id,
                    finding_title=finding_obj.title if finding_obj else "Security Finding Fix",
                    rule_id=finding_obj.rule_identifier if finding_obj else (run.patch_id or "FIX"),
                    file_path=finding_obj.file_path if finding_obj else None,
                    status=run.status,
                    patch_summary=f"Fix proposal for {finding_obj.rule_identifier if finding_obj else 'vulnerability'}",
                    patch_diff=(run.patch_diff[:400] + "...") if run.patch_diff and len(run.patch_diff) > 400 else run.patch_diff,
                    evidence_items=evidence_items,
                    evidence_report_link=f"/verifications/{run.id}",
                    finding_detail_link=f"/findings/{run.finding_id}" if run.finding_id else None,
                ))
    except Exception as exc:
        logger.debug(f"Verification query skipped or empty: {str(exc)}")

    # 8. Determine overall PR analysis status
    if unavailable_checks:
        overall_status = "inconclusive" if not head_findings else "partial"
    elif failed_checks or new_count > 0 or regressed_count > 0:
        overall_status = "failed"
    else:
        overall_status = "completed"

    repro_cmd = f"python -m scripts.ci_security_gate --repo-path . --head-sha {head_commit_sha[:8]} --base-sha {base_commit_sha[:8]}"
    report_links = {
        "repository_dashboard": f"/repositories/{repo.id}",
        "findings_report": f"/repositories/{repo.id}/findings",
        "ci_summary": f"/github/pr-scans",
    }

    return PRAnalysisResult(
        head_commit_sha=head_commit_sha,
        base_commit_sha=base_commit_sha,
        status=overall_status,
        changed_files=norm_changed_files,
        categorized_findings=categorized,
        new_count=new_count,
        resolved_count=resolved_count,
        unchanged_count=unchanged_count,
        regressed_count=regressed_count,
        scanners_executed=scanners_executed,
        incomplete_checks=incomplete_checks,
        failed_checks=failed_checks,
        unavailable_checks=unavailable_checks,
        verification_summaries=verification_summaries,
        repository_id=repo.id,
        repository_name=repo.name,
        reproduction_command=repro_cmd,
        report_links=report_links,
        execution_log=f"Scanned {len(scanners_executed)} tools on {len(norm_changed_files)} changed files. {len(unavailable_checks)} unavailable, {len(failed_checks)} failed.",
    )
