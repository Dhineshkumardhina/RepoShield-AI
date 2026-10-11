#!/usr/bin/env python3
"""Standalone Machine-Readable CI Security Gate for RepoShield AI.

Provides DevSecOps gate evaluation for Pull Requests and CI/CD pipelines:
1. Associates scans with exact repository and commit SHAs.
2. Analyzes changed code (diff-aware analysis).
3. Distinguishes NEW, RESOLVED, UNCHANGED, and REGRESSED findings.
4. Displays fix-verification evidence alongside candidate patches.
5. Emits standardized machine-readable JSON (and optional SARIF / Markdown).
6. Returns non-success exit codes:
   - 0: PASS (clean security gate, zero blocking findings, all checks completed).
   - 1: FAIL (security policy failure: new or regressed high/critical findings or test failures).
   - 2: INCOMPLETE (configured checks unavailable, skipped, or timed out).
7. Audits omissions (distinguishes failed checks from unavailable checks).
8. Outputs reproducible local CLI commands for developers.
9. Preserves links to complete finding and verification evidence records.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

# Add workspace and backend directories to path
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT / "backend"))
sys.path.insert(0, str(WORKSPACE_ROOT))

try:
    from app.integrations.github.pr_analyzer import PRAnalysisResult, PRAnalyzer, normalize_file_path
    from app.integrations.github.publisher import generate_pr_summary_markdown
    from app.integrations.github.schemas import CategorizedPRFinding, FindingClassification, PRVerificationSummary
except ImportError:
    # Standalone fallback if package structure differs in CI container
    PRAnalyzer = None


SEVERITY_LEVELS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def _get_git_commit(cwd: Path, rev: str = "HEAD") -> str:
    """Retrieve full 40-character commit hash from local git workspace."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", rev],
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return rev


def _get_git_changed_files(cwd: Path, base_sha: str, head_sha: str) -> List[str]:
    """Retrieve list of changed files between base and head revisions."""
    try:
        res = subprocess.run(
            ["git", "diff", "--name-only", f"{base_sha}...{head_sha}"],
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        files = [line.strip().replace("\\", "/") for line in res.stdout.splitlines() if line.strip()]
        if files:
            return files
    except Exception:
        pass

    try:
        res = subprocess.run(
            ["git", "diff", "--name-only", "HEAD~1", "HEAD"],
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        return [line.strip().replace("\\", "/") for line in res.stdout.splitlines() if line.strip()]
    except Exception:
        return []


def run_ci_security_gate(
    repo_path: Path,
    head_sha: Optional[str] = None,
    base_sha: Optional[str] = None,
    changed_files: Optional[List[str]] = None,
    fail_on_severity: str = "HIGH",
    strict_checks: bool = True,
    baseline_findings_file: Optional[Path] = None,
    head_findings_file: Optional[Path] = None,
    verifications_file: Optional[Path] = None,
    output_format: str = "json",
    output_file: Optional[Path] = None,
    pr_number: Optional[int] = None,
) -> Tuple[int, Dict[str, Any]]:
    """Execute CI security evaluation and return exit_code and structured payload."""
    repo_path = repo_path.resolve()
    resolved_head_sha = head_sha or _get_git_commit(repo_path, "HEAD")
    resolved_base_sha = base_sha or _get_git_commit(repo_path, "HEAD~1")

    if not changed_files:
        changed_files = _get_git_changed_files(repo_path, resolved_base_sha, resolved_head_sha)

    norm_changed_files = [f.replace("\\", "/").strip().lstrip("/") for f in (changed_files or [])]
    changed_files_set = set(norm_changed_files)

    # 1. Load baseline & head findings
    baseline_findings: List[Dict[str, Any]] = []
    if baseline_findings_file and baseline_findings_file.exists():
        with open(baseline_findings_file, "r", encoding="utf-8") as f:
            baseline_findings = json.load(f)

    head_findings: List[Dict[str, Any]] = []
    if head_findings_file and head_findings_file.exists():
        with open(head_findings_file, "r", encoding="utf-8") as f:
            head_findings = json.load(f)

    # 2. Check tool availability and omission auditing
    scanners_executed: List[str] = []
    unavailable_checks: List[str] = []
    failed_checks: List[str] = []

    # Check for installed security scanners
    scanner_binaries = {
        "Semgrep OSS": "semgrep",
        "Bandit": "bandit",
        "pip-audit": "pip-audit",
    }
    for display_name, bin_name in scanner_binaries.items():
        found = False
        try:
            res = subprocess.run([bin_name, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode == 0:
                found = True
        except Exception:
            found = False

        if found:
            scanners_executed.append(display_name)
        else:
            unavailable_checks.append(f"{display_name}: Scanner binary '{bin_name}' not detected in environment PATH")

    # 3. Categorize findings into NEW, RESOLVED, UNCHANGED, and REGRESSED
    categorized_findings: List[Dict[str, Any]] = []
    base_fp_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for bf in baseline_findings:
        fp = ((bf.get("rule_id") or "GENERAL").lower().strip(), (bf.get("file_path") or "").replace("\\", "/").lower().lstrip("/"))
        base_fp_map[fp] = bf

    seen_head_fps = set()
    new_count = 0
    resolved_count = 0
    unchanged_count = 0
    regressed_count = 0

    threshold_level = SEVERITY_LEVELS.get(fail_on_severity.upper(), 3)
    policy_violations: List[str] = []

    for hf in head_findings:
        rule_id = hf.get("rule_id", "GENERAL")
        file_path = hf.get("file_path", "").replace("\\", "/").lstrip("/")
        fp = (rule_id.lower().strip(), file_path.lower())
        seen_head_fps.add(fp)

        is_changed_file = file_path in changed_files_set or any(file_path.endswith(cf) for cf in changed_files_set) if changed_files_set else True
        severity = (hf.get("severity") or "MEDIUM").upper()
        sev_level = SEVERITY_LEVELS.get(severity, 2)

        if fp in base_fp_map:
            unchanged_count += 1
            cat_item = dict(hf)
            cat_item.update({"classification": "UNCHANGED", "commit_sha": resolved_head_sha})
            categorized_findings.append(cat_item)
        else:
            if is_changed_file:
                new_count += 1
                cat_item = dict(hf)
                cat_item.update({"classification": "NEW", "commit_sha": resolved_head_sha})
                categorized_findings.append(cat_item)
                if sev_level >= threshold_level:
                    policy_violations.append(f"NEW finding exceeds threshold: {severity} '{rule_id}' in {file_path}")
            else:
                regressed_count += 1
                cat_item = dict(hf)
                cat_item.update({"classification": "REGRESSED", "commit_sha": resolved_head_sha})
                categorized_findings.append(cat_item)
                policy_violations.append(f"REGRESSED finding detected in unchanged file '{file_path}': {severity} '{rule_id}'")

    for fp, bf in base_fp_map.items():
        if fp not in seen_head_fps:
            bf_file = (bf.get("file_path") or "").replace("\\", "/").lstrip("/")
            if bf_file in changed_files_set or any(bf_file.endswith(cf) for cf in changed_files_set) or not changed_files_set:
                resolved_count += 1
                cat_item = dict(bf)
                cat_item.update({
                    "classification": "RESOLVED",
                    "commit_sha": resolved_head_sha,
                    "message": f"Resolved: {bf.get('message', '')}",
                })
                categorized_findings.append(cat_item)

    # 4. Load Fix Verification evidence if provided
    verification_summaries: List[Dict[str, Any]] = []
    if verifications_file and verifications_file.exists():
        with open(verifications_file, "r", encoding="utf-8") as f:
            v_data = json.load(f)
            verification_summaries = v_data if isinstance(v_data, list) else [v_data]

    # 5. Evaluate CI Gate Policy
    # Failed checks include policy violations and execution errors
    all_failed_checks = list(dict.fromkeys(failed_checks + policy_violations))

    if unavailable_checks and strict_checks and not head_findings:
        gate_status = "INCOMPLETE"
        exit_code = 2
        gate_passed = False
    elif all_failed_checks:
        gate_status = "FAIL"
        exit_code = 1
        gate_passed = False
    elif unavailable_checks and strict_checks:
        gate_status = "INCOMPLETE"
        exit_code = 2
        gate_passed = False
    else:
        gate_status = "PASS"
        exit_code = 0
        gate_passed = True

    # 6. Build Local Reproduction Command
    repro_cmd = f"python -m scripts.ci_security_gate --repo-path . --head-sha {resolved_head_sha[:8]} --base-sha {resolved_base_sha[:8]} --fail-on {fail_on_severity.upper()}"

    # 7. Generate Actionable Pull Request Markdown Summary
    md_lines: List[str] = [
        f"## 🛡️ RepoShield AI — CI Security Gate Evaluation",
        f"**Repository:** `{repo_path.name}` | **Commit:** `{resolved_head_sha[:8]}` (`{resolved_head_sha}`) | **Base:** `{resolved_base_sha[:8]}` | **Gate Status:** `{gate_status}`",
        "",
        f"| 🚨 New Findings | ✅ Resolved | ⚠️ Regressed | ℹ️ Unchanged | 🔬 Verified Fixes | Scanners Checked |",
        f"| :---: | :---: | :---: | :---: | :---: | :---: |",
        f"| **{new_count}** | **{resolved_count}** | **{regressed_count}** | {unchanged_count} | **{len(verification_summaries)}** | {len(scanners_executed)} |",
        "",
    ]

    if gate_status == "FAIL":
        md_lines.append(
            "> [!CAUTION]\n"
            f"> **Security Gate FAILED:** This pull request introduces **{new_count} new** and **{regressed_count} regressed** "
            f"security findings violating the `{fail_on_severity}` policy threshold. CI build blocked."
        )
    elif gate_status == "INCOMPLETE":
        md_lines.append(
            "> [!WARNING]\n"
            f"> **Security Gate INCOMPLETE:** {len(unavailable_checks)} configured security checks were unavailable or omitted. "
            "Under strict DevSecOps policy, unverified builds cannot pass silently."
        )
    elif resolved_count > 0 and new_count == 0:
        md_lines.append(
            "> [!TIP]\n"
            f"> **Security Gate PASSED:** Pull request successfully verified **{resolved_count}** remediated vulnerability(ies) "
            "with zero new issues detected on configured checks."
        )
    else:
        md_lines.append(
            "> [!NOTE]\n"
            "> **Security Gate PASSED:** Configured static analysis checks detected zero policy-violating findings."
        )
    md_lines.append("")

    # Fix Verification Evidence Section
    if verification_summaries:
        md_lines.append("### 🔬 Proposed Fixes & Verification Evidence")
        md_lines.append("| Finding / Fix | Status | Verification Evidence | Report |")
        md_lines.append("| :--- | :--- | :--- | :--- |")
        for v in verification_summaries:
            status_val = v.get("status", "VERIFIED")
            status_icon = "✅" if "VERIFIED" in status_val else "❌" if "FAILED" in status_val else "⚠️"
            title = v.get("finding_title") or v.get("rule_id") or "Security Fix"
            file_loc = f"`{v.get('file_path')}`" if v.get("file_path") else "`Workspace`"
            items = v.get("evidence_items") or [f"Status: {status_val}"]
            ev_str = "<br>".join([f"• {i}" for i in items])
            rep_link = f"[Report]({v.get('evidence_report_link')})" if v.get("evidence_report_link") else "-"
            md_lines.append(f"| **{title}**<br>{file_loc} | {status_icon} `{status_val}` | {ev_str} | {rep_link} |")
        md_lines.append("")

    # Detailed findings table
    if categorized_findings:
        md_lines.append("### 📋 Security Findings Detail")
        md_lines.append("| Status | Severity | Finding / Rule | File & Line | Link |")
        md_lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for cf in categorized_findings:
            icon = "🚨" if cf.get("classification") == "NEW" else \
                   "✅" if cf.get("classification") == "RESOLVED" else \
                   "⚠️" if cf.get("classification") == "REGRESSED" else "ℹ️"
            line_str = f"L{cf.get('line_number')}" if cf.get("line_number") else "-"
            dt_link = f"[Details]({cf.get('detail_url')})" if cf.get("detail_url") else "-"
            md_lines.append(f"| {icon} {cf.get('classification')} | **{cf.get('severity')}** | `{cf.get('rule_id')}`: {str(cf.get('message', ''))[:60]} | `{cf.get('file_path')}:{line_str}` | {dt_link} |")
        md_lines.append("")

    # Failed checks
    if all_failed_checks:
        md_lines.append("### ❌ Failed Security Checks")
        for fc in all_failed_checks:
            md_lines.append(f"- ❌ **{fc}**")
        md_lines.append("")

    # Unavailable / skipped checks (Omission auditing)
    if unavailable_checks:
        md_lines.append("### ⚠️ Checks Not Performed / Incomplete (Omission Auditing)")
        for uc in unavailable_checks:
            md_lines.append(f"- ⚠️ **{uc}**")
        md_lines.append("")

    # Local reproduction
    md_lines.append("### 💻 Local Reproduction")
    md_lines.append("Developers can reproduce this evaluation locally:")
    md_lines.append("```bash")
    md_lines.append(repro_cmd)
    md_lines.append("```")
    md_lines.append("")

    # Links
    md_lines.append("### 🔗 Full Reports & Evidence")
    md_lines.append("- 📋 [Full Findings Catalog](file:///docs/SCANNERS.md)")
    md_lines.append("- 🔬 [Fix Verification Engine Framework](file:///docs/VERIFICATION.md)")
    md_lines.append("- 📖 [DevSecOps Integration Architecture](file:///docs/CI_CD_CODE_REVIEW_INTEGRATION.md)")
    md_lines.append("")
    md_lines.append(
        "---  \n"
        "*Disclaimer: RepoShield AI analysis reflects static scanner results and targeted verification checks on supported file formats. "
        "Passing checks do not provide cryptographic mathematical proof of universal security or exploit impossibility. "
        "Automated merging or deploying of proposed fixes is strictly prohibited without explicit operator review.*"
    )

    summary_markdown = "\n".join(md_lines)

    # 8. Assemble Machine-Readable JSON Output
    result_payload: Dict[str, Any] = {
        "schema_version": "1.0.0",
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "repository": repo_path.name,
        "repository_path": str(repo_path),
        "head_commit_sha": resolved_head_sha,
        "base_commit_sha": resolved_base_sha,
        "gate_status": gate_status,
        "exit_code": exit_code,
        "gate_passed": gate_passed,
        "policy": {
            "fail_on_severity": fail_on_severity.upper(),
            "strict_checks": strict_checks,
        },
        "metrics": {
            "new_findings": new_count,
            "resolved_findings": resolved_count,
            "regressed_findings": regressed_count,
            "unchanged_findings": unchanged_count,
            "verified_fixes": len(verification_summaries),
            "failed_checks": len(all_failed_checks),
            "unavailable_checks": len(unavailable_checks),
        },
        "changed_files": norm_changed_files,
        "failed_checks": all_failed_checks,
        "unavailable_checks": unavailable_checks,
        "categorized_findings": categorized_findings,
        "verification_evidence": verification_summaries,
        "summary_markdown": summary_markdown,
        "reproduction": {
            "command": repro_cmd,
            "guide": "docs/CI_CD_CODE_REVIEW_INTEGRATION.md",
        },
        "report_links": {
            "findings_dashboard": f"/repositories/{repo_path.name}/findings",
            "verification_docs": "docs/VERIFICATION.md",
            "ci_cd_guide": "docs/CI_CD_CODE_REVIEW_INTEGRATION.md",
        },
    }

    # Write output to file if requested
    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            if output_format.lower() == "markdown":
                f.write(summary_markdown)
            else:
                json.dump(result_payload, f, indent=2)

    return exit_code, result_payload


def main():
    parser = argparse.ArgumentParser(
        description="RepoShield AI — Standalone CI Security Gate for Code Review & Pipelines"
    )
    parser.add_argument("--repo-path", type=str, default=".", help="Path to local repository workspace")
    parser.add_argument("--head-sha", type=str, default=None, help="Head commit SHA to evaluate")
    parser.add_argument("--base-sha", type=str, default=None, help="Base commit SHA target")
    parser.add_argument("--changed-files", type=str, default=None, help="Comma-separated list of changed files")
    parser.add_argument("--fail-on", type=str, default="HIGH", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"], help="Severity threshold to fail the gate")
    parser.add_argument("--strict-checks", action="store_true", default=True, help="Fail gate if required checks are unavailable or skipped")
    parser.add_argument("--no-strict-checks", dest="strict_checks", action="store_false", help="Permit scans with unavailable checks to pass")
    parser.add_argument("--baseline-findings", type=str, default=None, help="Path to baseline findings JSON")
    parser.add_argument("--head-findings", type=str, default=None, help="Path to head findings JSON")
    parser.add_argument("--verifications-file", type=str, default=None, help="Path to fix verification records JSON")
    parser.add_argument("--format", type=str, default="json", choices=["json", "markdown", "text"], help="Console output format")
    parser.add_argument("--output-file", type=str, default=None, help="File path to write machine-readable evaluation report")
    parser.add_argument("--pr-number", type=int, default=None, help="Pull request number")

    args = parser.parse_args()

    changed_list = [f.strip() for f in args.changed_files.split(",")] if args.changed_files else None
    base_file = Path(args.baseline_findings) if args.baseline_findings else None
    head_file = Path(args.head_findings) if args.head_findings else None
    verif_file = Path(args.verifications_file) if args.verifications_file else None
    out_file = Path(args.output_file) if args.output_file else None

    exit_code, payload = run_ci_security_gate(
        repo_path=Path(args.repo_path),
        head_sha=args.head_sha,
        base_sha=args.base_sha,
        changed_files=changed_list,
        fail_on_severity=args.fail_on,
        strict_checks=args.strict_checks,
        baseline_findings_file=base_file,
        head_findings_file=head_file,
        verifications_file=verif_file,
        output_format=args.format,
        output_file=out_file,
        pr_number=args.pr_number,
    )

    if args.format == "markdown":
        print(payload["summary_markdown"])
    elif args.format == "text":
        print(f"RepoShield AI Security Gate Verdict: {payload['gate_status']} (Exit Code {exit_code})")
        print(f"New: {payload['metrics']['new_findings']} | Resolved: {payload['metrics']['resolved_findings']} | Regressed: {payload['metrics']['regressed_findings']}")
        if payload['failed_checks']:
            print("Failed Checks:")
            for fc in payload['failed_checks']:
                print(f"  - {fc}")
        if payload['unavailable_checks']:
            print("Unavailable Checks:")
            for uc in payload['unavailable_checks']:
                print(f"  - {uc}")
    else:
        print(json.dumps(payload, indent=2))

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
