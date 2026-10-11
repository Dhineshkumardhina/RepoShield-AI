"""Pull Request Security Summary Generator and Gated Comment Publisher.

Enforces:
1. Gated publishing: Publishes to GitHub ONLY when repository owner explicitly enabled commenting.
2. Permission verification: Verifies 'pull_requests: write' permission prior to API calls.
3. Truth-in-evidence: Never reports clean/pass when checks failed, timed out, or were omitted.
4. Transparent breakdown of NEW, RESOLVED, UNCHANGED, and REGRESSED findings.
5. Clear identification of incomplete or skipped checks.
"""
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from ...core.errors import AppSecException, ForbiddenError, SecurityPolicyViolationError
from ...core.logging import get_logger
from .pr_analyzer import PRAnalysisResult
from .schemas import CategorizedPRFinding, FindingClassification

logger = get_logger("reposhield.github.publisher")


def generate_pr_summary_markdown(
    repo_name: str,
    pr_number: int,
    head_sha: str,
    analysis: PRAnalysisResult,
) -> str:
    """Format an actionable, transparent GitHub Pull Request security comment in Markdown."""
    base_sha_str = analysis.base_commit_sha or analysis.base_sha or "BASE"
    lines: List[str] = [
        f"## 🛡️ RepoShield AI — Security Analysis for PR #{pr_number}",
        f"**Repository:** `{repo_name}` | **Commit:** `{head_sha[:8]}` (`{head_sha}`) | **Base:** `{base_sha_str[:8]}` | **Status:** `{analysis.status.upper()}` | **Evaluated at:** `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`",
        "",
    ]

    # Summary metric badges
    verified_fixes_count = len(analysis.verification_summaries)
    lines.append(
        f"| 🚨 New Findings | ✅ Resolved Findings | ⚠️ Regressed | ℹ️ Unchanged | 🔬 Verified Fixes | Scanners Run |\n"
        f"| :---: | :---: | :---: | :---: | :---: | :---: |\n"
        f"| **{analysis.new_count}** | **{analysis.resolved_count}** | **{analysis.regressed_count}** | {analysis.unchanged_count} | **{verified_fixes_count}** | {len(analysis.scanners_executed)} |"
    )
    lines.append("")

    # Status verdict banner
    if analysis.new_count > 0 or analysis.regressed_count > 0:
        lines.append(
            "> [!CAUTION]\n"
            f"> **Security Risk Detected:** This pull request introduces **{analysis.new_count} new** "
            f"and **{analysis.regressed_count} regressed** security findings that should be reviewed before merging."
        )
    elif analysis.unavailable_checks or analysis.incomplete_checks:
        lines.append(
            "> [!WARNING]\n"
            "> **Scan Incomplete:** One or more configured security checks could not execute completely. "
            "Do NOT treat this summary as confirmation that changes are vulnerability-free."
        )
    elif analysis.failed_checks:
        lines.append(
            "> [!CAUTION]\n"
            "> **Security Checks Failed:** One or more required security checks failed during execution."
        )
    elif analysis.resolved_count > 0 and analysis.new_count == 0:
        lines.append(
            "> [!TIP]\n"
            f"> **Security Fixes Verified:** This PR successfully resolves **{analysis.resolved_count}** pre-existing finding(s) "
            "with zero new issues introduced on configured scanners."
        )
    else:
        lines.append(
            "> [!NOTE]\n"
            "> **No New Findings Detected:** Configured static analysis tools reported zero new findings on the modified files."
        )
    lines.append("")

    # Fix Verification & Evidence Section (Requirement 4)
    if analysis.verification_summaries:
        lines.append("### 🔬 Proposed Fixes & Verification Evidence")
        lines.append("Concrete verification evidence collected from candidate fix evaluation runs:\n")
        lines.append("| Target Vulnerability | Verification Status | Verification Evidence | Report |")
        lines.append("| :--- | :--- | :--- | :--- |")

        for v in analysis.verification_summaries:
            status_icon = "✅" if "VERIFIED" in v.status else "❌" if "FAILED" in v.status else "⚠️"
            v_title = v.finding_title or v.rule_id or "Security Fix"
            v_file = f"`{v.file_path}`" if v.file_path else "`Workspace`"
            evidence_str = "<br>".join([f"• {e}" for e in v.evidence_items]) if v.evidence_items else "Defined sandbox checks"
            report_link_str = f"[View Report]({v.evidence_report_link})" if v.evidence_report_link else "-"
            lines.append(f"| **{v_title}**<br>{v_file} | {status_icon} `{v.status}` | {evidence_str} | {report_link_str} |")
        lines.append("")

        # Patch diffs preview if available
        diffs_to_show = [v for v in analysis.verification_summaries if v.patch_diff]
        if diffs_to_show:
            lines.append("<details><summary>🔎 View Proposed Fix Unified Diffs</summary>\n")
            for v in diffs_to_show:
                lines.append(f"#### Fix for {v.finding_title or v.rule_id}")
                lines.append("```diff")
                lines.append(v.patch_diff.strip())
                lines.append("```\n")
            lines.append("</details>\n")

    # Detailed Findings Table
    if analysis.categorized_findings:
        lines.append("### 📋 Security Findings Detail")
        lines.append("| Status | Severity | Tool | Finding / Rule | File & Line | Link |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")

        for f in analysis.categorized_findings:
            icon = "🚨" if f.classification == FindingClassification.NEW else \
                   "✅" if f.classification == FindingClassification.RESOLVED else \
                   "⚠️" if f.classification == FindingClassification.REGRESSED else "ℹ️"
            line_str = f"L{f.line_number}" if f.line_number else "-"
            detail_link = f"[Details]({f.detail_url})" if f.detail_url else "-"
            lines.append(f"| {icon} {f.classification.value} | **{f.severity}** | {f.scanner_name} | `{f.rule_id}`: {f.message[:60]} | `{f.file_path}:{line_str}` | {detail_link} |")
        lines.append("")

    # Failed Checks (Requirement 8)
    if analysis.failed_checks:
        lines.append("### ❌ Failed Security Checks")
        lines.append("The following checks executed and reported security failures or policy violations:")
        for check in analysis.failed_checks:
            lines.append(f"- ❌ **{check}**")
        lines.append("")

    # Incomplete or Unavailable Checks (Requirement 8 - Omission Auditing)
    checks_missing = analysis.unavailable_checks or analysis.incomplete_checks
    if checks_missing:
        lines.append("### ⚠️ Checks Not Performed / Incomplete")
        lines.append("The following checks were omitted, unavailable, or timed out. **Do NOT assume code is vulnerability-free:**")
        for check in checks_missing:
            lines.append(f"- ⚠️ **{check}**")
        lines.append("")

    # Local Reproduction Guide (Requirement 9)
    lines.append("### 💻 Local Reproduction")
    lines.append("Developers can reproduce these scan and verification results locally before pushing commits:")
    repro_cmd = analysis.reproduction_command or f"python -m scripts.ci_security_gate --repo-path . --head-sha {head_sha[:8]} --base-sha {base_sha_str[:8]}"
    lines.append("```bash")
    lines.append(repro_cmd)
    lines.append("```")
    lines.append("*For full local setup and CLI flags, see [CI/CD Code Review Integration Guide](file:///docs/CI_CD_CODE_REVIEW_INTEGRATION.md).*")
    lines.append("")

    # Changed files audited
    if analysis.changed_files:
        lines.append(f"<details><summary>📁 Audited Files ({len(analysis.changed_files)})</summary>\n")
        for cf in analysis.changed_files:
            lines.append(f"- `{cf}`")
        lines.append("\n</details>\n")

    # Links to Complete Findings & Evidence Reports (Requirement 10)
    lines.append("### 🔗 Full Reports & Evidence Links")
    findings_url = analysis.report_links.get("findings_report", "/findings")
    lines.append(f"- 📋 [Complete Findings Dashboard]({findings_url})")
    lines.append("- 🔬 [Fix Verification Engine Framework](file:///docs/VERIFICATION.md)")
    lines.append("- 🛡️ [DevSecOps Integration Architecture](file:///docs/CI_CD_CODE_REVIEW_INTEGRATION.md)")
    lines.append("")

    # Disclaimer
    lines.append(
        "---  \n"
        "*Disclaimer: RepoShield AI analysis reflects static scanner results and targeted verification checks on supported file formats. "
        "Passing checks do not provide cryptographic mathematical proof of universal security or exploit impossibility. "
        "Automated merging or deploying of proposed fixes is strictly prohibited without explicit operator review.*"
    )

    return "\n".join(lines)


def can_publish_pr_summary(
    link_publish_toggle: bool,
    granted_permissions: Optional[Dict[str, str]],
) -> Tuple[bool, Optional[str]]:
    """Enforce operator consent and permission gating before posting comments to GitHub."""
    if not link_publish_toggle:
        return False, "Publishing disabled: Repository policy toggle 'publish_pr_comments' is False (read-only mode active)."

    if not granted_permissions:
        return False, "Publishing rejected: No GitHub permissions granted."

    pr_perm = granted_permissions.get("pull_requests", "none")
    if pr_perm != "write":
        return False, f"Publishing rejected: Missing 'pull_requests: write' permission (current: '{pr_perm}')."

    return True, None
