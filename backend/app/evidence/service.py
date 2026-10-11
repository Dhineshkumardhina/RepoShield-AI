"""Evidence management service handling storage, tenant isolation, and report generation."""
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from ..core.audit import record_audit_event
from ..core.auth import verify_repository_ownership
from ..core.errors import NotFoundError, SecurityPolicyViolationError
from ..models.evidence import SecurityEvidence
from ..models.finding import SecurityFinding
from ..models.repository import Repository
from ..models.scan import Scan
from ..models.user import User
from ..models.verification import VerificationRun
from ..prioritization.evaluator import evaluate_finding_risk
from .sanitizer import (
    compute_evidence_hash,
    sanitize_evidence_text,
    sanitize_payload,
    verify_evidence_integrity,
)
from .schemas import (
    AUTHENTICITY_DISCLAIMER,
    EvidenceIntegrityResponse,
    EvidenceIntegrityStatus,
    ReportExportFormat,
    SecurityReportResponse,
    VerificationRunIntegrityResponse,
)



def record_security_evidence(
    db: Session,
    repository_id: str,
    evidence_category: str,
    title: str,
    tool_name: str,
    raw_payload: Any,
    tool_version: Optional[str] = None,
    scan_id: Optional[str] = None,
    verification_run_id: Optional[str] = None,
    finding_id: Optional[str] = None,
    provenance: str = "scanner_observed",
    checks_not_performed: Optional[List[str]] = None,
) -> SecurityEvidence:
    """Stores an evidence record with secret scrubbing and SHA-256 hashing."""
    sanitized = sanitize_payload(raw_payload)
    content_hash = compute_evidence_hash(sanitized)
    
    checks_str = json.dumps(checks_not_performed) if checks_not_performed else None

    evidence = SecurityEvidence(
        repository_id=repository_id,
        scan_id=scan_id,
        verification_run_id=verification_run_id,
        finding_id=finding_id,
        evidence_category=evidence_category,
        title=title,
        provenance=provenance,
        tool_name=tool_name,
        tool_version=tool_version,
        content_hash=content_hash,
        sanitized_payload=sanitized,
        checks_not_performed=checks_str,
        recorded_at=datetime.now(timezone.utc),
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence


def get_evidence_by_id(db: Session, evidence_id: str, current_user: User) -> SecurityEvidence:
    """Retrieves an evidence record ensuring repository ownership."""
    evidence = db.query(SecurityEvidence).filter(SecurityEvidence.id == evidence_id).first()
    if not evidence:
        raise NotFoundError("EvidenceRecord", evidence_id)
    
    repo = db.query(Repository).filter(Repository.id == evidence.repository_id).first()
    if not repo:
        raise NotFoundError("Repository", evidence.repository_id)
    if repo.owner_id != current_user.id:
        raise SecurityPolicyViolationError("Access denied: You do not own the repository associated with this evidence.")
    
    return evidence


def list_repository_evidence(
    db: Session,
    repository_id: str,
    current_user: User,
    category: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
) -> List[SecurityEvidence]:
    """Lists evidence records for a repository enforcing ownership."""
    verify_repository_ownership(repo_id=repository_id, current_user=current_user, db=db)
    
    query = db.query(SecurityEvidence).filter(SecurityEvidence.repository_id == repository_id)
    if category:
        query = query.filter(SecurityEvidence.evidence_category == category)
    
    return query.order_by(SecurityEvidence.recorded_at.desc()).offset(skip).limit(limit).all()


def verify_evidence_record_integrity(
    db: Session,
    evidence_id: str,
    current_user: User,
) -> EvidenceIntegrityResponse:
    """Detects accidental alterations of a SecurityEvidence artifact using content hashing."""
    evidence = get_evidence_by_id(db, evidence_id, current_user)
    
    computed_hash = compute_evidence_hash(evidence.sanitized_payload)
    is_intact = verify_evidence_integrity(evidence.content_hash, evidence.sanitized_payload)
    status = EvidenceIntegrityStatus.VALID if is_intact else EvidenceIntegrityStatus.MODIFIED

    record_audit_event(
        db=db,
        action="EVIDENCE_INTEGRITY_CHECKED" if is_intact else "EVIDENCE_TAMPER_DETECTED",
        resource_type="evidence",
        resource_identifier=evidence.id,
        actor_id=current_user.id,
        metadata={
            "repo_id": evidence.repository_id,
            "status": status.value,
            "stored_hash": evidence.content_hash,
            "computed_hash": computed_hash,
        },
    )

    return EvidenceIntegrityResponse(
        evidence_id=evidence.id,
        repository_id=evidence.repository_id,
        status=status,
        stored_hash=evidence.content_hash,
        computed_hash=computed_hash,
        is_intact=is_intact,
    )


def verify_verification_run_integrity(
    db: Session,
    verification_run_id: str,
    current_user: User,
) -> VerificationRunIntegrityResponse:
    """Detects accidental alterations of a VerificationRun record using content hashing."""
    run = db.query(VerificationRun).filter(VerificationRun.id == verification_run_id).first()
    if not run:
        raise NotFoundError("VerificationRun", verification_run_id)

    finding = db.query(SecurityFinding).filter(SecurityFinding.id == run.finding_id).first()
    if not finding:
        raise NotFoundError("SecurityFinding", run.finding_id or "unknown")

    repo = verify_repository_ownership(repo_id=finding.repo_id, current_user=current_user, db=db)

    tests_executed = json.loads(run.tests_executed) if run.tests_executed else []
    new_findings = json.loads(run.new_findings) if run.new_findings else []
    reasons = json.loads(run.reasons) if run.reasons else []

    integrity_payload = {
        "run_id": run.id,
        "finding_id": run.finding_id,
        "status": run.status,
        "baseline_hash": run.baseline_hash,
        "patched_hash": run.patched_hash,
        "source_revision": run.source_revision,
        "target_revision": run.target_revision,
        "tests_executed": sorted(tests_executed),
        "original_finding_status": run.original_finding_status,
        "new_findings_count": len(new_findings),
        "reasons_count": len(reasons),
    }
    computed_hash = compute_evidence_hash(json.dumps(integrity_payload, sort_keys=True))

    if not run.integrity_hash:
        status = EvidenceIntegrityStatus.MISSING_HASH
        is_intact = False
    elif run.integrity_hash.lower() == computed_hash.lower():
        status = EvidenceIntegrityStatus.VALID
        is_intact = True
    else:
        status = EvidenceIntegrityStatus.MODIFIED
        is_intact = False

    record_audit_event(
        db=db,
        action="EVIDENCE_INTEGRITY_CHECKED" if is_intact else "EVIDENCE_TAMPER_DETECTED",
        resource_type="verification_run",
        resource_identifier=run.id,
        actor_id=current_user.id,
        metadata={
            "repo_id": repo.id,
            "status": status.value,
            "stored_hash": run.integrity_hash,
            "computed_hash": computed_hash,
        },
    )

    return VerificationRunIntegrityResponse(
        verification_run_id=run.id,
        finding_id=run.finding_id,
        status=status,
        stored_hash=run.integrity_hash,
        computed_hash=computed_hash,
        is_intact=is_intact,
    )


def generate_findings_report(

    db: Session,
    repository_id: str,
    current_user: User,
    format: ReportExportFormat = ReportExportFormat.MARKDOWN,
) -> SecurityReportResponse:
    """Generates an auditable Security Findings Report."""
    if isinstance(format, str):
        try:
            format = ReportExportFormat(format.lower())
        except ValueError:
            format = ReportExportFormat.MARKDOWN

    repo = verify_repository_ownership(repo_id=repository_id, current_user=current_user, db=db)

    
    findings = db.query(SecurityFinding).filter(SecurityFinding.repo_id == repository_id).all()
    latest_scan = (
        db.query(Scan)
        .filter(Scan.repository_id == repository_id)
        .order_by(Scan.started_at.desc())
        .first()
    )
    
    # Assess contextual risk for every finding
    assessments = [evaluate_finding_risk(f, db) for f in findings]
    
    # Standard identified checks not performed across scanners
    checks_not_performed = [
        "Dynamic Runtime Taint Analysis (DAST): Not configured in this static analysis pipeline.",
        "Interactive Application Security Testing (IAST): No runtime server agent attached.",
        "Production Database Privilege Auditing: Database credential permissions unverified.",
    ]
    
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    if format == ReportExportFormat.JSON:
        report_data = {
            "report_title": f"RepoShield AI Security Findings Report — {repo.name}",
            "repository_id": repo.id,
            "repository_name": repo.name,
            "generated_at": now_str,
            "scan_id": latest_scan.id if latest_scan else None,
            "summary": {
                "total_findings": len(findings),
                "critical": sum(1 for a in assessments if a.contextual_priority.value == "CRITICAL"),
                "high": sum(1 for a in assessments if a.contextual_priority.value == "HIGH"),
                "medium": sum(1 for a in assessments if a.contextual_priority.value == "MEDIUM"),
                "low": sum(1 for a in assessments if a.contextual_priority.value == "LOW"),
            },
            "checks_not_performed": checks_not_performed,
            "findings": [
                {
                    "finding_id": f.id,
                    "title": f.title,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "original_scanner_severity": a.original_scanner_severity,
                    "repshield_contextual_priority": a.contextual_priority.value,
                    "priority_score": a.priority_score,
                    "evidence_completeness": a.evidence_completeness.value,
                    "verification_status": a.verification_status,
                    "sensitive_data_involved": a.sensitive_data_involved,
                    "reachability_evidence": a.reachability_evidence,
                    "code_excerpt": f.code_excerpt,
                    "scoring_factors": [factor.model_dump() for factor in a.factors],
                    "missing_context": a.missing_context,
                }
                for f, a in zip(findings, assessments)
            ],
            "methodology_notice": (
                "Content hashes assist in detecting accidental changes but do not alone prove authenticity or original provenance. "
                "Numerical priority scores represent contextual triage indices and are not validated probabilities of real-world exploitation."
            ),
        }
        content_str = json.dumps(report_data, indent=2)
    else:
        # Markdown generation
        lines = [
            f"# RepoShield AI — Security Findings Report",
            f"**Repository:** `{repo.name}` (`{repo.id}`)",
            f"**Generated At:** {now_str}",
            f"**Default Branch:** `{repo.default_branch}` | **Languages:** {repo.language_metadata or 'Python'}",
            "",
            "## 1. Executive Summary & Prioritization Overview",
            "",
            f"Total Findings Identified: **{len(findings)}**",
            "",
            "| Finding ID | Title | Scanner Severity | RepoShield Contextual Priority | Priority Score | Evidence Completeness | Verification Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        
        for f, a in zip(findings, assessments):
            lines.append(
                f"| `{f.id}` | {f.title} | **{a.original_scanner_severity}** | **{a.contextual_priority.value}** | {a.priority_score}/100 | `{a.evidence_completeness.value}` | `{a.verification_status}` |"
            )
        
        lines.extend([
            "",
            "---",
            "",
            "## 2. Granular Evidence & Provenance Breakdown",
            "",
            "> [!NOTE]",
            "> Scanner observations reflect verified AST or dependency findings. AI commentary is demarcated as advisory only.",
            "",
        ])
        
        for f, a in zip(findings, assessments):
            lines.extend([
                f"### Finding `{f.id}`: {f.title}",
                f"- **Location:** `{f.file_path}:{f.line_number}`",
                f"- **Scanner Engine:** `{f.scanner_name}` (`{f.rule_identifier}`)",
                f"- **Original Severity:** `{a.original_scanner_severity}` &rarr; **Contextual Priority:** `{a.contextual_priority.value}` (Score: {a.priority_score}/100)",
                f"- **Evidence Completeness:** `{a.evidence_completeness.value}`",
                f"- **Sensitive Data Involved:** {'Yes (Confirmed Credentials/PII Pattern)' if a.sensitive_data_involved else 'No / Unproven'}",
                f"- **Reachability Posture:** `{a.reachability_evidence}`",
                f"- **Verification Status:** `{a.verification_status}`",
                "",
                "**[SCANNER EVIDENCE EXCERPT]**",
                "```",
                f"{f.code_excerpt or 'No code excerpt recorded by scanner.'}",
                "```",
                "",
                "**Traceable Scoring Factors:**",
            ])
            for factor in a.factors:
                lines.append(f"- **{factor.name}** ({'+' if factor.impact >= 0 else ''}{factor.impact}): {factor.rationale}")
            
            if a.missing_context:
                lines.append("")
                lines.append("**Missing Context / Limitations:**")
                for mc in a.missing_context:
                    lines.append(f"- *{mc}*")
            
            lines.append("")

        lines.extend([
            "---",
            "",
            "## 3. Checks Not Performed",
            "",
            "The following security verification checks were NOT performed during this assessment:",
        ])
        for cnp in checks_not_performed:
            lines.append(f"- [ ] {cnp}")

        lines.extend([
            "",
            "---",
            "",
            "## 4. Governance & Threat Model Limitations",
            "",
            "> [!CAUTION]",
            "> 1. A scanner finding disappearing does not prove that the vulnerability is impossible.",
            "> 2. Passing tests do not prove complete security.",
            "> 3. Content hashes assist in detecting accidental alterations but do not alone prove authenticity or original provenance.",
            "> 4. Numerical priority scores represent contextual triage indices and are **not** validated mathematical probabilities of exploitation.",
            "> 5. Never claim universal security or mathematically proven correctness.",
            "",
            f"*Report generated by RepoShield AI Security Engine v1.0.0*",
        ])
        content_str = "\n".join(lines)

    return SecurityReportResponse(
        report_title=f"Security Findings Report — {repo.name}",
        repository_id=repo.id,
        format=format,
        generated_at=now_str,
        content=content_str,
        metadata={"total_findings": len(findings)},
    )


def _generate_sarif_verification_report(
    run: VerificationRun,
    finding: SecurityFinding,
    repo: Repository,
    scanner_metadata: Dict[str, Any],
    scanner_config: Dict[str, Any],
    tests_executed: List[str],
    test_results: Dict[str, Any],
    findings_before: List[Dict[str, Any]],
    findings_after: List[Dict[str, Any]],
    new_findings: List[Dict[str, Any]],
    reasons: List[str],
    all_missing_checks: List[str],
    evidence_refs: List[str],
    ai_interpretation: Optional[str],
    now_str: str,
) -> str:
    """Builds standard OASIS SARIF 2.1.0 output for verification runs."""
    rule_id = finding.rule_identifier or "SECURITY-RULE"
    rules = [
        {
            "id": rule_id,
            "name": finding.title or "Target Security Finding",
            "shortDescription": {"text": finding.title or "Security finding under verification"},
            "fullDescription": {"text": f"Original scanner rule {rule_id} detected by {finding.scanner_name or 'scanner'}."},
            "defaultConfiguration": {"level": "error" if finding.severity == "CRITICAL" else "warning"},
        }
    ]

    results = [
        {
            "ruleId": rule_id,
            "level": "error" if run.original_finding_status != "resolved" else "note",
            "message": {
                "text": (
                    f"Original finding '{finding.title}' verification status: {run.original_finding_status.upper()}. "
                    f"Final verification verdict: {run.status}."
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file_path or "src/app.py"},
                        "region": {"startLine": finding.line_number or 1},
                    }
                }
            ],
            "properties": {
                "finding_id": finding.id,
                "original_finding_status": run.original_finding_status,
                "final_verification_status": run.status,
                "scanner_name": finding.scanner_name,
            },
        }
    ]

    for nf in new_findings:
        nf_rule = nf.get("rule_id", "REGRESSION-RULE")
        results.append({
            "ruleId": nf_rule,
            "level": "error",
            "message": {"text": f"New security finding / regression introduced by proposed patch: {nf.get('message', 'Regression detected')}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": nf.get("file_path", "unknown")},
                        "region": {"startLine": nf.get("line_number", 1)},
                    }
                }
            ],
            "properties": {"is_regression": True},
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RepoShield AI Fix Verification Engine",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/reposhield/reposhield-ai",
                        "rules": rules,
                    }
                },
                "artifacts": [
                    {
                        "location": {"uri": finding.file_path or "src/app.py"},
                        "description": {"text": "Target file evaluated for proposed security patch"},
                    }
                ],
                "results": results,
                "properties": {
                    "verification_run_id": run.id,
                    "repository_id": repo.id,
                    "repository_name": repo.name,
                    "source_revision": run.source_revision or repo.default_branch or "main",
                    "target_revision": run.target_revision,
                    "final_verification_status": run.status,
                    "explanation": reasons,
                    "scanner_names_and_versions": scanner_metadata,
                    "scanner_configuration": scanner_config,
                    "tests_executed": tests_executed,
                    "test_results": test_results,
                    "findings_before_count": len(findings_before),
                    "findings_after_count": len(findings_after),
                    "new_findings_detected": len(new_findings),
                    "missing_or_unavailable_checks": all_missing_checks,
                    "evidence_references": evidence_refs,
                    "raw_evidence": {
                        "baseline_hash": run.baseline_hash,
                        "patched_hash": run.patched_hash,
                        "patch_diff": sanitize_evidence_text(run.patch_diff or ""),
                        "test_summary": run.test_summary,
                    },
                    "ai_interpretation": ai_interpretation,
                    "authenticity_disclaimer": AUTHENTICITY_DISCLAIMER,
                    "generated_at": now_str,
                },
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)


def generate_verification_report(
    db: Session,
    verification_run_id: str,
    current_user: User,
    format: ReportExportFormat = ReportExportFormat.MARKDOWN,
) -> SecurityReportResponse:
    """Generates an auditable Fix Verification Report identifying all 14 mandatory traceability fields."""
    if isinstance(format, str):
        try:
            format = ReportExportFormat(format.lower())
        except ValueError:
            format = ReportExportFormat.MARKDOWN

    run = db.query(VerificationRun).filter(VerificationRun.id == verification_run_id).first()

    if not run:
        raise NotFoundError("VerificationRun", verification_run_id)

    # Verify repository ownership through the finding
    finding = db.query(SecurityFinding).filter(SecurityFinding.id == run.finding_id).first()
    if not finding:
        raise NotFoundError("SecurityFinding", run.finding_id or "unknown")

    repo = verify_repository_ownership(repo_id=finding.repo_id, current_user=current_user, db=db)

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    started_at_str = run.started_at.strftime("%Y-%m-%d %H:%M:%S UTC") if run.started_at else now_str
    completed_at_str = run.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC") if run.completed_at else now_str

    # Parse and sanitize stored fields
    scanner_metadata = json.loads(run.scanner_metadata) if run.scanner_metadata else {}
    scanner_config = json.loads(run.scanner_config) if run.scanner_config else {}
    configuration_changes = json.loads(run.configuration_changes) if run.configuration_changes else {}
    tests_executed = json.loads(run.tests_executed) if run.tests_executed else []
    test_results = json.loads(run.test_results) if run.test_results else {}
    findings_before = json.loads(run.findings_before_patch) if run.findings_before_patch else []
    findings_after = json.loads(run.findings_after_patch) if run.findings_after_patch else []
    new_findings = json.loads(run.new_findings) if run.new_findings else []
    reasons = json.loads(run.reasons) if run.reasons else []
    missing_evidence = json.loads(run.missing_evidence) if run.missing_evidence else []
    evidence_references = json.loads(run.evidence_references) if run.evidence_references else []

    # Standard unavailable checks across verification pipeline
    standard_unavailable_checks = [
        "Runtime Dynamic Application Security Testing (DAST): Not configured in static analysis fix verification pipeline.",
        "Interactive Application Security Testing (IAST): No runtime server agent attached.",
        "Production Database Privilege & ACL Auditing: Live database credentials unverified.",
    ]
    all_missing_or_unavailable_checks = list(missing_evidence) + standard_unavailable_checks

    # Redact secrets from patch diff and any test logs
    sanitized_patch_diff = sanitize_evidence_text(run.patch_diff or "")
    source_revision = run.source_revision or repo.default_branch or "main"
    target_revision = run.target_revision or f"patch_{run.patched_hash[:12]}" if run.patched_hash else "patch_uncommitted"

    # Separate raw tool evidence from advisory AI interpretation
    raw_evidence_summary = {
        "baseline_content_hash": run.baseline_hash,
        "patched_content_hash": run.patched_hash,
        "patch_diff": sanitized_patch_diff,
        "raw_scanner_metadata": scanner_metadata,
        "raw_test_results": test_results,
        "test_summary": run.test_summary,
        "evidence_references": evidence_references,
    }
    ai_interpretation_text = run.ai_interpretation or (
        f"[ADVISORY AI INTERPRETATION - NON-AUTHORITATIVE]: Fix verification concluded with status {run.status}. "
        f"Original finding is marked {run.original_finding_status}. Reasons: {'; '.join(reasons) if reasons else 'Defined checks passed.'}"
    )

    if format == ReportExportFormat.SARIF:
        content_str = _generate_sarif_verification_report(
            run=run,
            finding=finding,
            repo=repo,
            scanner_metadata=scanner_metadata,
            scanner_config=scanner_config,
            tests_executed=tests_executed,
            test_results=test_results,
            findings_before=findings_before,
            findings_after=findings_after,
            new_findings=new_findings,
            reasons=reasons,
            all_missing_checks=all_missing_or_unavailable_checks,
            evidence_refs=evidence_references,
            ai_interpretation=ai_interpretation_text,
            now_str=now_str,
        )
    elif format == ReportExportFormat.JSON:
        report_data = {
            "report_title": f"RepoShield AI Fix Verification Report — {run.id}",
            "verification_run_id": run.id,
            "1_original_finding": {
                "id": finding.id,
                "title": finding.title,
                "scanner_name": finding.scanner_name,
                "rule_identifier": finding.rule_identifier,
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "original_severity": finding.severity,
                "status_after_patch": run.original_finding_status,
            },
            "2_repository_and_source_revision": {
                "repository_id": repo.id,
                "repository_name": repo.name,
                "source_revision": source_revision,
                "target_revision": target_revision,
            },
            "3_proposed_patch": sanitized_patch_diff,
            "4_scanner_names_and_versions": scanner_metadata,
            "5_scanner_configuration": {
                "active_config": scanner_config,
                "configuration_changes": configuration_changes,
            },
            "6_tests_executed": tests_executed,
            "7_test_results": test_results,
            "8_findings_before_and_after_patch": {
                "findings_before_count": len(findings_before),
                "findings_before": findings_before,
                "findings_after_count": len(findings_after),
                "findings_after": findings_after,
            },
            "9_new_findings_detected": {
                "count": len(new_findings),
                "findings": new_findings,
            },
            "10_missing_or_unavailable_checks": all_missing_or_unavailable_checks,
            "11_final_verification_status": run.status,
            "12_explanation_supporting_status": reasons,
            "13_timestamp": {
                "started_at": started_at_str,
                "completed_at": completed_at_str,
                "report_generated_at": now_str,
            },
            "14_relevant_evidence_references": evidence_references,
            "raw_evidence": raw_evidence_summary,
            "ai_interpretation": ai_interpretation_text,
            "authenticity_disclaimer": AUTHENTICITY_DISCLAIMER,
            "governance_limitations": [
                "A scanner finding disappearing does not prove that the vulnerability is impossible.",
                "Passing tests do not prove complete security.",
                "A patch may change code paths or trigger a different rule without fixing the underlying issue.",
                "Never claim universal security or mathematically proven correctness.",
            ],
        }
        content_str = json.dumps(report_data, indent=2)
    else:
        # Markdown generation covering all 14 mandatory fields with strict raw vs AI separation
        lines = [
            f"# RepoShield AI — Fix Verification Report",
            f"**Verification Run ID:** `{run.id}`",
            f"**Target Finding:** `{finding.id}` — *{finding.title}*",
            f"**Repository:** `{repo.name}` (`{repo.id}`)",
            f"**Verdict:** **{run.status}**",
            f"**Report Generated At:** {now_str}",
            "",
            "---",
            "",
            "## 1. Executive Summary & Verification Verdict",
            "",
            f"- **Final Verification Status:** `{run.status}`",
            f"- **Original Finding Persistence:** `{run.original_finding_status.upper()}`",
            f"- **Execution Window:** `{started_at_str}` to `{completed_at_str}`",
            f"- **Source Revision (Base):** `{source_revision}`",
            f"- **Target Revision (Patched):** `{target_revision}`",
            f"- **Baseline Content Hash (SHA-256):** `{run.baseline_hash or 'N/A'}`",
            f"- **Patched Content Hash (SHA-256):** `{run.patched_hash or 'N/A'}`",
            "",
            "### Status Explanation & Rationale:",
        ]
        for r in reasons:
            lines.append(f"- {r}")

        lines.extend([
            "",
            "---",
            "",
            "## 2. Target Finding Context",
            "",
            f"| Attribute | Value |",
            f"| :--- | :--- |",
            f"| Finding ID | `{finding.id}` |",
            f"| Title | {finding.title} |",
            f"| Scanner Engine | `{finding.scanner_name}` |",
            f"| Rule Identifier | `{finding.rule_identifier or 'N/A'}` |",
            f"| File Path & Line | `{finding.file_path}:{finding.line_number}` |",
            f"| Original Scanner Severity | **{finding.severity}** |",
            f"| Status in Patched Code | `{run.original_finding_status}` |",
            "",
            "---",
            "",
            "## 3. Scanners, Configurations & Test Execution",
            "",
            "### A. Scanner Names & Versions",
            "```json",
            json.dumps(scanner_metadata, indent=2),
            "```",
            "",
            "### B. Scanner Configuration & Changes",
            "```json",
            json.dumps({"active_config": scanner_config, "configuration_changes": configuration_changes}, indent=2),
            "```",
            "",
            "### C. Tests Executed & Results",
            f"- **Suites Executed:** {len(tests_executed)} suite(s)",
        ])
        for t in tests_executed:
            lines.append(f"  - `{t}`")

        lines.extend([
            f"- **Execution Summary:** {run.test_summary or 'Completed'}",
            "",
            "**Test Results Breakdown:**",
            "```json",
            json.dumps(test_results, indent=2),
            "```",
            "",
            "---",
            "",
            "## 4. Pre vs Post Patch Findings & Regression Analysis",
            "",
            f"- **Baseline Findings Observed:** {len(findings_before)}",
            f"- **Patched Findings Observed:** {len(findings_after)}",
            f"- **New Findings Detected (Regressions):** {len(new_findings)}",
        ])

        if new_findings:
            lines.extend([
                "",
                "> [!WARNING]",
                f"> **{len(new_findings)} new security regression(s) detected in the patched workspace!**",
                "```json",
                json.dumps(new_findings, indent=2),
                "```",
            ])
        else:
            lines.append("- *No new security defects or scanner regressions detected in patched code.*")

        lines.extend([
            "",
            "---",
            "",
            "## 5. Missing or Unavailable Checks",
            "",
            "The following checks were NOT performed or were unavailable during this verification run:",
        ])
        for muc in all_missing_or_unavailable_checks:
            lines.append(f"- [ ] {muc}")

        lines.extend([
            "",
            "---",
            "",
            "## 6. Authoritative Raw Tool Evidence",
            "",
            "> [!NOTE]",
            "> Raw tool evidence represents unaltered, objective machine observations from scanners, test harnesses, and git diffs.",
            "",
            "### Evaluated Patch Diff:",
            "```diff",
            sanitized_patch_diff or "No patch diff recorded.",
            "```",
            "",
            "### Relevant Evidence References:",
        ])
        if evidence_references:
            for ref in evidence_references:
                lines.append(f"- `{ref}`")
        else:
            lines.append("- *No external evidence reference IDs linked.*")

        lines.extend([
            "",
            "---",
            "",
            "## 7. AI-Generated Interpretation (Advisory Only - Non-Authoritative)",
            "",
            "> [!IMPORTANT]",
            "> **AI Interpretation Notice:** The commentary below is generated by an automated language model for contextual triage support. "
            "It is strictly advisory, non-authoritative, and does not replace human security code review.",
            "",
            f"{ai_interpretation_text}",
            "",
            "---",
            "",
            "## 8. Governance, Guardrails & Authenticity Disclaimer",
            "",
            "> [!CAUTION]",
            f"> **Authenticity Notice:** {AUTHENTICITY_DISCLAIMER}",
            ">",
            "> **Verification Guardrails:**",
            "> 1. A scanner finding disappearing does not prove that the vulnerability is impossible.",
            "> 2. Passing tests do not prove complete security.",
            "> 3. A patch may change code paths or trigger a different rule without fixing the underlying issue.",
            "> 4. Never claim universal security or mathematically proven correctness.",
            "",
            f"*Report generated by RepoShield AI Security Verification Engine v1.0.0*",
        ])
        content_str = "\n".join(lines)

    record_audit_event(
        db=db,
        action="VERIFICATION_REPORT_GENERATED",
        resource_type="verification_report",
        resource_identifier=run.id,
        actor_id=current_user.id,
        metadata={"repo_id": repo.id, "format": format.value, "status": run.status},
    )

    return SecurityReportResponse(
        report_title=f"Fix Verification Report — {run.id}",
        repository_id=repo.id,
        format=format,
        generated_at=now_str,
        content=content_str,
        metadata={
            "status": run.status,
            "finding_id": finding.id,
            "source_revision": source_revision,
            "target_revision": target_revision,
            "evidence_references_count": len(evidence_references),
        },
    )

