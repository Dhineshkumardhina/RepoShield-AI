"""Scan orchestrator and execution engine.

Coordinates execution of real security scanner adapters against repository workspaces,
persists normalized security findings, recalculates repository health score, and
logs audit events with full execution provenance.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from .base import ScannerStatus
from .registry import scanner_registry
from ..core.audit import record_audit_event
from ..core.logging import get_logger
from ..models.finding import SecurityFinding
from ..models.repository import Repository
from ..models.scan import Scan

logger = get_logger("reposhield.scanner.runner")


def run_security_scan(
    repo: Repository,
    scan: Scan,
    db: Session,
    selected_tools: Optional[List[str]] = None,
    timeout_per_tool: int = 60,
    options: Optional[Dict[str, Any]] = None,
) -> Scan:
    """Execute security scanners on repository workspace and update database state.

    Enforces:
    - Safe execution timeouts per scanner.
    - Path isolation within designated repository workspace.
    - Zero execution of untrusted repository scripts.
    - Strict redaction of secrets in findings and metadata.
    - Real metrics update (health score and severity counts).
    """
    logger.info(f"Initiating security scan {scan.id} for repo '{repo.name}' (id={repo.id})")

    # 1. Validate isolated workspace directory
    if not repo.workspace_path:
        error_msg = "Repository workspace path is not set. Ingest source code archive or git repository first."
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary = json.dumps({"error": error_msg})
        db.commit()
        db.refresh(scan)
        logger.warning(f"Scan {scan.id} failed: {error_msg}")
        return scan

    target_path = Path(repo.workspace_path)
    if not target_path.exists() or not target_path.is_dir():
        error_msg = f"Repository workspace path does not exist on disk: {repo.workspace_path}"
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary = json.dumps({"error": error_msg})
        db.commit()
        db.refresh(scan)
        logger.warning(f"Scan {scan.id} failed: {error_msg}")
        return scan

    # 2. Transition scan to running
    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    db.commit()

    # 3. Determine scanner adapters to execute
    adapters_to_run = []
    if selected_tools:
        for tool_name in selected_tools:
            adapter = scanner_registry.get(tool_name)
            if adapter:
                adapters_to_run.append(adapter)
            else:
                logger.warning(f"Requested tool '{tool_name}' not found in registry")
    else:
        # Default: all registered and available adapters
        adapters_to_run = scanner_registry.get_available()

    if not adapters_to_run:
        error_msg = "No available security scanners found to execute in current environment."
        scan.status = "failed"
        scan.completed_at = datetime.now(timezone.utc)
        scan.summary = json.dumps({"error": error_msg})
        db.commit()
        db.refresh(scan)
        logger.warning(f"Scan {scan.id} failed: {error_msg}")
        return scan

    # 4. Execute each adapter safely
    results = []
    new_findings_count = 0
    scanner_reports = []

    for adapter in adapters_to_run:
        logger.info(f"Running adapter '{adapter.name}' ({adapter.display_name}) on scan {scan.id}")
        job_result = adapter.scan(
            target_dir=target_path,
            scan_id=scan.id,
            timeout_seconds=timeout_per_tool,
            options=options,
        )
        results.append(job_result)
        scanner_reports.append({
            "scanner_name": job_result.scanner_name,
            "version": job_result.scanner_version,
            "category": job_result.category,
            "status": job_result.status.value,
            "execution_time_seconds": job_result.execution_time_seconds,
            "findings_count": len(job_result.findings),
            "exit_code": job_result.exit_code,
            "error_message": job_result.error_message,
        })

        # Persist normalized findings
        for f in job_result.findings:
            title_text = f.scanner_message[:250] if f.scanner_message else f"Security finding {f.scanner_rule_id}"
            finding_record = SecurityFinding(
                repo_id=repo.id,
                scan_id=scan.id,
                scanner_identifier=f.scanner_name,
                scanner_name=f.scanner_name,
                rule_identifier=f.scanner_rule_id,
                cwe=f.cwe or f.vulnerability_category,
                title=title_text,
                category=f.vulnerability_category,
                severity=f.severity,
                confidence=f.confidence,
                confidence_score=0.95 if f.confidence == "HIGH" else 0.75 if f.confidence == "MEDIUM" else 0.50,
                file_path=f.file_path,
                line_number=f.start_line,
                line_information=f"{f.start_line}-{f.end_line}" if f.start_line != f.end_line else str(f.start_line),
                evidence_reference=f.evidence_reference,
                code_excerpt=f.evidence_reference,
                status="open",
                finding_status="open",
            )
            db.add(finding_record)
            new_findings_count += 1

    # 5. Commit findings and recalculate repository security posture
    db.flush()

    crit_count = db.query(SecurityFinding).filter(
        SecurityFinding.repo_id == repo.id,
        SecurityFinding.status == "open",
        SecurityFinding.severity == "CRITICAL",
    ).count()

    high_count = db.query(SecurityFinding).filter(
        SecurityFinding.repo_id == repo.id,
        SecurityFinding.status == "open",
        SecurityFinding.severity == "HIGH",
    ).count()

    med_count = db.query(SecurityFinding).filter(
        SecurityFinding.repo_id == repo.id,
        SecurityFinding.status == "open",
        SecurityFinding.severity == "MEDIUM",
    ).count()

    low_count = db.query(SecurityFinding).filter(
        SecurityFinding.repo_id == repo.id,
        SecurityFinding.status == "open",
        SecurityFinding.severity == "LOW",
    ).count()

    # Calculate enterprise security health score [0, 100]
    health = max(0, 100 - (crit_count * 25 + high_count * 15 + med_count * 5 + low_count * 1))

    repo.critical_count = crit_count
    repo.high_count = high_count
    repo.medium_count = med_count
    repo.low_count = low_count
    repo.health_score = health
    repo.last_scanned_at = datetime.now(timezone.utc)

    # 6. Determine overall scan completion status
    any_success = any(r.status in (ScannerStatus.SUCCESS, ScannerStatus.NO_FINDINGS) for r in results)
    any_error = any(r.status in (ScannerStatus.EXECUTION_ERROR, ScannerStatus.TIMEOUT) for r in results)

    if any_error and any_success:
        scan.status = "partial"
    elif any_error and not any_success:
        scan.status = "failed"
    else:
        scan.status = "completed"

    scan.completed_at = datetime.now(timezone.utc)
    summary_data = {
        "total_findings": new_findings_count,
        "scanners_executed": len(adapters_to_run),
        "scanners": scanner_reports,
        "health_score_after": health,
    }
    scan.summary = json.dumps(summary_data)

    # Record scan completion audit event
    record_audit_event(
        db=db,
        action="SCAN_COMPLETED",
        resource_type="scan",
        resource_identifier=scan.id,
        actor_id=repo.owner_id,
        metadata={
            "repository_id": repo.id,
            "status": scan.status,
            "findings_count": new_findings_count,
            "health_score": health,
        },
    )

    db.commit()
    db.refresh(scan)
    logger.info(
        f"Completed scan {scan.id} with status={scan.status}, findings={new_findings_count}, health={health}"
    )
    return scan
