"""AI Security Analyst service orchestration.

Coordinates bounded context extraction, secret redaction, AI/fallback execution,
strict schema validation, and persistence into the finding_analyses table.
"""
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from ..core.audit import record_audit_event
from ..core.errors import NotFoundError, SecurityPolicyViolationError
from ..core.logging import get_logger
from ..models.analysis import FindingAnalysis
from ..models.finding import SecurityFinding
from ..models.repository import Repository
from ..schemas.analyzer import FindingAnalysisRequest, FindingAnalysisResponse
from .client import gemini_analyst_client
from .context import get_bounded_source_context
from ..scanner.base import redact_secrets

logger = get_logger("reposhield.analyzer.service")


def analyze_finding_service(
    payload: FindingAnalysisRequest,
    db: Optional[Session] = None,
    current_user_id: Optional[str] = None,
) -> FindingAnalysisResponse:
    """Execute AI Security Analysis workflow with full guardrails and isolation."""
    # 1. Enforce user authorization requirement
    if not payload.user_authorized_analysis:
        raise SecurityPolicyViolationError(
            "Analysis refused: User authorization toggle is not enabled. "
            "RepoShield AI requires explicit operator consent before analyzing repository source code."
        )

    finding_record: Optional[SecurityFinding] = None
    repo_record: Optional[Repository] = None

    if db and payload.finding_id:
        finding_record = db.query(SecurityFinding).filter(SecurityFinding.id == payload.finding_id).first()
        if finding_record:
            repo_record = db.query(Repository).filter(Repository.id == finding_record.repo_id).first()

    # 2. Retrieve bounded source-code context if repository workspace is available
    source_context_text = None
    is_truncated = False

    if repo_record and repo_record.workspace_path:
        file_target = payload.file_path or (finding_record.file_path if finding_record else "")
        line_target = payload.line_number or (finding_record.line_number if finding_record else 1)
        
        ctx = get_bounded_source_context(
            repo=repo_record,
            file_path=file_target,
            target_line=line_target,
            window_lines=15,
        )
        if ctx:
            source_context_text = ctx.code_excerpt
            is_truncated = ctx.is_truncated

    # If code excerpt was manually passed in payload and context wasn't found from disk
    if not source_context_text and payload.code_excerpt:
        source_context_text = redact_secrets(payload.code_excerpt)
        is_truncated = len(source_context_text.strip().splitlines()) <= 1
    elif source_context_text:
        source_context_text = redact_secrets(source_context_text)

    # 3. Assemble finding dictionary
    finding_dict: Dict[str, Any] = {
        "finding_id": payload.finding_id,
        "scanner_name": payload.scanner_name or (finding_record.scanner_name if finding_record else "Security Scanner"),
        "scanner_rule_id": payload.vulnerability_category or (finding_record.rule_identifier if finding_record else "RULE-1"),
        "vulnerability_category": payload.vulnerability_category or (finding_record.cwe if finding_record else "CWE-General"),
        "severity": payload.scanner_severity or (finding_record.severity if finding_record else "MEDIUM"),
        "file_path": payload.file_path or (finding_record.file_path if finding_record else "unknown"),
        "line_number": payload.line_number or (finding_record.line_number if finding_record else 1),
        "scanner_message": redact_secrets(payload.scanner_message or (finding_record.title if finding_record else "")),
        "code_excerpt": source_context_text,
    }

    # 4. Perform AI analysis with client / deterministic fallback
    analysis_result = gemini_analyst_client.analyze(
        finding_dict=finding_dict,
        source_context=source_context_text,
        dependency_info=payload.dependency_info,
        is_truncated=is_truncated,
    )

    # 5. Persist the analysis record separately from the original scanner finding
    if db and finding_record:
        analysis_entity = FindingAnalysis(
            finding_id=finding_record.id,
            repo_id=finding_record.repo_id,
            plain_language_explanation=analysis_result.plain_language_explanation,
            potential_impact=analysis_result.potential_impact,
            relevant_code_evidence=json.dumps(analysis_result.relevant_code_evidence),
            likely_root_cause=analysis_result.likely_root_cause,
            suggested_remediation=json.dumps(analysis_result.suggested_remediation),
            suggested_targeted_tests=json.dumps(analysis_result.suggested_targeted_tests),
            missing_context=json.dumps(analysis_result.missing_context),
            limitations=json.dumps(analysis_result.limitations),
            ai_model=analysis_result.ai_model,
            analysis_timestamp=analysis_result.analysis_timestamp,
            confidence=analysis_result.confidence,
            is_exploitable_claim_supported=analysis_result.is_exploitable_claim_supported,
            requires_human_review=True,
            user_authorized=True,
        )
        db.add(analysis_entity)

        if current_user_id:
            record_audit_event(
                db=db,
                action="AI_FINDING_ANALYSIS_COMPLETED",
                resource_type="finding_analysis",
                resource_identifier=analysis_entity.id,
                actor_id=current_user_id,
                metadata={
                    "finding_id": finding_record.id,
                    "model": analysis_result.ai_model,
                },
            )

        db.commit()
        db.refresh(analysis_entity)
        analysis_result.id = analysis_entity.id

    return analysis_result


def get_finding_analyses_for_finding(
    finding_id: str,
    db: Session,
) -> List[FindingAnalysisResponse]:
    """Retrieve all historical AI analyses stored for a specific finding."""
    entities = (
        db.query(FindingAnalysis)
        .filter(FindingAnalysis.finding_id == finding_id)
        .order_by(FindingAnalysis.created_at.desc())
        .all()
    )

    results: List[FindingAnalysisResponse] = []
    for e in entities:
        resp = FindingAnalysisResponse(
            id=e.id,
            finding_id=e.finding_id,
            vulnerability_category="Analyzed Finding",
            plain_language_explanation=e.plain_language_explanation,
            potential_impact=e.potential_impact,
            relevant_code_evidence=json.loads(e.relevant_code_evidence) if e.relevant_code_evidence else [],
            likely_root_cause=e.likely_root_cause,
            suggested_remediation=json.loads(e.suggested_remediation) if e.suggested_remediation else [],
            suggested_targeted_tests=json.loads(e.suggested_targeted_tests) if e.suggested_targeted_tests else [],
            missing_context=json.loads(e.missing_context) if e.missing_context else [],
            limitations=json.loads(e.limitations) if e.limitations else [],
            ai_model=e.ai_model,
            analysis_timestamp=e.analysis_timestamp or e.created_at,
            confidence=e.confidence,
            is_exploitable_claim_supported=e.is_exploitable_claim_supported,
            requires_human_review=e.requires_human_review,
            user_authorized=e.user_authorized,
        )
        results.append(resp)
    return results
