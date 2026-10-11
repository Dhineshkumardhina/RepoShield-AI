"""Evidence-driven vulnerability validation service orchestration."""
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from ..core.audit import record_audit_event
from ..core.auth import verify_finding_ownership, verify_repository_ownership
from ..core.errors import NotFoundError, SecurityPolicyViolationError
from ..core.logging import get_logger
from ..evidence.service import record_security_evidence
from ..models.finding import SecurityFinding
from ..models.repository import Repository
from ..models.validation import FindingValidation
from ..schemas.validation import (
    EvidenceItem,
    FindingValidationRequest,
    FindingValidationResponse,
    OriginalFindingSnapshot,
    ValidationStatusEnum,
)
from .ai_assistant import invoke_validation_ai_assistant
from .collector import collect_finding_evidence
from .enums import ValidationStatus
from .rules import evaluate_evidence_rules

logger = get_logger("reposhield.validation.service")


def _format_validation_response(
    entity: FindingValidation,
    finding: SecurityFinding,
) -> FindingValidationResponse:
    """Constructs a clean Pydantic response from a database entity and finding."""
    original_snapshot = OriginalFindingSnapshot(
        finding_id=finding.id,
        scanner_name=finding.scanner_name or finding.scanner_identifier or "Security Scanner",
        rule_identifier=finding.rule_identifier or finding.cwe or "RULE-UNKNOWN",
        cwe=finding.cwe or "CWE-General",
        original_severity=finding.severity,
        scanner_message=finding.title or finding.evidence_reference or "Finding reported",
        file_path=finding.file_path,
        line_number=finding.line_number,
    )

    sup_items = [EvidenceItem(**item) for item in json.loads(entity.supporting_evidence or "[]")]
    ref_items = [EvidenceItem(**item) for item in json.loads(entity.refuting_evidence or "[]")]
    missing = json.loads(entity.missing_evidence or "[]")
    limitations = json.loads(entity.analysis_limitations or "[]")
    next_steps = json.loads(entity.suggested_next_steps or "[]")

    return FindingValidationResponse(
        id=entity.id,
        finding_id=entity.finding_id,
        repo_id=entity.repo_id,
        original_finding=original_snapshot,
        assessment_status=ValidationStatusEnum(entity.assessment_status),
        confidence_score=entity.confidence_score,
        confidence_level=entity.confidence_level,
        explanation=entity.explanation,
        evidence_summary=entity.evidence_summary,
        supporting_evidence=sup_items,
        refuting_evidence=ref_items,
        missing_evidence=missing,
        analysis_limitations=limitations,
        suggested_next_steps=next_steps,
        code_excerpt_inspected=entity.code_excerpt_inspected,
        context_start_line=str(entity.context_start_line) if entity.context_start_line else None,
        context_end_line=str(entity.context_end_line) if entity.context_end_line else None,
        is_context_truncated=entity.is_context_truncated,
        ai_assisted=entity.ai_assisted,
        ai_model=entity.ai_model,
        evidence_hash=entity.evidence_hash,
        recorded_at=entity.recorded_at,
    )


def validate_finding_service(
    finding_id: str,
    db: Session,
    current_user_id: Optional[str] = None,
    request: Optional[FindingValidationRequest] = None,
    use_ai_assistant: Optional[bool] = None,
) -> FindingValidationResponse:
    """Executes the evidence-driven validation pipeline for a finding."""
    if request is None:
        request = FindingValidationRequest(use_ai_assistant=bool(use_ai_assistant))
    elif use_ai_assistant is not None:
        request.use_ai_assistant = use_ai_assistant

    finding = db.query(SecurityFinding).filter(SecurityFinding.id == finding_id).first()
    if not finding:
        raise NotFoundError("SecurityFinding", finding_id)

    repo = db.query(Repository).filter(Repository.id == finding.repo_id).first()
    if not repo:
        raise NotFoundError("Repository", finding.repo_id)

    # 1. Enforce repository tenant ownership if current_user_id provided
    if current_user_id and repo.owner_id != current_user_id:
        raise SecurityPolicyViolationError("Access denied: You do not own the repository associated with this finding.")

    # 2. Collect Evidence Dossier
    dossier = collect_finding_evidence(
        finding=finding,
        repo=repo,
        custom_code=request.custom_code_excerpt,
    )

    # 3. Evaluate Deterministic Rules
    rule_eval = evaluate_evidence_rules(dossier)
    final_status = rule_eval.assessment_status
    final_confidence_score = rule_eval.confidence_score
    final_confidence_level = rule_eval.confidence_level
    final_explanation = rule_eval.explanation
    final_evidence_summary = rule_eval.evidence_summary
    final_next_steps = list(rule_eval.suggested_next_steps)
    ai_assisted = False
    ai_model = None

    # 4. Optional AI Assistant Integration
    if request.use_ai_assistant and request.user_authorized:
        ai_output = invoke_validation_ai_assistant(dossier)
        ai_assisted = True
        ai_model = "gemini-2.5-flash"

        # If AI flags prompt injection, reinforce HUMAN_REVIEW_REQUIRED
        if ai_output.prompt_injection_detected:
            final_status = ValidationStatus.HUMAN_REVIEW_REQUIRED
            final_explanation = f"{final_explanation} [AI Assistant]: {ai_output.technical_explanation}"
        else:
            final_explanation = f"{final_explanation} [AI Commentary]: {ai_output.technical_explanation}"

        if ai_output.suggested_next_steps:
            for step in ai_output.suggested_next_steps:
                if step not in final_next_steps:
                    final_next_steps.append(step)

    # 5. Persist Validation Assessment (Separately from pristine finding)
    validation_entity = FindingValidation(
        finding_id=finding.id,
        repo_id=repo.id,
        assessment_status=final_status.value,
        confidence_score=final_confidence_score,
        confidence_level=final_confidence_level,
        explanation=final_explanation,
        evidence_summary=final_evidence_summary,
        supporting_evidence=json.dumps([e.model_dump() for e in dossier.supporting_evidence]),
        refuting_evidence=json.dumps([e.model_dump() for e in dossier.refuting_evidence]),
        missing_evidence=json.dumps(dossier.missing_evidence),
        analysis_limitations=json.dumps(dossier.analysis_limitations),
        suggested_next_steps=json.dumps(final_next_steps),
        code_excerpt_inspected=dossier.code_excerpt,
        context_start_line=str(dossier.start_line) if dossier.start_line else None,
        context_end_line=str(dossier.end_line) if dossier.end_line else None,
        is_context_truncated=dossier.is_truncated,
        ai_assisted=ai_assisted,
        ai_model=ai_model,
        evidence_hash=dossier.evidence_hash,
        recorded_at=datetime.now(timezone.utc),
    )
    db.add(validation_entity)

    # 6. Record Granular Security Evidence Artifact
    try:
        record_security_evidence(
            db=db,
            repository_id=repo.id,
            finding_id=finding.id,
            evidence_category="vulnerability_validation",
            title=f"Evidence Validation: {dossier.original_finding.rule_identifier} [{final_status.value}]",
            tool_name="RepoShield Validation Engine",
            provenance="ai_generated_commentary" if ai_assisted else "sandbox_observed",
            raw_payload={
                "assessment_status": final_status.value,
                "confidence_score": final_confidence_score,
                "explanation": final_explanation,
                "supporting_count": len(dossier.supporting_evidence),
                "refuting_count": len(dossier.refuting_evidence),
                "evidence_hash": dossier.evidence_hash,
            },
            checks_not_performed=dossier.missing_evidence,
        )
    except Exception as e:
        logger.warning(f"Could not record linked security evidence artifact: {e}")

    # 7. Record Audit Event
    record_audit_event(
        db=db,
        action="VULNERABILITY_VALIDATION_PERFORMED",
        resource_type="finding_validation",
        resource_identifier=validation_entity.id,
        actor_id=current_user_id,
        metadata={
            "finding_id": finding.id,
            "status": final_status.value,
            "confidence": final_confidence_score,
            "ai_assisted": ai_assisted,
        },
    )

    db.commit()
    db.refresh(validation_entity)

    return _format_validation_response(validation_entity, finding)


def get_finding_validation_service(
    finding_id: str,
    db: Session,
    current_user_id: Optional[str] = None,
) -> Optional[FindingValidationResponse]:
    """Retrieve the latest evidence validation assessment for a finding."""
    finding = db.query(SecurityFinding).filter(SecurityFinding.id == finding_id).first()
    if not finding:
        raise NotFoundError("SecurityFinding", finding_id)

    repo = db.query(Repository).filter(Repository.id == finding.repo_id).first()
    if not repo:
        raise NotFoundError("Repository", finding.repo_id)

    if current_user_id and repo.owner_id != current_user_id:
        raise SecurityPolicyViolationError("Access denied: You do not own the repository associated with this finding.")

    latest = (
        db.query(FindingValidation)
        .filter(FindingValidation.finding_id == finding_id)
        .order_by(FindingValidation.recorded_at.desc())
        .first()
    )
    if not latest:
        return None

    return _format_validation_response(latest, finding)


def list_finding_validations_service(
    finding_id: str,
    db: Session,
    current_user_id: Optional[str] = None,
) -> List[FindingValidationResponse]:
    """Retrieve all historical validation assessments for a finding."""
    finding = db.query(SecurityFinding).filter(SecurityFinding.id == finding_id).first()
    if not finding:
        raise NotFoundError("SecurityFinding", finding_id)

    repo = db.query(Repository).filter(Repository.id == finding.repo_id).first()
    if not repo:
        raise NotFoundError("Repository", finding.repo_id)

    if current_user_id and repo.owner_id != current_user_id:
        raise SecurityPolicyViolationError("Access denied: You do not own the repository associated with this finding.")

    entities = (
        db.query(FindingValidation)
        .filter(FindingValidation.finding_id == finding_id)
        .order_by(FindingValidation.recorded_at.desc())
        .all()
    )
    return [_format_validation_response(e, finding) for e in entities]
