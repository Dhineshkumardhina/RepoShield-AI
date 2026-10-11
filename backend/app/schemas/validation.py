"""Pydantic schemas for Evidence-Driven Vulnerability Validation."""
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ValidationStatusEnum(str, Enum):
    """Explicit assessment statuses representing evidentiary support.
    
    These statuses represent assessment states, not absolute proof that a
    vulnerability is exploitable or harmless.
    """
    UNREVIEWED = "UNREVIEWED"
    SUPPORTED_BY_EVIDENCE = "SUPPORTED_BY_EVIDENCE"
    POSSIBLE_FALSE_POSITIVE = "POSSIBLE_FALSE_POSITIVE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"


class EvidencePolarity(str, Enum):
    SUPPORTING = "SUPPORTING"
    REFUTING = "REFUTING"
    NEUTRAL = "NEUTRAL"


class EvidenceItem(BaseModel):
    """Granular piece of observable code, data-flow, or configuration evidence."""
    evidence_type: str = Field(description="Classification e.g. source_sink, sanitization, literal_constant, test_context")
    description: str = Field(description="Clear explanation of the observed property")
    code_snippet: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    polarity: str = Field(default="SUPPORTING", description="SUPPORTING, REFUTING, or NEUTRAL")


class OriginalFindingSnapshot(BaseModel):
    """Pristine snapshot of original scanner finding to guarantee zero mutation."""
    finding_id: str
    scanner_name: str
    rule_identifier: str
    cwe: str
    original_severity: str
    scanner_message: str
    file_path: str
    line_number: int


class FindingValidationRequest(BaseModel):
    """Request payload to initiate evidence-based validation on a finding."""
    use_ai_assistant: bool = Field(default=False, description="Whether to invoke AI analysis assistant")
    user_authorized: bool = Field(default=True, description="Operator consent for code inspection")
    custom_code_excerpt: Optional[str] = Field(default=None, description="Optional custom context for offline testing")


class FindingValidationResponse(BaseModel):
    """Structured, schema-validated validation report for an existing scanner finding."""
    id: str
    finding_id: str
    repo_id: str
    original_finding: OriginalFindingSnapshot
    assessment_status: ValidationStatusEnum
    confidence_score: float = Field(ge=0.0, le=1.0)
    confidence_level: str  # HIGH, MEDIUM, LOW
    explanation: str
    evidence_summary: str
    supporting_evidence: List[EvidenceItem] = Field(default_factory=list)
    refuting_evidence: List[EvidenceItem] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list, description="Evidence required to reach a stronger conclusion")
    analysis_limitations: List[str] = Field(default_factory=list, description="Unsupported analysis capabilities")
    suggested_next_steps: List[str] = Field(default_factory=list)
    code_excerpt_inspected: Optional[str] = None
    context_start_line: Optional[str] = None
    context_end_line: Optional[str] = None
    is_context_truncated: bool = False
    ai_assisted: bool = False
    ai_model: Optional[str] = None
    evidence_hash: str
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(from_attributes=True)
