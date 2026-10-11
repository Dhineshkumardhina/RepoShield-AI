"""Pydantic schemas for Security Evidence Management and Reports."""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class EvidenceCategory(str, Enum):
    SCANNER_FINDING = "scanner_finding"
    SANITIZED_OUTPUT = "sanitized_output"
    REVISION_HASH = "revision_hash"
    PATCH_DIFF = "patch_diff"
    TEST_RESULT = "test_result"
    COMPARISON = "comparison"
    TOOL_METADATA = "tool_metadata"
    VERIFICATION_REPORT = "verification_report"
    AUDIT_EVENT = "audit_event"
    AI_COMMENTARY = "ai_commentary"


class EvidenceProvenance(str, Enum):
    SCANNER_OBSERVED = "scanner_observed"
    SANDBOX_OBSERVED = "sandbox_observed"
    AI_GENERATED_COMMENTARY = "ai_generated_commentary"
    USER_SUPPLIED = "user_supplied"


class SecurityEvidenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    repository_id: str
    scan_id: Optional[str] = None
    verification_run_id: Optional[str] = None
    finding_id: Optional[str] = None
    evidence_category: str
    title: str
    provenance: str
    tool_name: str
    tool_version: Optional[str] = None
    content_hash: str
    sanitized_payload: str
    checks_not_performed: Optional[str] = None
    recorded_at: datetime
    created_at: datetime


class SecurityEvidenceCreate(BaseModel):
    repository_id: str
    scan_id: Optional[str] = None
    verification_run_id: Optional[str] = None
    finding_id: Optional[str] = None
    evidence_category: EvidenceCategory
    title: str
    provenance: EvidenceProvenance = EvidenceProvenance.SCANNER_OBSERVED
    tool_name: str
    tool_version: Optional[str] = None
    raw_payload: Any
    checks_not_performed: Optional[List[str]] = None


class ReportExportFormat(str, Enum):
    JSON = "json"
    MARKDOWN = "markdown"
    SARIF = "sarif"


class SecurityReportResponse(BaseModel):
    report_title: str
    repository_id: str
    format: ReportExportFormat
    generated_at: str
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EvidenceIntegrityStatus(str, Enum):
    VALID = "VALID"
    MODIFIED = "MODIFIED"
    MISSING_HASH = "MISSING_HASH"


AUTHENTICITY_DISCLAIMER: str = (
    "A content hash helps detect accidental alterations, but hashing alone does not "
    "establish evidence authenticity or original provenance."
)


class EvidenceIntegrityResponse(BaseModel):
    evidence_id: str
    repository_id: str
    status: EvidenceIntegrityStatus
    stored_hash: str
    computed_hash: str
    is_intact: bool
    disclaimer: str = AUTHENTICITY_DISCLAIMER


class VerificationRunIntegrityResponse(BaseModel):
    verification_run_id: str
    finding_id: Optional[str] = None
    status: EvidenceIntegrityStatus
    stored_hash: Optional[str] = None
    computed_hash: str
    is_intact: bool
    disclaimer: str = AUTHENTICITY_DISCLAIMER

