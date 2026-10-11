"""Pydantic schemas for the AI Security Analysis Engine."""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator


class FindingAnalysisRequest(BaseModel):
    finding_id: str = Field(min_length=1, examples=["FIND-418"])
    repo_id: Optional[str] = None
    scanner_name: Optional[str] = Field(default="Security Scanner", examples=["Semgrep OSS"])
    vulnerability_category: Optional[str] = Field(default="CWE-Other", examples=["CWE-89: SQL Injection"])
    file_path: Optional[str] = Field(default="unknown", examples=["src/dao/user_query.py"])
    line_number: Optional[int] = Field(default=1, ge=1, examples=[42])
    scanner_severity: Optional[str] = Field(default="MEDIUM", pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$", examples=["CRITICAL"])
    scanner_message: Optional[str] = Field(default="Security finding reported by scanner", examples=["Detected unescaped user parameter in raw SQL query string"])
    code_excerpt: Optional[str] = Field(default=None, examples=["cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"])
    data_flow_evidence: List[str] = Field(default_factory=list)
    dependency_info: Optional[str] = None
    user_authorized_analysis: bool = Field(default=True, description="Explicit operator consent to analyze code")


class FindingAnalysisResponse(BaseModel):
    id: Optional[str] = None
    finding_id: str
    vulnerability_category: str
    plain_language_explanation: str
    potential_impact: str
    relevant_code_evidence: List[str]
    likely_root_cause: str
    suggested_remediation: List[str]
    suggested_targeted_tests: List[str]
    missing_context: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    ai_model: str = Field(default="gemini-2.5-flash")
    analysis_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: str = Field(default="HIGH")
    is_exploitable_claim_supported: bool = False
    requires_human_review: bool = True
    user_authorized: bool = True

    # Compatibility aliases
    finding_summary: Optional[str] = None
    evidence_observed: Optional[List[str]] = None
    reasoning_summary: Optional[str] = None
    recommended_remediation: Optional[List[str]] = None
    suggested_tests: Optional[List[str]] = None

    @model_validator(mode="after")
    def populate_compatibility_fields(self):
        if not self.finding_summary:
            self.finding_summary = self.plain_language_explanation[:200]
        if not self.evidence_observed:
            self.evidence_observed = self.relevant_code_evidence
        if not self.reasoning_summary:
            self.reasoning_summary = self.plain_language_explanation
        if not self.recommended_remediation:
            self.recommended_remediation = self.suggested_remediation
        if not self.suggested_tests:
            self.suggested_tests = self.suggested_targeted_tests
        return self

    model_config = ConfigDict(from_attributes=True)

