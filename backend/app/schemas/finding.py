"""Pydantic schemas for Security Findings."""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator


class SecurityFindingBase(BaseModel):
    repo_id: str
    scan_id: Optional[str] = None
    scanner_identifier: Optional[str] = None
    scanner_name: Optional[str] = None
    rule_identifier: Optional[str] = None
    cwe: Optional[str] = None
    title: str = Field(examples=["Raw SQL Query String Interpolation"])
    category: str = Field(default="vulnerability", examples=["vulnerability", "secret", "sast"])
    severity: str = Field(pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$", examples=["CRITICAL"])
    confidence: str = Field(default="HIGH", examples=["HIGH", "MEDIUM", "LOW"])
    confidence_score: float = Field(default=0.95, ge=0.0, le=1.0)
    file_path: str = Field(examples=["src/dao/user_query.py"])
    line_number: int = Field(default=1, ge=1, examples=[42])
    line_information: Optional[str] = None
    evidence_reference: Optional[str] = None
    status: str = Field(default="open", examples=["open"])
    finding_status: Optional[str] = None
    code_excerpt: Optional[str] = None
    pr_number: Optional[int] = None

    @model_validator(mode="after")
    def populate_aliases(self):
        if not self.scanner_identifier and self.scanner_name:
            self.scanner_identifier = self.scanner_name
        elif not self.scanner_name and self.scanner_identifier:
            self.scanner_name = self.scanner_identifier
        elif not self.scanner_identifier and not self.scanner_name:
            self.scanner_identifier = "Semgrep OSS"
            self.scanner_name = "Semgrep OSS"

        if not self.rule_identifier and self.cwe:
            self.rule_identifier = self.cwe
        elif not self.cwe and self.rule_identifier:
            self.cwe = self.rule_identifier
        elif not self.rule_identifier and not self.cwe:
            self.rule_identifier = "CWE-General"
            self.cwe = "CWE-General"

        if not self.finding_status and self.status:
            self.finding_status = self.status
        elif not self.status and self.finding_status:
            self.status = self.finding_status

        if not self.line_information:
            self.line_information = str(self.line_number)

        return self


class SecurityFindingCreate(SecurityFindingBase):
    pass


class SecurityFindingRead(SecurityFindingBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    contextual_priority: Optional[str] = Field(
        default=None,
        description="RepoShield contextual priority (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)"
    )
    priority_score: Optional[float] = Field(
        default=None,
        description="Contextual priority score index (0.0 - 100.0)"
    )
    evidence_completeness: Optional[str] = Field(
        default=None,
        description="Depth of observable evidence (COMPLETE, PARTIAL, MINIMAL, INSUFFICIENT)"
    )
    remediation_readiness: Optional[str] = Field(
        default=None,
        description="Remediation status: VERIFIED_FIX_READY, PATCH_PENDING_REVIEW, etc."
    )
    created_at: datetime
    updated_at: datetime
