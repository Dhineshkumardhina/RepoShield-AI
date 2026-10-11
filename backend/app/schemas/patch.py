"""Pydantic schemas for Patch Proposals and Verification Runs."""
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class PatchProposalCreate(BaseModel):
    finding_id: str
    proposed_diff_reference: str = Field(..., description="Git unified diff or artifact reference")
    ai_explanation: str = Field(..., description="Explanation of security patch rationale")


class PatchProposalRead(BaseModel):
    id: str
    finding_id: str
    proposed_diff_reference: str
    ai_explanation: str
    review_status: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VerificationEvidenceCreate(BaseModel):
    evidence_type: str = Field(..., examples=["test_log", "sast_scan", "ast_diff"])
    result: str = Field(..., examples=["passed", "failed", "error"])
    tool_name_and_version: str = Field(..., examples=["pytest-9.1.1", "semgrep-1.78.0"])
    evidence_reference: Optional[str] = None


class VerificationEvidenceRead(BaseModel):
    id: str
    verification_run_id: str
    evidence_type: str
    result: str
    tool_name_and_version: str
    evidence_reference: Optional[str] = None
    timestamp: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VerificationRunCreate(BaseModel):
    patch_proposal_id: str
    test_summary: Optional[str] = None


class VerificationRunRead(BaseModel):
    id: str
    patch_proposal_id: str
    status: str
    test_summary: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    created_at: datetime
    evidence: List[VerificationEvidenceRead] = []

    model_config = ConfigDict(from_attributes=True)
