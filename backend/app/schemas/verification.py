"""Pydantic schemas for the RepoShield AI Fix Verification Engine."""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class VerificationStatus(str, Enum):
    NOT_TESTED = "NOT_TESTED"
    RUNNING = "RUNNING"
    VERIFIED_AGAINST_DEFINED_CHECKS = "VERIFIED_AGAINST_DEFINED_CHECKS"
    FAILED_VERIFICATION = "FAILED_VERIFICATION"
    INCONCLUSIVE = "INCONCLUSIVE"


class FindingRegressionClassification(str, Enum):
    """Taxonomy of finding classifications across baseline and patched revisions."""
    NEW = "NEW"
    RESOLVED_BY_DEFINED_CHECKS = "RESOLVED_BY_DEFINED_CHECKS"
    STILL_PRESENT = "STILL_PRESENT"
    UNCHANGED = "UNCHANGED"
    POTENTIALLY_REGRESSED = "POTENTIALLY_REGRESSED"
    INCOMPARABLE = "INCOMPARABLE"


CLASSIFICATION_RULE_DEFINITIONS: Dict[str, str] = {
    "RESOLVED_BY_DEFINED_CHECKS": (
        "The targeted baseline finding was reproduced in the baseline workspace under the configured scanner rules "
        "and is no longer reported in the patched workspace under the same scanner configuration."
    ),
    "STILL_PRESENT": (
        "The target finding remains detected by the scanner in the patched workspace under the same rule "
        "and file path with overlapping or identical sink location."
    ),
    "UNCHANGED": (
        "Non-target pre-existing findings in unmodified files or unaffected sections that remain present in both "
        "baseline and patched workspaces without alteration."
    ),
    "NEW": (
        "A finding detected in the patched workspace that did not exist in the baseline workspace, "
        "representing a newly introduced security defect or regression."
    ),
    "POTENTIALLY_REGRESSED": (
        "A baseline finding in a modified file whose location, sink, or severity shifted without being completely resolved, "
        "or a partial fix where an associated vulnerability pattern remains detectable in the modified hunk."
    ),
    "INCOMPARABLE": (
        "Static comparison could not be completed reliably because the scanner errored/timed out, the scanner configuration "
        "differed between runs, or the baseline finding was never reproduced by the scanner in the baseline workspace."
    ),
}


class ClassifiedFinding(BaseModel):
    rule_id: str
    scanner_name: str
    vulnerability_category: str
    severity: str
    file_path: str
    line_number: Optional[int] = None
    message: str
    classification: FindingRegressionClassification
    classification_reason: str
    is_target_finding: bool = False
    baseline_match: Optional[Dict[str, Any]] = None
    patched_match: Optional[Dict[str, Any]] = None


class ParsedHunk(BaseModel):
    old_start: int
    old_length: int
    new_start: int
    new_length: int
    lines: List[str] = []


class ParsedFilePatch(BaseModel):
    old_path: str
    new_path: str
    hunks: List[ParsedHunk] = []
    added_lines: int = 0
    deleted_lines: int = 0
    modified_lines_range: str = ""


class PatchValidationResult(BaseModel):
    is_valid: bool
    files: List[ParsedFilePatch] = []
    total_added: int = 0
    total_deleted: int = 0
    errors: List[str] = []
    warnings: List[str] = []


class PatchValidationRequest(BaseModel):
    proposed_patch: str = Field(..., description="Git unified diff string")
    repo_id: Optional[str] = None


class VerificationRunRequest(BaseModel):
    finding_id: str = Field(..., description="ID of the original security finding")
    proposed_patch: str = Field(..., description="Git unified diff of the proposed fix")
    patch_id: Optional[str] = Field(None, description="Optional patch proposal identifier")
    scanner_names: Optional[List[str]] = Field(None, description="Optional list of scanner tools to run")
    scanner_config: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Configuration overrides")
    run_existing_tests: bool = Field(True, description="Whether to execute existing project tests")
    run_regression_tests: bool = Field(True, description="Whether to execute targeted security regression tests")
    regression_test_code: Optional[str] = Field(None, description="Optional inline security test script")
    regression_test_file: Optional[str] = Field(None, description="Optional repository path to regression test")
    timeout_seconds: int = Field(60, ge=5, le=300, description="Verification timeout in seconds")


class VerificationEvidenceSchema(BaseModel):
    id: str
    verification_run_id: str
    evidence_type: str
    result: str
    tool_name_and_version: str
    evidence_reference: Optional[str] = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


STANDARD_VERIFICATION_LIMITATIONS = [
    "A scanner finding disappearing does not prove that the vulnerability is impossible.",
    "Passing tests do not prove complete security.",
    "A patch may change the code path or trigger a different rule without fixing the underlying issue.",
    "Never claim universal security or mathematically proven correctness.",
]


class VerificationRunResponse(BaseModel):
    id: str
    finding_id: str
    patch_id: Optional[str] = None
    baseline_hash: Optional[str] = None
    patched_hash: Optional[str] = None
    scanner_metadata: Dict[str, Any] = Field(default_factory=dict)
    scanner_config: Dict[str, Any] = Field(default_factory=dict)
    tests_executed: List[str] = Field(default_factory=list)
    test_results: Dict[str, Any] = Field(default_factory=dict)
    original_finding_status: str  # resolved, persisting, modified, untested
    new_findings: List[Dict[str, Any]] = Field(default_factory=list)
    classified_findings: List[ClassifiedFinding] = Field(default_factory=list)
    baseline_test_results: Dict[str, Any] = Field(default_factory=dict)
    test_regressions: List[str] = Field(default_factory=list)
    execution_errors: List[str] = Field(default_factory=list)
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: VerificationStatus
    reasons: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    patch_diff: Optional[str] = None
    test_summary: Optional[str] = None
    source_revision: Optional[str] = None
    target_revision: Optional[str] = None
    configuration_changes: Dict[str, Any] = Field(default_factory=dict)
    findings_before_patch: List[Dict[str, Any]] = Field(default_factory=list)
    findings_after_patch: List[Dict[str, Any]] = Field(default_factory=list)
    ai_interpretation: Optional[str] = None
    integrity_hash: Optional[str] = None
    limitations: List[str] = Field(default_factory=lambda: list(STANDARD_VERIFICATION_LIMITATIONS))
    evidence: List[VerificationEvidenceSchema] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)

