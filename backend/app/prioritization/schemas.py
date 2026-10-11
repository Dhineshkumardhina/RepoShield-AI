"""Pydantic schemas for Contextual Risk Prioritization and Remediation Queue.

Explicitly separates:
1. Original Scanner Severity (raw report from scanner)
2. RepoShield Contextual Priority (urgency derived from verified evidence)
3. Evidence Completeness (depth and availability of observable facts)
4. Verification Status (lifecycle of fix testing and regression checks)
"""
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class RepoShieldPriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class EvidenceCompleteness(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    MINIMAL = "MINIMAL"
    INSUFFICIENT = "INSUFFICIENT"


class ComponentCategory(str, Enum):
    CORE_SECURITY_BOUNDARY = "core_security_boundary"
    PUBLIC_INGRESS_API = "public_ingress_api"
    BUSINESS_LOGIC = "business_logic"
    INTERNAL_UTILITY = "internal_utility"
    TEST_OR_MOCK_FIXTURE = "test_or_mock_fixture"
    UNKNOWN = "unknown"


class RemediationReadiness(str, Enum):
    VERIFIED_FIX_READY = "VERIFIED_FIX_READY"
    PATCH_PENDING_REVIEW = "PATCH_PENDING_REVIEW"
    PATCH_FAILED_TESTS = "PATCH_FAILED_TESTS"
    ANALYSIS_AVAILABLE = "ANALYSIS_AVAILABLE"
    NEEDS_INVESTIGATION = "NEEDS_INVESTIGATION"


class EnvironmentContext(BaseModel):
    """Environmental parameters provided by the user or configuration."""
    environment: str = Field(
        default="unknown",
        description="Target tier: production, staging, development, or unknown"
    )
    is_internet_facing: Optional[bool] = Field(
        default=None,
        description="Whether the application or service is directly exposed to the public Internet"
    )
    asset_criticality: str = Field(
        default="unknown",
        description="Business criticality tier: tier_1_mission_critical, tier_2_business_operational, tier_3_internal_support, unknown"
    )
    auth_context: str = Field(
        default="unknown",
        description="Authentication level: unauthenticated_public, authenticated_user, authenticated_admin, internal_service, unknown"
    )
    data_sensitivity: str = Field(
        default="unknown",
        description="Data boundary: contains_secrets_or_pii, business_confidential, public_data, unknown"
    )


class PrioritizationFactor(BaseModel):
    """A transparent, traceable contributor to the risk ranking."""
    name: str
    weight: float
    impact: float
    evidence: str
    rationale: str


class RemediationLinkage(BaseModel):
    """Links between remediation recommendations, patches, and supporting findings."""
    finding_id: str
    patch_proposal_id: Optional[str] = Field(
        default=None,
        description="ID of candidate patch proposal, if generated"
    )
    verification_run_id: Optional[str] = Field(
        default=None,
        description="ID of latest verification run evaluating the candidate patch"
    )
    verification_status: Optional[str] = Field(
        default=None,
        description="Latest verification run status: VERIFIED_AGAINST_DEFINED_CHECKS, FAILED_VERIFICATION, INCONCLUSIVE"
    )
    analysis_id: Optional[str] = Field(
        default=None,
        description="ID of AI security analysis record, if present"
    )
    recommendations: List[str] = Field(
        default_factory=list,
        description="Actionable remediation steps linked to the finding"
    )
    suggested_targeted_tests: List[str] = Field(
        default_factory=list,
        description="Security regression or verification tests suggested for this vulnerability"
    )
    patch_diff_preview: Optional[str] = Field(
        default=None,
        description="Preview of proposed patch unified diff"
    )


class ContextualRiskAssessment(BaseModel):
    """Complete, transparent contextual risk evaluation.
    
    IMPORTANT: The numerical priority score is a triage prioritization index,
    NOT a validated probability of real-world exploitation.
    """
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    repo_id: str
    
    # 4 Separated Evaluation Dimensions
    original_scanner_severity: str = Field(
        description="Raw, unmodified severity reported by the scanner engine (e.g. CRITICAL, HIGH, MEDIUM, LOW)"
    )
    contextual_priority: RepoShieldPriority = Field(
        description="RepoShield prioritized urgency based on contextual evidence"
    )
    evidence_completeness: EvidenceCompleteness = Field(
        description="Level of supporting context available: COMPLETE, PARTIAL, MINIMAL, INSUFFICIENT"
    )
    verification_status: str = Field(
        description="Fix verification status: NOT_TESTED, RUNNING, VERIFIED_AGAINST_DEFINED_CHECKS, FAILED_VERIFICATION, INCONCLUSIVE"
    )
    
    # Score details
    priority_score: float = Field(
        ge=0.0,
        le=100.0,
        description="Normalized risk-ranking score (0.0 - 100.0). Triage metric only."
    )
    
    # Granular Evidence Dimensions (Strictly evidence-backed, never invented)
    sensitive_data_involved: bool = Field(
        description="True if evidence verifies sensitive credentials, keys, or personal data involvement"
    )
    reachability_evidence: str = Field(
        description="Evidence-supported reachability status: entrypoint_route, internal_utility, test_fixture, unproven"
    )
    dependency_exposure: str = Field(
        description="Dependency exposure context: direct_production, transitive_dev, non_dependency, unproven"
    )
    auth_context: str = Field(
        description="Observed authentication/authorization posture"
    )
    affected_component: str = Field(
        default="unknown",
        description="Architectural component category: core_security_boundary, public_ingress_api, business_logic, internal_utility, test_or_mock_fixture, unknown"
    )
    remediation_readiness: str = Field(
        default="NEEDS_INVESTIGATION",
        description="Remediation status: VERIFIED_FIX_READY, PATCH_PENDING_REVIEW, PATCH_FAILED_TESTS, ANALYSIS_AVAILABLE, NEEDS_INVESTIGATION"
    )
    
    # Floor Protection & Missing Information Guarantees
    floor_protection_applied: bool = Field(
        default=False,
        description="True if severe scanner finding was protected from silent downgrade due to missing contextual information"
    )
    investigation_recommendation: Optional[str] = Field(
        default=None,
        description="Explicit recommendation when evidence is insufficient or manual investigation is required"
    )
    
    # Traceable Factors, Linkages, and Limitations
    factors: List[PrioritizationFactor] = Field(
        default_factory=list,
        description="Detailed list of transparent scoring factors and weights"
    )
    missing_context: List[str] = Field(
        default_factory=list,
        description="Context that could not be determined from available evidence"
    )
    remediation_linkage: Optional[RemediationLinkage] = Field(
        default=None,
        description="Links between recommendations, patches, and supporting finding"
    )
    methodology_disclaimer: str = Field(
        default=(
            "The RepoShield Contextual Priority Score is a transparent deterministic triage ranking metric. "
            "It does NOT represent a validated mathematical probability of exploitation or universal security guarantee. "
            "Reachability, internet exposure, and exploitability are evaluated strictly against recorded evidence and never synthesized without observable data. "
            "Severe scanner findings are protected against silent downgrading when contextual evidence is missing."
        )
    )


class RemediationQueueItem(BaseModel):
    """An item in the prioritized remediation queue."""
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    repo_id: str
    repo_name: str
    title: str
    file_path: str
    line_number: int
    cwe: str
    scanner_name: str
    
    # Priority & Severity Separation
    original_scanner_severity: str
    contextual_priority: RepoShieldPriority
    priority_score: float
    affected_component: str
    
    # Readiness & Evidence Status
    remediation_status: RemediationReadiness
    evidence_completeness: EvidenceCompleteness
    evidence_limitations: List[str] = Field(default_factory=list)
    suggested_action: str
    
    # Links to supporting evidence and recommendations
    linkage: RemediationLinkage
