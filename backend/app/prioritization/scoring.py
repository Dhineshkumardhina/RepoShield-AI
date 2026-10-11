"""Documented scoring model for Contextual Risk Prioritization.

SCORING METHODOLOGY SPECIFICATION:

1. Base Severity Baseline (CVSS v3.1 qualitative intervals):
   - CRITICAL: 80.0
   - HIGH: 60.0
   - MEDIUM: 40.0
   - LOW: 20.0
   - INFORMATIONAL: 5.0

2. Scanner Confidence Multiplier (Discounts false-positive-prone heuristics when confidence is supplied):
   - HIGH (>= 0.85 score): 1.00
   - MEDIUM (0.50 - 0.84 score): 0.85
   - LOW (< 0.50 score): 0.70
   - Unspecified / Missing: 1.00 (neutral baseline, no penalty)

3. Additive Contextual Modifiers (Derived strictly from verified evidence):
   - Affected Component Category:
     * Core Security Boundary (+10.0): auth, login, crypto, IAM, session, tokens.
     * Public Ingress API (+5.0): routes, controllers, endpoints, handlers.
     * Business Logic (0.0): domain services, models.
     * Internal Utility (-5.0): helpers, utility scripts.
     * Test / Mock Fixture (-20.0): test harnesses, test fixtures.
   - Evidence Supporting Finding (Validation Status):
     * Supported by Evidence (+10.0): confirmed taint sink or rule condition.
     * Possible False Positive (-30.0): refuting evidence observed.
     * Insufficient Evidence / Unreviewed (0.0): neutral baseline.
   - Availability of Verified Remediation:
     * Verified Fix Available (+5.0): fix passed verification, immediate triage readiness.
     * Patch Pending / Analysis (0.0): fix exists or in review.
   - Sensitive Data Involved (+10.0): Confirmed credential, secret key, token, or PII.
   - Reachability Evidence:
     * Ingress Route / Entrypoint (+10.0): Entrypoint exposure observed in code path.
     * Test fixture (-20.0): Handled via component or path confinement.
     * Unproven (0.0): No call graph or trace proof exists. NEVER assume reachable!
   - Dependency Exposure:
     * Direct production dependency (+5.0): Directly imported in runtime manifest.
     * Transitive / Dev dependency (-10.0): Only present in build-time or dev tooling.
   - Authentication Posture:
     * Unauthenticated public surface (+10.0): Reachable without authentication credential.
     * Authenticated admin / internal service (-10.0): Protected behind access control perimeter.
   - User-Supplied Environmental Context:
     * Production tier (+5.0): Deployed in live production infrastructure.
     * Internet-facing (+5.0): Exposed to public ingress.
     * Development / Sandbox tier (-10.0): Confined to isolated test environments.

4. Severe Finding Floor Protection (Explicit Handling of Missing Information):
   - Do NOT silently downgrade severe scanner findings because contextual information is missing!
   - In the absence of affirmative refuting evidence (e.g., test fixture, confirmed false positive):
     * A scanner CRITICAL finding cannot drop below HIGH (Floor score: 60.0).
     * A scanner HIGH finding cannot drop below MEDIUM (Floor score: 40.0).
   - If contextual evidence is missing, flag limitation and recommend investigation rather than downgrading.

5. Output Normalization:
   - Clamped to [0.0, 100.0].
   - Mapped to RepoShieldPriority (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL).
   - NOT a probability of exploitation!
"""
from typing import Dict, List, Optional, Tuple
from .schemas import (
    ComponentCategory,
    EnvironmentContext,
    PrioritizationFactor,
    RemediationReadiness,
    RepoShieldPriority,
)

# Documented default base scores
DEFAULT_BASE_SEVERITY_SCORES: Dict[str, float] = {
    "CRITICAL": 80.0,
    "HIGH": 60.0,
    "MEDIUM": 40.0,
    "LOW": 20.0,
    "INFORMATIONAL": 5.0,
}

DEFAULT_CONFIDENCE_MULTIPLIERS: Dict[str, float] = {
    "HIGH": 1.00,
    "MEDIUM": 0.85,
    "LOW": 0.70,
}


def calculate_contextual_risk_score(
    scanner_severity: str,
    confidence_label: Optional[str] = None,
    confidence_score: Optional[float] = None,
    sensitive_data_involved: bool = False,
    reachability_status: str = "unproven",
    dependency_exposure: str = "non_dependency",
    auth_context: str = "unknown",
    env_context: Optional[EnvironmentContext] = None,
    affected_component: str = "unknown",
    finding_validation_status: str = "UNREVIEWED",
    remediation_status: str = "NEEDS_INVESTIGATION",
) -> Tuple[float, RepoShieldPriority, List[PrioritizationFactor]]:
    """Calculates deterministic, transparent risk-ranking score and returns factors.
    
    Returns:
        (final_score, priority, factors)
    """
    if env_context is None:
        env_context = EnvironmentContext()

    factors: List[PrioritizationFactor] = []
    
    # 1. Base Severity Baseline
    norm_severity = scanner_severity.upper() if scanner_severity else "MEDIUM"
    base_score = DEFAULT_BASE_SEVERITY_SCORES.get(norm_severity, 40.0)
    factors.append(
        PrioritizationFactor(
            name="Original Scanner Severity Baseline",
            weight=1.0,
            impact=base_score,
            evidence=f"Reported by engine as {norm_severity}",
            rationale=f"Base score initialized to {base_score} per CVSS qualitative intervals.",
        )
    )
    
    # 2. Scanner Confidence Multiplier
    if confidence_label:
        norm_conf = confidence_label.upper()
        conf_mult = DEFAULT_CONFIDENCE_MULTIPLIERS.get(norm_conf, 1.0)
    elif confidence_score is not None:
        if confidence_score < 0.50:
            conf_mult = 0.70
            norm_conf = "LOW"
        elif confidence_score < 0.85:
            conf_mult = 0.85
            norm_conf = "MEDIUM"
        else:
            conf_mult = 1.00
            norm_conf = "HIGH"
    else:
        conf_mult = 1.00
        norm_conf = "UNSPECIFIED"

    adjusted_base = base_score * conf_mult
    if conf_mult < 1.0:
        discount = adjusted_base - base_score
        factors.append(
            PrioritizationFactor(
                name="Scanner Confidence Discount",
                weight=conf_mult,
                impact=round(discount, 1),
                evidence=f"Confidence {norm_conf}" + (f" (score {confidence_score:.2f})" if confidence_score else ""),
                rationale="Lower confidence finding discounted to suppress false-positive inflation.",
            )
        )
    elif norm_conf == "UNSPECIFIED":
        factors.append(
            PrioritizationFactor(
                name="Scanner Confidence Neutral",
                weight=1.0,
                impact=0.0,
                evidence="Scanner did not report confidence metric",
                rationale="Neutral multiplier applied: findings are not penalized when confidence is omitted.",
            )
        )
    
    current_score = adjusted_base

    # 3. Affected Component Impact
    if affected_component == ComponentCategory.CORE_SECURITY_BOUNDARY.value or affected_component == "core_security_boundary":
        impact = 10.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Core Security Boundary Component",
                weight=1.0,
                impact=impact,
                evidence="Vulnerability resides within authentication, cryptography, IAM, or security boundary code",
                rationale="Security boundary flaws have high-leverage architectural impact and direct exploit utility.",
            )
        )
    elif affected_component == ComponentCategory.PUBLIC_INGRESS_API.value or affected_component == "public_ingress_api":
        impact = 5.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Public Ingress API Component",
                weight=1.0,
                impact=impact,
                evidence="File resides in routing controllers, HTTP handlers, or public endpoint definitions",
                rationale="Directly exposed to untrusted external request inputs.",
            )
        )
    elif affected_component == ComponentCategory.INTERNAL_UTILITY.value or affected_component == "internal_utility":
        impact = -5.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Internal Utility Component",
                weight=1.0,
                impact=impact,
                evidence="File resides in utility scripts, helpers, or CLI tooling",
                rationale="Utility functions typically process sanitized inputs or run in non-serving contexts.",
            )
        )
    elif affected_component == ComponentCategory.TEST_OR_MOCK_FIXTURE.value or affected_component == "test_or_mock_fixture":
        impact = -20.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Test / Mock Fixture Confinement",
                weight=1.0,
                impact=impact,
                evidence="File resides in test suite, mock directory, or test fixtures",
                rationale="Vulnerabilities strictly located in test fixtures cannot be invoked in deployment.",
            )
        )

    # 4. Evidence Supporting Finding (Validation Status)
    if finding_validation_status == "SUPPORTED_BY_EVIDENCE":
        impact = 10.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Validated by Concrete Evidence",
                weight=1.0,
                impact=impact,
                evidence="Evidence validation confirmed observable taint flow or vulnerability condition",
                rationale="Positive confirmation validates vulnerability presence and elevates triage urgency.",
            )
        )
    elif finding_validation_status == "POSSIBLE_FALSE_POSITIVE":
        impact = -30.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Possible False Positive Evidence",
                weight=1.0,
                impact=impact,
                evidence="Validation evidence refutes vulnerability or indicates sanitization is present",
                rationale="Refuting evidence significantly de-prioritizes finding to prevent analyst alert fatigue.",
            )
        )
    elif finding_validation_status == "INSUFFICIENT_EVIDENCE":
        factors.append(
            PrioritizationFactor(
                name="Validation Evidence Insufficient",
                weight=1.0,
                impact=0.0,
                evidence="Validation evaluated finding but available code context was insufficient to prove or refute",
                rationale="Neutral impact applied; manual investigation recommended without silent downgrading.",
            )
        )

    # 5. Availability of Verified Remediation
    if remediation_status == RemediationReadiness.VERIFIED_FIX_READY.value or remediation_status == "VERIFIED_FIX_READY":
        impact = 5.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Verified Remediation Available",
                weight=1.0,
                impact=impact,
                evidence="A candidate fix has passed targeted verification checks and tests without regression",
                rationale="Actionable resolution ready for immediate review and merging elevates triage queue readiness.",
            )
        )

    # 6. Sensitive Data Involvement
    if sensitive_data_involved:
        impact = 10.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Sensitive Data Exposure",
                weight=1.0,
                impact=impact,
                evidence="Rule or code excerpt references credentials, tokens, keys, or PII",
                rationale="Compromise of secret credentials or personal data incurs severe compliance and operational impact.",
            )
        )

    # 7. Reachability Evidence
    if reachability_status == "entrypoint_route":
        impact = 10.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Ingress Route Reachability",
                weight=1.0,
                impact=impact,
                evidence="File path resides within API router, controller, or public ingress entrypoint",
                rationale="Code directly exposed to request routing mechanisms has higher exposure.",
            )
        )
    elif reachability_status == "test_fixture" and affected_component != "test_or_mock_fixture":
        impact = -20.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Test / Mock Fixture Confinement",
                weight=1.0,
                impact=impact,
                evidence="File path resides in test suite, mock directory, or sample fixture",
                rationale="Vulnerabilities strictly located in non-production test suites cannot be invoked in deployment.",
            )
        )
    elif reachability_status == "unproven":
        factors.append(
            PrioritizationFactor(
                name="Reachability Unproven",
                weight=1.0,
                impact=0.0,
                evidence="No static call graph or runtime execution trace evidence observed",
                rationale="RepoShield adheres to truth-in-evidence: reachability is never fabricated.",
            )
        )

    # 8. Dependency Exposure
    if dependency_exposure == "direct_production":
        impact = 5.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Direct Production Dependency",
                weight=1.0,
                impact=impact,
                evidence="Vulnerability is in a top-level production runtime dependency",
                rationale="Directly referenced packages are invoked directly by application code.",
            )
        )
    elif dependency_exposure == "transitive_dev":
        impact = -10.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Transitive Development Dependency",
                weight=1.0,
                impact=impact,
                evidence="Vulnerability is in a secondary or development/build-time dependency",
                rationale="Development dependencies are typically excluded from production deployment bundles.",
            )
        )

    # 9. Authentication Posture
    if auth_context == "unauthenticated_public":
        impact = 10.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Unauthenticated Public Surface",
                weight=1.0,
                impact=impact,
                evidence="Endpoint is explicitly unauthenticated and publicly accessible",
                rationale="Any anonymous client can invoke the affected capability without credentials.",
            )
        )
    elif auth_context in ("authenticated_admin", "internal_service"):
        impact = -10.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Access Controlled / Internal Service",
                weight=1.0,
                impact=impact,
                evidence=f"Endpoint is restricted by {auth_context}",
                rationale="Exploitation requires pre-existing privileged credentials or internal network access.",
            )
        )

    # 10. Environmental Information (User-supplied)
    if env_context.environment == "production":
        impact = 5.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Production Environment Tier",
                weight=1.0,
                impact=impact,
                evidence="User specified environment: production",
                rationale="Active production systems host live business data.",
            )
        )
    elif env_context.environment in ("development", "staging"):
        impact = -10.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Non-Production Environment Tier",
                weight=1.0,
                impact=impact,
                evidence=f"User specified environment: {env_context.environment}",
                rationale="Non-production environments do not process live customer traffic.",
            )
        )

    if env_context.is_internet_facing is True:
        impact = 5.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Internet-Facing Deployment",
                weight=1.0,
                impact=impact,
                evidence="User specified asset is directly exposed to public Internet",
                rationale="Public internet assets are subject to automated untargeted scanning and reconnaissance.",
            )
        )
    elif env_context.is_internet_facing is False:
        impact = -5.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Internal Network Perimeter",
                weight=1.0,
                impact=impact,
                evidence="User specified asset is isolated from public Internet",
                rationale="Requires internal network breach or pivoting to reach.",
            )
        )

    if env_context.asset_criticality == "tier_1_mission_critical":
        impact = 5.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="Mission-Critical Business Asset",
                weight=1.0,
                impact=impact,
                evidence="User specified asset criticality: tier_1_mission_critical",
                rationale="Tier 1 assets incur critical operational disruption if compromised.",
            )
        )

    if env_context.data_sensitivity == "contains_secrets_or_pii":
        impact = 5.0
        current_score += impact
        factors.append(
            PrioritizationFactor(
                name="High Data Sensitivity Boundary",
                weight=1.0,
                impact=impact,
                evidence="User specified data sensitivity: contains_secrets_or_pii",
                rationale="Asset boundary contains secrets, financial data, or sensitive personal information.",
            )
        )

    # 11. Severe Finding Floor Protection Rule (No Silent Downgrade on Missing Context)
    # Check if affirmative refuting evidence exists:
    has_affirmative_refutation = (
        affected_component in (ComponentCategory.TEST_OR_MOCK_FIXTURE.value, "test_or_mock_fixture")
        or reachability_status == "test_fixture"
        or finding_validation_status == "POSSIBLE_FALSE_POSITIVE"
        or dependency_exposure == "transitive_dev"
        or (env_context.environment in ("development", "staging"))
    )

    floor_protection_applied = False
    if not has_affirmative_refutation:
        if norm_severity == "CRITICAL" and current_score < 60.0:
            # Floor guarantee: CRITICAL findings cannot drop below HIGH (60.0) without refuting evidence
            floor_protection_applied = True
            elevation = 60.0 - current_score
            current_score = 60.0
            factors.append(
                PrioritizationFactor(
                    name="Severe Finding Protection Floor (CRITICAL)",
                    weight=1.0,
                    impact=round(elevation, 1),
                    evidence="Scanner reported CRITICAL; missing reachability/environment context cannot justify silent downgrade",
                    rationale="RepoShield safety guarantee: Severe findings maintain elevated triage priority until explicitly refuted.",
                )
            )
        elif norm_severity == "HIGH" and current_score < 40.0:
            # Floor guarantee: HIGH findings cannot drop below MEDIUM (40.0) without refuting evidence
            floor_protection_applied = True
            elevation = 40.0 - current_score
            current_score = 40.0
            factors.append(
                PrioritizationFactor(
                    name="Severe Finding Protection Floor (HIGH)",
                    weight=1.0,
                    impact=round(elevation, 1),
                    evidence="Scanner reported HIGH; missing reachability/environment context cannot justify silent downgrade",
                    rationale="RepoShield safety guarantee: High severity findings maintain triage visibility.",
                )
            )

    # Clamping
    final_score = max(0.0, min(100.0, current_score))
    final_score = round(final_score, 1)

    # Priority mapping
    if final_score >= 80.0:
        priority = RepoShieldPriority.CRITICAL
    elif final_score >= 60.0:
        priority = RepoShieldPriority.HIGH
    elif final_score >= 40.0:
        priority = RepoShieldPriority.MEDIUM
    elif final_score >= 20.0:
        priority = RepoShieldPriority.LOW
    else:
        priority = RepoShieldPriority.INFORMATIONAL

    # Investigation recommendation when evidence is limited
    investigation_recommendation: Optional[str] = None
    if reachability_status == "unproven" or auth_context == "unknown" or env_context.environment == "unknown":
        if floor_protection_applied:
            investigation_recommendation = (
                f"Severe scanner finding ({norm_severity}) preserved at {priority.value} priority. "
                "Because runtime reachability or environmental exposure is unproven, conduct dynamic exploit verification "
                "or call graph tracing before de-prioritizing."
            )
        elif finding_validation_status == "INSUFFICIENT_EVIDENCE":
            investigation_recommendation = (
                "Validation evidence was insufficient to verify data flow sink. "
                "Inspect source code context and test whether untrusted user inputs reach this location."
            )
        elif reachability_status == "unproven":
            investigation_recommendation = (
                "Runtime reachability is unproven from static analysis alone. "
                "Verify whether the affected function is invoked from active routing entrypoints."
            )

    return final_score, priority, factors
