"""Tests for Contextual Risk Prioritization Engine."""
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.models.finding import SecurityFinding
from backend.app.models.repository import Repository
from backend.app.models.user import User
from backend.app.models.verification import VerificationRun
from backend.app.prioritization.evaluator import evaluate_finding_risk
from backend.app.prioritization.schemas import (
    EnvironmentContext,
    EvidenceCompleteness,
    RepoShieldPriority,
)
from backend.app.prioritization.scoring import calculate_contextual_risk_score


def test_base_severity_scoring_consistency():
    """Verifies baseline scoring reflects documented qualitative intervals."""
    env = EnvironmentContext()
    
    score_crit, prio_crit, _ = calculate_contextual_risk_score(
        scanner_severity="CRITICAL",
        confidence_label="HIGH",
        confidence_score=1.0,
        sensitive_data_involved=False,
        reachability_status="unproven",
        dependency_exposure="non_dependency",
        auth_context="unknown",
        env_context=env,
    )
    assert score_crit == 80.0
    assert prio_crit == RepoShieldPriority.CRITICAL

    score_med, prio_med, _ = calculate_contextual_risk_score(
        scanner_severity="MEDIUM",
        confidence_label="HIGH",
        confidence_score=1.0,
        sensitive_data_involved=False,
        reachability_status="unproven",
        dependency_exposure="non_dependency",
        auth_context="unknown",
        env_context=env,
    )
    assert score_med == 40.0
    assert prio_med == RepoShieldPriority.MEDIUM


def test_confidence_discounting():
    """Verifies low confidence scanner findings are discounted."""
    env = EnvironmentContext()
    score_high_conf, _, _ = calculate_contextual_risk_score(
        scanner_severity="HIGH",
        confidence_label="HIGH",
        confidence_score=0.95,
        sensitive_data_involved=False,
        reachability_status="unproven",
        dependency_exposure="non_dependency",
        auth_context="unknown",
        env_context=env,
    )
    score_low_conf, _, _ = calculate_contextual_risk_score(
        scanner_severity="HIGH",
        confidence_label="LOW",
        confidence_score=0.40,
        sensitive_data_involved=False,
        reachability_status="unproven",
        dependency_exposure="non_dependency",
        auth_context="unknown",
        env_context=env,
    )
    assert score_high_conf == 60.0
    assert score_low_conf == 42.0  # 60.0 * 0.70


def test_reachability_truth_in_evidence():
    """Verifies reachability is never fabricated: neutral when unproven, decreased for test fixtures, increased for ingress."""
    env = EnvironmentContext()
    
    # 1. Unproven reachability has strictly 0.0 impact
    _, _, factors_unproven = calculate_contextual_risk_score(
        scanner_severity="MEDIUM",
        confidence_label="HIGH",
        confidence_score=1.0,
        sensitive_data_involved=False,
        reachability_status="unproven",
        dependency_exposure="non_dependency",
        auth_context="unknown",
        env_context=env,
    )
    reachability_factor = next(f for f in factors_unproven if f.name == "Reachability Unproven")
    assert reachability_factor.impact == 0.0

    # 2. Test fixture confinement reduces priority
    score_test, _, _ = calculate_contextual_risk_score(
        scanner_severity="HIGH",
        confidence_label="HIGH",
        confidence_score=1.0,
        sensitive_data_involved=False,
        reachability_status="test_fixture",
        dependency_exposure="non_dependency",
        auth_context="unknown",
        env_context=env,
    )
    assert score_test == 40.0  # 60.0 - 20.0

    # 3. Router entrypoint increases priority
    score_ingress, _, _ = calculate_contextual_risk_score(
        scanner_severity="HIGH",
        confidence_label="HIGH",
        confidence_score=1.0,
        sensitive_data_involved=False,
        reachability_status="entrypoint_route",
        dependency_exposure="non_dependency",
        auth_context="unknown",
        env_context=env,
    )
    assert score_ingress == 70.0  # 60.0 + 10.0


def test_sensitive_data_and_auth_context_modifiers():
    """Verifies sensitive data and auth context adjust score appropriately."""
    env_public = EnvironmentContext(environment="production", is_internet_facing=True)
    score, priority, factors = calculate_contextual_risk_score(
        scanner_severity="HIGH",
        confidence_label="HIGH",
        confidence_score=1.0,
        sensitive_data_involved=True,
        reachability_status="entrypoint_route",
        dependency_exposure="direct_production",
        auth_context="unauthenticated_public",
        env_context=env_public,
    )
    # 60 (base) + 10 (sensitive) + 10 (route) + 5 (direct dep) + 10 (unauthenticated) + 5 (prod) + 5 (internet) = 105 -> clamped to 100.0
    assert score == 100.0
    assert priority == RepoShieldPriority.CRITICAL


def test_separation_of_four_evaluation_dimensions(db_session: Session):
    """Verifies complete separation of original scanner severity, contextual priority, evidence completeness, and verification status."""
    owner = User(
        id=f"usr_test_{uuid.uuid4().hex[:8]}",
        email=f"prioritize_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash="mock_hash",
        account_status="active",
    )
    db_session.add(owner)
    db_session.flush()

    repo = Repository(
        id=f"repo_{uuid.uuid4().hex[:8]}",
        owner_id=owner.id,
        name="xerova/auth-gateway",
        default_branch="main",
    )
    db_session.add(repo)
    db_session.flush()

    finding = SecurityFinding(
        id=f"FIND_{uuid.uuid4().hex[:6]}",
        repo_id=repo.id,
        scanner_name="Semgrep OSS",
        rule_identifier="python.lang.security.audit.sqli",
        cwe="CWE-89",
        title="SQL Injection in auth router query builder",
        severity="CRITICAL",  # Original scanner severity
        confidence="HIGH",
        confidence_score=0.98,
        file_path="src/api/routes/user_login.py",
        line_number=45,
        code_excerpt="cursor.execute(f'SELECT * FROM users WHERE user_id = {user_id}')",
    )
    db_session.add(finding)
    db_session.flush()

    # Record a verification run that failed verification
    ver_run = VerificationRun(
        id=f"vr_{uuid.uuid4().hex[:8]}",
        finding_id=finding.id,
        status="FAILED_VERIFICATION",
    )
    db_session.add(ver_run)
    db_session.commit()

    assessment = evaluate_finding_risk(finding, db_session)

    # 4 distinct dimensions must be present and distinct:
    assert assessment.original_scanner_severity == "CRITICAL"
    assert assessment.contextual_priority in (RepoShieldPriority.CRITICAL, RepoShieldPriority.HIGH)
    assert assessment.evidence_completeness in (EvidenceCompleteness.COMPLETE, EvidenceCompleteness.PARTIAL)
    assert assessment.verification_status == "FAILED_VERIFICATION"

    # Non-probabilistic disclaimer must be present
    assert "NOT represent a validated mathematical probability" in assessment.methodology_disclaimer


def test_prioritization_api_endpoints_and_ownership(client: TestClient, db_session: Session):
    """Verifies GET and POST prioritization endpoints enforce tenant boundaries."""
    # Create User A & Repo A
    user_a = User(
        id=f"usr_a_{uuid.uuid4().hex[:8]}",
        email=f"usera_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash="mock_hash",
        account_status="active",
    )
    user_b = User(
        id=f"usr_b_{uuid.uuid4().hex[:8]}",
        email=f"userb_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash="mock_hash",
        account_status="active",
    )
    db_session.add_all([user_a, user_b])
    db_session.flush()

    repo_a = Repository(
        id=f"repo_a_{uuid.uuid4().hex[:8]}",
        owner_id=user_a.id,
        name="xerova/service-a",
        default_branch="main",
    )
    db_session.add(repo_a)
    db_session.flush()

    finding_a = SecurityFinding(
        id=f"FIND_A_{uuid.uuid4().hex[:6]}",
        repo_id=repo_a.id,
        scanner_name="Semgrep OSS",
        rule_identifier="python.lang.security.hardcoded-key",
        cwe="CWE-798",
        title="Hardcoded API secret token in config",
        severity="HIGH",
        confidence="HIGH",
        confidence_score=0.95,
        file_path="src/config/keys.py",
        line_number=12,
        code_excerpt="API_KEY = 'secret_token_value'",
    )
    db_session.add(finding_a)
    db_session.commit()

    from backend.app.core.security import create_access_token

    token_a = create_access_token({"sub": user_a.id, "email": user_a.email})
    token_b = create_access_token({"sub": user_b.id, "email": user_b.email})

    # User A accesses own finding prioritization -> 200 OK
    res_a = client.get(
        f"/api/v1/findings/{finding_a.id}/prioritization",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert res_a.status_code == 200
    data_a = res_a.json()
    assert data_a["finding_id"] == finding_a.id
    assert data_a["original_scanner_severity"] == "HIGH"
    assert "priority_score" in data_a

    # User B attempts to access User A's finding -> 403 Forbidden
    res_b = client.get(
        f"/api/v1/findings/{finding_a.id}/prioritization",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert res_b.status_code == 403

    # User A tailors risk with environment context -> 200 OK
    res_post = client.post(
        f"/api/v1/findings/{finding_a.id}/prioritize",
        headers={"Authorization": f"Bearer {token_a}"},
        json={
            "environment": "production",
            "is_internet_facing": True,
            "asset_criticality": "tier_1_mission_critical",
            "auth_context": "unauthenticated_public",
        },
    )
    assert res_post.status_code == 200
    tailored = res_post.json()
    assert tailored["priority_score"] >= data_a["priority_score"]
    assert any("Production Environment Tier" in f["name"] for f in tailored["factors"])
