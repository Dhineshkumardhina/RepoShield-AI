"""Comprehensive tests for RepoShield AI's Evidence-Based Vulnerability Prioritization Engine."""
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.core.security import create_access_token
from backend.app.models.analysis import FindingAnalysis
from backend.app.models.finding import SecurityFinding
from backend.app.models.patch import PatchProposal
from backend.app.models.repository import Repository
from backend.app.models.user import User
from backend.app.models.validation import FindingValidation
from backend.app.models.verification import VerificationRun
from backend.app.prioritization.evaluator import (
    detect_affected_component,
    evaluate_finding_risk,
    extract_remediation_linkage,
)
from backend.app.prioritization.schemas import (
    ComponentCategory,
    EnvironmentContext,
    EvidenceCompleteness,
    RemediationReadiness,
    RepoShieldPriority,
)
from backend.app.prioritization.scoring import calculate_contextual_risk_score
from backend.app.prioritization.service import build_remediation_queue


def test_consistent_scoring_across_baseline_intervals():
    """Verifies deterministic scoring adheres strictly to documented qualitative baselines."""
    severities = {
        "CRITICAL": (80.0, RepoShieldPriority.CRITICAL),
        "HIGH": (60.0, RepoShieldPriority.HIGH),
        "MEDIUM": (40.0, RepoShieldPriority.MEDIUM),
        "LOW": (20.0, RepoShieldPriority.LOW),
        "INFORMATIONAL": (5.0, RepoShieldPriority.INFORMATIONAL),
    }

    for sev, (expected_score, expected_prio) in severities.items():
        score, prio, factors = calculate_contextual_risk_score(
            scanner_severity=sev,
            confidence_label="HIGH",
            confidence_score=1.0,
            sensitive_data_involved=False,
            reachability_status="unproven",
            dependency_exposure="non_dependency",
            auth_context="unknown",
            env_context=EnvironmentContext(),
            affected_component="unknown",
        )
        assert score == expected_score, f"Expected {expected_score} for {sev}, got {score}"
        assert prio == expected_prio, f"Expected {expected_prio} for {sev}, got {prio}"
        assert any(f.name == "Original Scanner Severity Baseline" for f in factors)


def test_severe_finding_protection_floor_no_silent_downgrade():
    """Verifies that severe scanner findings (CRITICAL, HIGH) are NEVER silently downgraded when context is missing."""
    # 1. CRITICAL finding with missing/unproven context and low confidence
    # Without floor protection: 80.0 * 0.70 = 56.0 (MEDIUM)
    # With floor protection: Floor is 60.0 (HIGH), preventing silent downgrade to MEDIUM/LOW!
    score_crit, prio_crit, factors_crit = calculate_contextual_risk_score(
        scanner_severity="CRITICAL",
        confidence_label="LOW",
        confidence_score=0.40,
        sensitive_data_involved=False,
        reachability_status="unproven",
        dependency_exposure="non_dependency",
        auth_context="unknown",
        env_context=EnvironmentContext(),  # all unknown
        affected_component="unknown",
    )
    assert score_crit >= 60.0, f"Critical finding was downgraded below floor: {score_crit}"
    assert prio_crit in (RepoShieldPriority.CRITICAL, RepoShieldPriority.HIGH)
    assert any("Severe Finding Protection Floor (CRITICAL)" in f.name for f in factors_crit)

    # 2. HIGH finding with missing context and low confidence
    # Without floor protection: 60.0 * 0.70 = 42.0. If internal utility (-5) -> 37.0 (LOW)
    # With floor protection: Floor is 40.0 (MEDIUM)
    score_high, prio_high, factors_high = calculate_contextual_risk_score(
        scanner_severity="HIGH",
        confidence_label="LOW",
        confidence_score=0.40,
        sensitive_data_involved=False,
        reachability_status="unproven",
        dependency_exposure="non_dependency",
        auth_context="unknown",
        env_context=EnvironmentContext(),
        affected_component="internal_utility",  # -5.0
    )
    assert score_high >= 40.0, f"High finding was downgraded below floor: {score_high}"
    assert prio_high in (RepoShieldPriority.HIGH, RepoShieldPriority.MEDIUM)
    assert any("Severe Finding Protection Floor (HIGH)" in f.name for f in factors_high)


def test_affirmative_refutation_permits_appropriate_downgrading():
    """Verifies that severe findings CAN be downgraded ONLY when affirmative refuting evidence exists."""
    # A CRITICAL finding strictly confined to test fixture can be downgraded safely
    score_test, prio_test, factors_test = calculate_contextual_risk_score(
        scanner_severity="CRITICAL",
        confidence_label="HIGH",
        confidence_score=1.0,
        sensitive_data_involved=False,
        reachability_status="test_fixture",
        dependency_exposure="non_dependency",
        auth_context="unknown",
        env_context=EnvironmentContext(),
        affected_component="test_or_mock_fixture",
    )
    # 80.0 - 20.0 (test fixture) = 60.0 (or lower if non-prod)
    assert not any("Severe Finding Protection Floor" in f.name for f in factors_test)

    # A CRITICAL finding validated as POSSIBLE_FALSE_POSITIVE
    score_fp, prio_fp, factors_fp = calculate_contextual_risk_score(
        scanner_severity="CRITICAL",
        confidence_label="HIGH",
        confidence_score=1.0,
        sensitive_data_involved=False,
        reachability_status="unproven",
        dependency_exposure="non_dependency",
        auth_context="unknown",
        env_context=EnvironmentContext(),
        affected_component="business_logic",
        finding_validation_status="POSSIBLE_FALSE_POSITIVE",
    )
    # 80.0 - 30.0 (false positive) = 50.0 (MEDIUM). Allowed because affirmative refuting evidence exists!
    assert score_fp == 50.0
    assert prio_fp == RepoShieldPriority.MEDIUM
    assert not any("Severe Finding Protection Floor" in f.name for f in factors_fp)


def test_affected_component_detection():
    """Verifies component categorization correctly distinguishes boundaries, APIs, utilities, and test harnesses."""
    f_auth = SecurityFinding(
        file_path="src/auth/jwt_validator.py",
        rule_identifier="python.auth.token-bypass",
        title="Insecure JWT signature verification",
        severity="HIGH",
        line_number=10,
    )
    assert detect_affected_component(f_auth) == ComponentCategory.CORE_SECURITY_BOUNDARY.value

    f_api = SecurityFinding(
        file_path="src/api/routes/v1/orders.py",
        rule_identifier="python.sqli.query",
        title="SQL injection in order handler",
        severity="HIGH",
        line_number=50,
    )
    assert detect_affected_component(f_api) == ComponentCategory.PUBLIC_INGRESS_API.value

    f_test = SecurityFinding(
        file_path="tests/unit/test_payment.py",
        rule_identifier="python.secrets.mock-token",
        title="Hardcoded token in mock test fixture",
        severity="MEDIUM",
        line_number=15,
    )
    assert detect_affected_component(f_test) == ComponentCategory.TEST_OR_MOCK_FIXTURE.value

    f_util = SecurityFinding(
        file_path="src/utils/string_helpers.py",
        rule_identifier="python.regex.redos",
        title="Polynomial regex in helper function",
        severity="LOW",
        line_number=8,
    )
    assert detect_affected_component(f_util) == ComponentCategory.INTERNAL_UTILITY.value


def test_remediation_linkage_and_verified_fix_readiness(db_session: Session):
    """Verifies that verified remediation boosts triage actionability and links patches to findings."""
    owner = User(
        id=f"usr_remed_{uuid.uuid4().hex[:8]}",
        email=f"remed_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash="mock_hash",
        account_status="active",
    )
    db_session.add(owner)
    db_session.flush()

    repo = Repository(
        id=f"repo_remed_{uuid.uuid4().hex[:8]}",
        owner_id=owner.id,
        name="xerova/payments",
        default_branch="main",
    )
    db_session.add(repo)
    db_session.flush()

    finding = SecurityFinding(
        id=f"FIND_REM_{uuid.uuid4().hex[:6]}",
        repo_id=repo.id,
        scanner_name="Semgrep OSS",
        rule_identifier="python.sqli",
        cwe="CWE-89",
        title="SQL Injection in charge handler",
        severity="CRITICAL",
        file_path="src/api/endpoints/charge.py",
        line_number=45,
        code_excerpt="cursor.execute(f'SELECT * FROM accounts WHERE id = {acc_id}')",
    )
    db_session.add(finding)
    db_session.flush()

    # 1. Initially without patch -> NEEDS_INVESTIGATION
    readiness_initial, linkage_initial = extract_remediation_linkage(finding, db_session)
    assert readiness_initial == RemediationReadiness.NEEDS_INVESTIGATION.value
    assert linkage_initial.patch_proposal_id is None

    # 2. Add patch proposal -> PATCH_PENDING_REVIEW
    patch = PatchProposal(
        id=f"patch_{uuid.uuid4().hex[:8]}",
        finding_id=finding.id,
        proposed_diff_reference="--- a/charge.py\n+++ b/charge.py\n- query\n+ param_query",
        ai_explanation="Parameterized DB query",
        review_status="pending",
    )
    db_session.add(patch)
    db_session.flush()

    readiness_pending, linkage_pending = extract_remediation_linkage(finding, db_session)
    assert readiness_pending == RemediationReadiness.PATCH_PENDING_REVIEW.value
    assert linkage_pending.patch_proposal_id == patch.id

    # 3. Add successful verification run -> VERIFIED_FIX_READY
    ver_run = VerificationRun(
        id=f"vrun_{uuid.uuid4().hex[:8]}",
        finding_id=finding.id,
        patch_proposal_id=patch.id,
        status="VERIFIED_AGAINST_DEFINED_CHECKS",
        patch_diff=patch.proposed_diff_reference,
    )
    db_session.add(ver_run)
    db_session.commit()

    readiness_verified, linkage_verified = extract_remediation_linkage(finding, db_session)
    assert readiness_verified == RemediationReadiness.VERIFIED_FIX_READY.value
    assert linkage_verified.verification_run_id == ver_run.id
    assert linkage_verified.verification_status == "VERIFIED_AGAINST_DEFINED_CHECKS"

    # Evaluate full risk assessment
    assessment = evaluate_finding_risk(finding, db_session)
    assert assessment.remediation_readiness == RemediationReadiness.VERIFIED_FIX_READY.value
    assert any(f.name == "Verified Remediation Available" for f in assessment.factors)
    assert assessment.remediation_linkage is not None
    assert assessment.remediation_linkage.patch_proposal_id == patch.id


def test_remediation_queue_building_and_filtering(db_session: Session):
    """Verifies that build_remediation_queue accurately ranks findings and applies priority filters."""
    user = User(
        id=f"usr_q_{uuid.uuid4().hex[:8]}",
        email=f"queue_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash="mock_hash",
        account_status="active",
    )
    db_session.add(user)
    db_session.flush()

    repo = Repository(
        id=f"repo_q_{uuid.uuid4().hex[:8]}",
        owner_id=user.id,
        name="xerova/order-engine",
        default_branch="main",
    )
    db_session.add(repo)
    db_session.flush()

    # Finding 1: CRITICAL on auth boundary
    f1 = SecurityFinding(
        id=f"FIND_Q1_{uuid.uuid4().hex[:6]}",
        repo_id=repo.id,
        scanner_name="Semgrep OSS",
        rule_identifier="auth.bypass",
        cwe="CWE-287",
        title="Authentication bypass on auth route",
        severity="CRITICAL",
        file_path="src/auth/routes.py",
        line_number=22,
        code_excerpt="if not token: pass",
    )
    # Finding 2: LOW in utility script
    f2 = SecurityFinding(
        id=f"FIND_Q2_{uuid.uuid4().hex[:6]}",
        repo_id=repo.id,
        scanner_name="Bandit",
        rule_identifier="B301",
        cwe="CWE-502",
        title="Unpickling in local migration helper",
        severity="LOW",
        file_path="scripts/helpers.py",
        line_number=88,
        code_excerpt="data = pickle.loads(b)",
    )
    # Finding 3: HIGH in core API
    f3 = SecurityFinding(
        id=f"FIND_Q3_{uuid.uuid4().hex[:6]}",
        repo_id=repo.id,
        scanner_name="Semgrep OSS",
        rule_identifier="cmd.injection",
        cwe="CWE-78",
        title="Command injection in export controller",
        severity="HIGH",
        file_path="src/api/controllers/export.py",
        line_number=102,
        code_excerpt="os.system(cmd)",
    )
    db_session.add_all([f1, f2, f3])
    db_session.commit()

    # Build queue with no filters
    queue = build_remediation_queue(user_id=user.id, db=db_session)
    assert len(queue) == 3
    # Top item must be the CRITICAL auth vulnerability
    assert queue[0].finding_id == f1.id
    assert queue[0].contextual_priority == RepoShieldPriority.CRITICAL

    # Filter queue by priority="CRITICAL"
    queue_crit = build_remediation_queue(user_id=user.id, db=db_session, priority_filter="CRITICAL")
    assert len(queue_crit) >= 1
    assert all(item.contextual_priority == RepoShieldPriority.CRITICAL for item in queue_crit)

    # Filter queue by priority="LOW"
    queue_low = build_remediation_queue(user_id=user.id, db=db_session, priority_filter="LOW")
    assert all(item.contextual_priority in (RepoShieldPriority.LOW, RepoShieldPriority.INFORMATIONAL) for item in queue_low)


def test_remediation_queue_api_endpoint_and_authorization(client: TestClient, db_session: Session):
    """Verifies GET /api/v1/prioritization/remediation-queue enforces multi-tenant auth and parameters."""
    user_a = User(
        id=f"usr_qa_{uuid.uuid4().hex[:8]}",
        email=f"usera_q_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash="mock_hash",
        account_status="active",
    )
    user_b = User(
        id=f"usr_qb_{uuid.uuid4().hex[:8]}",
        email=f"userb_q_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash="mock_hash",
        account_status="active",
    )
    db_session.add_all([user_a, user_b])
    db_session.flush()

    repo_a = Repository(
        id=f"repo_qa_{uuid.uuid4().hex[:8]}",
        owner_id=user_a.id,
        name="xerova/vault-service",
        default_branch="main",
    )
    db_session.add(repo_a)
    db_session.flush()

    finding_a = SecurityFinding(
        id=f"FIND_QA_{uuid.uuid4().hex[:6]}",
        repo_id=repo_a.id,
        scanner_name="Semgrep OSS",
        rule_identifier="crypto.weak-hash",
        cwe="CWE-327",
        title="Use of MD5 in signature hashing",
        severity="HIGH",
        file_path="src/crypto/hasher.py",
        line_number=30,
        code_excerpt="hashlib.md5(data)",
    )
    db_session.add(finding_a)
    db_session.commit()

    token_a = create_access_token({"sub": user_a.id, "email": user_a.email})
    token_b = create_access_token({"sub": user_b.id, "email": user_b.email})

    # User A retrieves remediation queue -> 200 OK
    res_a = client.get(
        "/api/v1/prioritization/remediation-queue",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert res_a.status_code == 200
    items_a = res_a.json()
    assert len(items_a) == 1
    assert items_a[0]["finding_id"] == finding_a.id
    assert items_a[0]["repo_name"] == "xerova/vault-service"
    assert "suggested_action" in items_a[0]
    assert "linkage" in items_a[0]

    # User B retrieves remediation queue -> sees empty queue (no findings in User B repos)
    res_b = client.get(
        "/api/v1/prioritization/remediation-queue",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert res_b.status_code == 200
    assert len(res_b.json()) == 0

    # User B attempts to filter by User A's repo -> 403 Forbidden
    res_b_forbidden = client.get(
        f"/api/v1/prioritization/remediation-queue?repo_id={repo_a.id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert res_b_forbidden.status_code == 403

    # Check alias endpoint /api/v1/findings/remediation-queue
    res_alias = client.get(
        "/api/v1/findings/remediation-queue",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert res_alias.status_code == 200
    assert len(res_alias.json()) == 1


def test_findings_list_priority_filtering_and_metadata(client: TestClient, db_session: Session):
    """Verifies that GET /api/v1/findings enriches results with contextual priority and supports priority query param."""
    user = User(
        id=f"usr_fl_{uuid.uuid4().hex[:8]}",
        email=f"userfl_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash="mock_hash",
        account_status="active",
    )
    db_session.add(user)
    db_session.flush()

    repo = Repository(
        id=f"repo_fl_{uuid.uuid4().hex[:8]}",
        owner_id=user.id,
        name="xerova/catalog",
        default_branch="main",
    )
    db_session.add(repo)
    db_session.flush()

    # Critical finding in routes
    f_crit = SecurityFinding(
        id=f"FIND_FL1_{uuid.uuid4().hex[:6]}",
        repo_id=repo.id,
        scanner_name="Semgrep OSS",
        rule_identifier="sqli",
        cwe="CWE-89",
        title="SQL injection in catalog search",
        severity="CRITICAL",
        file_path="src/api/routes/search.py",
        line_number=14,
        code_excerpt="cursor.execute(f'SELECT * FROM items WHERE q={q}')",
    )
    # Low finding in utils
    f_low = SecurityFinding(
        id=f"FIND_FL2_{uuid.uuid4().hex[:6]}",
        repo_id=repo.id,
        scanner_name="Bandit",
        rule_identifier="B404",
        cwe="CWE-78",
        title="Subprocess imported in utility",
        severity="LOW",
        file_path="src/utils/subprocess_runner.py",
        line_number=2,
        code_excerpt="import subprocess",
    )
    db_session.add_all([f_crit, f_low])
    db_session.commit()

    token = create_access_token({"sub": user.id, "email": user.email})

    # 1. Fetch all findings -> both must include contextual_priority and priority_score
    res_all = client.get("/api/v1/findings", headers={"Authorization": f"Bearer {token}"})
    assert res_all.status_code == 200
    data_all = res_all.json()
    assert len(data_all) == 2
    for item in data_all:
        assert "contextual_priority" in item
        assert "priority_score" in item
        assert "remediation_readiness" in item

    # 2. Filter by priority=CRITICAL
    res_crit = client.get("/api/v1/findings?priority=CRITICAL", headers={"Authorization": f"Bearer {token}"})
    assert res_crit.status_code == 200
    data_crit = res_crit.json()
    assert len(data_crit) == 1
    assert data_crit[0]["id"] == f_crit.id
    assert data_crit[0]["contextual_priority"] == "CRITICAL"

    # 3. Filter by original scanner severity=LOW
    res_sev_low = client.get("/api/v1/findings?severity=LOW", headers={"Authorization": f"Bearer {token}"})
    assert res_sev_low.status_code == 200
    data_sev_low = res_sev_low.json()
    assert len(data_sev_low) == 1
    assert data_sev_low[0]["id"] == f_low.id
