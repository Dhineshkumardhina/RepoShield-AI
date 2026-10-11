"""Database models and transaction persistence tests."""
import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.user import User
from app.models.repository import Repository
from app.models.scan import Scan
from app.models.finding import SecurityFinding
from app.models.patch import PatchProposal
from app.models.verification import VerificationRun, VerificationEvidence, FixVerification
from app.models.audit import AuditEvent
from app.core.security import hash_password


def test_repository_model_persistence(db_session: Session):
    user = User(
        email=f"owner_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash=hash_password("SecurePassword123!"),
        account_status="active",
    )
    db_session.add(user)
    db_session.commit()

    unique_name = f"xerova/test-repo-{uuid.uuid4().hex[:6]}"
    repo = Repository(
        owner_id=user.id,
        name=unique_name,
        source_type="github",
        language_metadata="Python, TypeScript",
        git_url=f"https://github.com/{unique_name}",
        default_branch="main",
        health_score=92,
        critical_count=0,
        high_count=1,
    )
    db_session.add(repo)
    db_session.commit()
    db_session.refresh(repo)

    assert repo.id is not None
    assert repo.owner_id == user.id
    assert repo.name == unique_name
    assert repo.source_type == "github"
    assert repo.created_at is not None
    assert repo.updated_at is not None
    assert repo.health_score == 92
    assert repo.owner.email == user.email


def test_finding_and_verification_relationships(db_session: Session):
    user = User(
        email=f"tester_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash=hash_password("SecurePassword123!"),
        account_status="active",
    )
    db_session.add(user)
    db_session.commit()

    repo = Repository(
        owner_id=user.id,
        name=f"xerova/findings-test-{uuid.uuid4().hex[:6]}",
        git_url="https://github.com/xerova/findings-test",
    )
    db_session.add(repo)
    db_session.commit()

    # 1. Create Scan
    scan = Scan(
        repository_id=repo.id,
        status="completed",
        scanner_configuration="rules: p/default",
        summary="Scan finished with 1 finding",
    )
    db_session.add(scan)
    db_session.commit()

    # 2. Create Finding
    finding = SecurityFinding(
        repo_id=repo.id,
        scan_id=scan.id,
        scanner_identifier="Semgrep OSS",
        scanner_name="Semgrep OSS",
        rule_identifier="CWE-89",
        cwe="CWE-89: SQL Injection",
        title="SQL Injection in auth handler",
        category="vulnerability",
        severity="CRITICAL",
        confidence="HIGH",
        file_path="src/auth.py",
        line_number=25,
        line_information="25",
        status="open",
        finding_status="open",
        code_excerpt="cursor.execute('SELECT * FROM users WHERE id = ' + uid)",
    )
    db_session.add(finding)
    db_session.commit()

    # 3. Create Patch Proposal
    patch = PatchProposal(
        finding_id=finding.id,
        proposed_diff_reference="- cursor.execute('SELECT * FROM users WHERE id = ' + uid)\n+ cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))",
        ai_explanation="Replaces string concatenation with parameterized SQL query placeholder.",
        review_status="approved",
    )
    db_session.add(patch)
    db_session.commit()

    # 4. Create Verification Run and Evidence
    v_run = VerificationRun(
        patch_proposal_id=patch.id,
        status="passed",
        test_summary="10/10 test suites passed cleanly with 0 regressions.",
    )
    db_session.add(v_run)
    db_session.commit()

    evidence = VerificationEvidence(
        verification_run_id=v_run.id,
        evidence_type="test_log",
        result="passed",
        tool_name_and_version="pytest-9.1.1",
        evidence_reference="logs/pytest_run_418.log",
    )
    db_session.add(evidence)
    db_session.commit()

    # Query back and verify complete object graph relationships
    fetched_finding = db_session.query(SecurityFinding).filter(SecurityFinding.id == finding.id).first()
    assert fetched_finding is not None
    assert fetched_finding.repository.id == repo.id
    assert fetched_finding.scan.id == scan.id
    assert len(fetched_finding.patch_proposals) == 1

    fetched_patch = fetched_finding.patch_proposals[0]
    assert len(fetched_patch.verification_runs) == 1
    assert fetched_patch.verification_runs[0].status == "passed"
    assert len(fetched_patch.verification_runs[0].evidence) == 1
    assert fetched_patch.verification_runs[0].evidence[0].tool_name_and_version == "pytest-9.1.1"


def test_audit_event_logging(db_session: Session):
    user = User(
        email=f"auditor_{uuid.uuid4().hex[:6]}@xerova.com",
        password_hash=hash_password("SecurePassword123!"),
        account_status="active",
    )
    db_session.add(user)
    db_session.commit()

    event = AuditEvent(
        actor_id=user.id,
        action="REPOSITORY_DELETED",
        resource_type="repository",
        resource_identifier="repo-12345",
        safe_metadata='{"reason": "decommissioned"}',
    )
    db_session.add(event)
    db_session.commit()

    fetched = db_session.query(AuditEvent).filter(AuditEvent.id == event.id).first()
    assert fetched is not None
    assert fetched.actor.email == user.email
    assert fetched.action == "REPOSITORY_DELETED"
