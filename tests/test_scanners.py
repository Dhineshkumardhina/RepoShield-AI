"""Tests for real security scanners in RepoShield AI.

Validates:
1. Bandit adapter detects real Python AST vulnerabilities (SQL injection, command execution).
2. pip-audit adapter queries live advisory database and detects known vulnerable dependencies.
3. Built-in secret scanner detects credentials and verifies redaction.
4. Gitleaks adapter safely handles missing binary without crashing.
5. Scanner Registry provides accurate tool discovery and version information.
6. Full end-to-end scan execution updates repository metrics, health score, and normalized findings.
"""
import os
from pathlib import Path
import shutil
import tempfile
import pytest
from sqlalchemy.orm import Session

from app.scanner.bandit import BanditScannerAdapter
from app.scanner.pip_audit import PipAuditScannerAdapter
from app.scanner.secret_detector import SecretScannerAdapter
from app.scanner.gitleaks import GitleaksScannerAdapter
from app.scanner.semgrep import SemgrepScannerAdapter
from app.scanner.registry import scanner_registry
from app.scanner.base import ScannerStatus
from app.models.repository import Repository
from app.models.finding import SecurityFinding
from app.models.scan import Scan


@pytest.fixture
def sample_vulnerable_project():
    """Create an isolated temporary repository containing controlled test security issues."""
    temp_dir = tempfile.mkdtemp(prefix="reposhield_test_sample_")
    proj_path = Path(temp_dir)

    # 1. Python source file with SQL injection and Command injection
    vuln_code = (
        "import os\n"
        "import sqlite3\n"
        "\n"
        "def query_user(user_id):\n"
        "    db = sqlite3.connect(':memory:')\n"
        "    # SQL Injection pattern\n"
        "    query = \"SELECT * FROM accounts WHERE id = '\" + user_id + \"'\"\n"
        "    return db.execute(query).fetchall()\n"
        "\n"
        "def ping_server(target):\n"
        "    # Command injection pattern\n"
        "    os.system('ping ' + target)\n"
    )
    (proj_path / "app.py").write_text(vuln_code, encoding="utf-8")

    # 2. Dependency manifest with known vulnerable package (Jinja2 2.10)
    # CVE-2020-28493, CVE-2019-10906
    requirements_content = "jinja2==2.10\nrequests==2.25.1\n"
    (proj_path / "requirements.txt").write_text(requirements_content, encoding="utf-8")

    # 3. Source file with exposed credentials to verify detection and redaction
    config_code = (
        "# Configuration file with credentials\n"
        "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        "STRIPE_KEY = 'FAKE_STRIPE_KEY_FOR_TESTING_ONLY'\n"
    )
    (proj_path / "config.py").write_text(config_code, encoding="utf-8")

    yield proj_path

    # Cleanup temporary workspace
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_scanner_registry_discovery():
    """Verify registry discovers tools and reports metadata without errors."""
    scanners = scanner_registry.describe_scanners()
    assert len(scanners) >= 4

    names = [s["name"] for s in scanners]
    assert "bandit" in names
    assert "pip_audit" in names
    assert "secret_detector" in names
    assert "semgrep" in names

    # Secret detector should always be available
    secret_meta = next(s for s in scanners if s["name"] == "secret_detector")
    assert secret_meta["is_available"] is True

    # Bandit should be available in this environment
    bandit_meta = next(s for s in scanners if s["name"] == "bandit")
    assert bandit_meta["is_available"] is True
    assert bandit_meta["version"] is not None


def test_bandit_scanner_on_controlled_code(sample_vulnerable_project):
    """Verify Bandit runs real AST security checks and detects SQL and OS command injection."""
    adapter = BanditScannerAdapter()
    assert adapter.is_available() is True

    result = adapter.scan(target_dir=sample_vulnerable_project, scan_id="test-scan-bandit")

    assert result.status == ScannerStatus.SUCCESS
    assert result.execution_time_seconds > 0
    assert len(result.findings) >= 2

    rule_ids = [f.scanner_rule_id for f in result.findings]
    # B608: SQL injection, B605: start_process_with_a_shell (os.system)
    assert any("B608" in r or "B605" in r for r in rule_ids)

    # Verify normalized fields
    finding = result.findings[0]
    assert finding.scanner_name == adapter.display_name
    assert finding.file_path == "app.py"
    assert finding.start_line > 0
    assert finding.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert finding.cwe is not None
    assert finding.evidence_reference is not None


def test_pip_audit_on_vulnerable_manifest(sample_vulnerable_project):
    """Verify pip-audit analyzes requirements.txt and surfaces real CVEs."""
    adapter = PipAuditScannerAdapter()
    assert adapter.is_available() is True

    result = adapter.scan(target_dir=sample_vulnerable_project, scan_id="test-scan-pip-audit")

    assert result.status == ScannerStatus.SUCCESS
    assert len(result.findings) > 0

    # Ensure findings identify Jinja2 vulnerabilities
    pkg_findings = [f for f in result.findings if "jinja2" in f.scanner_message.lower()]
    assert len(pkg_findings) > 0

    vuln = pkg_findings[0]
    assert vuln.vulnerability_category.startswith("CWE-")
    assert vuln.severity == "HIGH"
    assert vuln.file_path == "requirements.txt"
    assert "jinja2==2.10" in vuln.evidence_reference


def test_secret_scanner_redacts_evidence(sample_vulnerable_project):
    """Verify secret detector flags exposed tokens and strictly masks the sensitive content."""
    adapter = SecretScannerAdapter()
    assert adapter.is_available() is True

    result = adapter.scan(target_dir=sample_vulnerable_project, scan_id="test-scan-secret")

    assert result.status == ScannerStatus.SUCCESS
    assert len(result.findings) >= 2

    rule_ids = [f.scanner_rule_id for f in result.findings]
    assert "SEC-AWS-KEY" in rule_ids

    aws_finding = next(f for f in result.findings if f.scanner_rule_id == "SEC-AWS-KEY")
    assert aws_finding.severity == "CRITICAL"
    assert aws_finding.file_path == "config.py"

    # Strictly verify secret is redacted in evidence and not leaked in raw text
    assert "AKIAIOSFODNN7EXAMPLE" not in aws_finding.evidence_reference
    assert "[REDACTED_AWS_KEY]" in aws_finding.evidence_reference


def test_semgrep_scanner_adapter_execution(sample_vulnerable_project):
    """Verify Semgrep adapter executes rules and produces normalized findings."""
    adapter = SemgrepScannerAdapter()
    if not adapter.is_available():
        pytest.skip("Semgrep not installed in test environment")

    # Define a custom local rule targeting the os.system pattern in app.py
    rule_file = sample_vulnerable_project / "semgrep_rule.yaml"
    rule_file.write_text(
        "rules:\n"
        "  - id: python-command-exec\n"
        "    patterns:\n"
        "      - pattern: os.system(...)\n"
        "    message: Unsafe operating system command execution\n"
        "    languages: [python]\n"
        "    severity: ERROR\n"
        "    metadata:\n"
        "      cwe: \"CWE-78: OS Command Injection\"\n",
        encoding="utf-8",
    )

    result = adapter.scan(
        target_dir=sample_vulnerable_project,
        scan_id="test-scan-semgrep",
        options={"config": str(rule_file)},
    )
    assert result.status == ScannerStatus.SUCCESS
    assert len(result.findings) >= 1
    f = result.findings[0]
    assert f.scanner_name == adapter.display_name
    assert f.file_path == "app.py"
    assert f.severity == "CRITICAL"
    assert "CWE-78" in f.vulnerability_category


def test_gitleaks_missing_binary_graceful_handling(sample_vulnerable_project):
    """Verify Gitleaks adapter reports TOOL_NOT_INSTALLED gracefully if binary is not present."""
    adapter = GitleaksScannerAdapter()
    if not adapter.is_available():
        res = adapter.scan(sample_vulnerable_project, scan_id="test-scan-gitleaks")
        assert res.status == ScannerStatus.TOOL_NOT_INSTALLED
        assert "not installed" in res.error_message.lower()


def test_full_scan_pipeline_and_results_api(auth_client, db_session: Session, sample_vulnerable_project):
    """End-to-end test: Ingest repository, trigger scan via API, and verify results."""
    user = auth_client.current_user

    # Create repository in DB with workspace set to the sample vulnerable project
    repo = Repository(
        owner_id=user.id,
        name="test-security-repo",
        source_type="local",
        default_branch="main",
        health_score=100,
        workspace_path=str(sample_vulnerable_project),
        ingestion_status="completed",
        file_count=3,
    )
    db_session.add(repo)
    db_session.commit()
    db_session.refresh(repo)

    # 1. Query available tools endpoint
    tools_res = auth_client.get("/api/v1/scans/tools")
    assert tools_res.status_code == 200
    tools_data = tools_res.json()
    assert isinstance(tools_data, list)
    assert any(t["name"] == "bandit" for t in tools_data)
    assert any(t["name"] == "pip_audit" for t in tools_data)

    # 2. Trigger real scan via POST /api/v1/scans with Bandit, pip-audit, and Secret Detector
    scan_res = auth_client.post(
        "/api/v1/scans",
        json={
            "repository_id": repo.id,
            "tools": ["bandit", "pip_audit", "secret_detector"],
            "summary": "Automated security integration test scan",
        },
    )
    assert scan_res.status_code == 201
    scan_data = scan_res.json()
    scan_id = scan_data["id"]
    assert scan_data["status"] == "completed"

    # 3. Verify repository metrics were updated
    db_session.refresh(repo)
    assert repo.health_score < 100
    assert repo.last_scanned_at is not None
    assert (repo.critical_count + repo.high_count + repo.medium_count) > 0

    # 4. Verify SecurityFinding rows exist in DB
    findings = db_session.query(SecurityFinding).filter(SecurityFinding.repo_id == repo.id).all()
    assert len(findings) >= 3

    # 5. Query detailed scan results endpoint
    results_res = auth_client.get(f"/api/v1/scans/{scan_id}/results")
    assert results_res.status_code == 200
    res_data = results_res.json()
    assert res_data["id"] == scan_id
    assert res_data["status"] == "completed"
    assert res_data["total_findings"] >= 3
    assert len(res_data["scanners"]) == 3
    assert res_data["health_score_after"] == repo.health_score

    # Check scanner reports
    scanner_names = [s["scanner_name"] for s in res_data["scanners"]]
    assert any("Bandit" in name for name in scanner_names)
    assert any("pip-audit" in name for name in scanner_names)
    assert any("Secret" in name for name in scanner_names)
