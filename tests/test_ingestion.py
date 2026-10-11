"""Tests for secure repository ingestion workflows and security boundaries."""
import io
import os
from pathlib import Path
import zipfile
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.repository import Repository
from app.models.audit import AuditEvent


def create_test_zip(files: dict, comment: bytes = b"") -> io.BytesIO:
    """Helper to create an in-memory ZIP archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, content in files.items():
            zf.writestr(filename, content)
        if comment:
            zf.comment = comment
    buf.seek(0)
    return buf


def test_normal_zip_archive_ingestion(client_a: TestClient, db_session: Session):
    # Prepare normal zip with python and typescript files
    files = {
        "src/main.py": "def main():\n    print('Hello RepoShield')\n",
        "src/utils.py": "def helper():\n    return 42\n",
        "frontend/app.tsx": "export const App = () => <div>RepoShield</div>;\n",
        "README.md": "# Sample Project\n",
    }
    zip_buf = create_test_zip(files)

    response = client_a.post(
        "/api/v1/repositories/ingest/upload",
        files={"file": ("sample-service.zip", zip_buf.getvalue(), "application/zip")},
        data={"name": "sample-service"},
    )
    assert response.status_code == 201
    data = response.json()

    assert data["name"] == "sample-service"
    assert data["source_type"] == "zip_upload"
    assert data["ingestion_status"] == "completed"
    assert data["file_count"] == 4
    assert data["total_size_bytes"] > 0
    assert "Python" in data["language_metadata"] or "TypeScript" in data["language_metadata"]

    # Check status endpoint
    status_res = client_a.get(f"/api/v1/repositories/{data['id']}/ingestion-status")
    assert status_res.status_code == 200
    st_data = status_res.json()
    assert st_data["status"] == "completed"
    assert st_data["file_count"] == 4

    # Verify audit event logged
    audit = db_session.query(AuditEvent).filter(
        AuditEvent.resource_identifier == data["id"],
        AuditEvent.action == "REPOSITORY_INGESTION_ZIP_SUCCESS",
    ).first()
    assert audit is not None


def test_path_traversal_zip_archive_rejected(client_a: TestClient):
    # Zip Slip attack: filename attempting to traverse out of extraction directory
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.py", "malicious_code = True")
        zf.writestr("normal.py", "print('normal')")
    buf.seek(0)

    response = client_a.post(
        "/api/v1/repositories/ingest/upload",
        files={"file": ("traversal-test.zip", buf.getvalue(), "application/zip")},
        data={"name": "traversal-attack"},
    )
    assert response.status_code == 422
    err = response.json()
    assert err["success"] is False
    assert "Path traversal" in err["error"]["message"] or "traversal" in err["error"]["message"].lower()


def test_absolute_path_zip_archive_rejected(client_a: TestClient):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("/etc/passwd", "root:x:0:0::/root:/bin/sh")
    buf.seek(0)

    response = client_a.post(
        "/api/v1/repositories/ingest/upload",
        files={"file": ("abs-path.zip", buf.getvalue(), "application/zip")},
        data={"name": "abs-path-attack"},
    )
    assert response.status_code == 422
    err = response.json()
    assert "absolute path" in err["error"]["message"].lower()


def test_invalid_archive_not_a_zip(client_a: TestClient):
    # Plain text file sent as zip
    fake_zip = b"This is plain text and definitely not a valid zip archive file header."
    response = client_a.post(
        "/api/v1/repositories/ingest/upload",
        files={"file": ("fake.zip", fake_zip, "application/zip")},
        data={"name": "corrupt-repo"},
    )
    assert response.status_code == 422
    err = response.json()
    assert "not a valid ZIP" in err["error"]["message"] or "integrity" in err["error"]["message"].lower()


def test_empty_archive_rejected(client_a: TestClient):
    empty_bytes = b""
    response = client_a.post(
        "/api/v1/repositories/ingest/upload",
        files={"file": ("empty.zip", empty_bytes, "application/zip")},
        data={"name": "empty-repo"},
    )
    assert response.status_code == 422
    err = response.json()
    assert "empty" in err["error"]["message"].lower()


def test_oversized_archive_upload_rejected(client_a: TestClient, monkeypatch):
    # Temporarily set MAX_UPLOAD_SIZE_BYTES to 1KB to test limit enforcement
    monkeypatch.setattr(settings, "MAX_UPLOAD_SIZE_BYTES", 1024)

    # Create 2KB file
    large_payload = b"A" * 2048
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("large.txt", large_payload)
    buf.seek(0)

    response = client_a.post(
        "/api/v1/repositories/ingest/upload",
        files={"file": ("oversized.zip", buf.getvalue(), "application/zip")},
        data={"name": "oversized-repo"},
    )
    assert response.status_code == 422
    err = response.json()
    assert "exceeded maximum limit" in err["error"]["message"].lower() or "exceeds" in err["error"]["message"].lower()


def test_zip_bomb_expansion_ratio_rejected(client_a: TestClient, monkeypatch):
    # Temporarily set MAX_COMPRESSION_RATIO low to test zip bomb defense
    monkeypatch.setattr(settings, "MAX_COMPRESSION_RATIO", 5.0)

    # Highly compressible stream of zeros
    bomb_content = b"\x00" * 100000
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.bin", bomb_content)
    buf.seek(0)

    response = client_a.post(
        "/api/v1/repositories/ingest/upload",
        files={"file": ("zipbomb.zip", buf.getvalue(), "application/zip")},
        data={"name": "zipbomb-repo"},
    )
    assert response.status_code == 422
    err = response.json()
    assert "expansion ratio" in err["error"]["message"].lower() or "bomb" in err["error"]["message"].lower()


def test_malicious_git_urls_ssrf_blocked(client_a: TestClient):
    # 1. Loopback addresses
    res_loopback = client_a.post(
        "/api/v1/repositories/ingest/git",
        json={"git_url": "https://127.0.0.1/private-repo.git", "name": "ssrf-loopback"},
    )
    assert res_loopback.status_code == 403
    assert "restricted" in res_loopback.json()["error"]["message"].lower() or "ssrf" in res_loopback.json()["error"]["message"].lower()

    # 2. Localhost hostname
    res_localhost = client_a.post(
        "/api/v1/repositories/ingest/git",
        json={"git_url": "https://localhost:8080/repo.git", "name": "ssrf-localhost"},
    )
    assert res_localhost.status_code == 403

    # 3. Cloud metadata IP (169.254.169.254)
    res_metadata = client_a.post(
        "/api/v1/repositories/ingest/git",
        json={"git_url": "https://169.254.169.254/latest/meta-data/git", "name": "ssrf-aws"},
    )
    assert res_metadata.status_code == 403

    # 4. RFC1918 Private address (10.0.0.1)
    res_private = client_a.post(
        "/api/v1/repositories/ingest/git",
        json={"git_url": "https://10.0.0.1/internal.git", "name": "ssrf-10"},
    )
    assert res_private.status_code == 403

    # 5. Non-HTTPS protocol (e.g. file://, ssh://, ftp://)
    res_file = client_a.post(
        "/api/v1/repositories/ingest/git",
        json={"git_url": "file:///etc/passwd", "name": "protocol-smuggle"},
    )
    assert res_file.status_code == 403
    assert "unsupported git protocol" in res_file.json()["error"]["message"].lower()

    # 6. Embedded credentials in URL prohibited
    res_cred = client_a.post(
        "/api/v1/repositories/ingest/git",
        json={"git_url": "https://user:password123@github.com/xerova/test.git", "name": "cred-leak"},
    )
    assert res_cred.status_code == 422
    assert "credentials" in res_cred.json()["error"]["message"].lower()


def test_cross_tenant_ingestion_status_blocked(client_a: TestClient, client_b: TestClient):
    # Alice uploads a repository
    files = {"index.js": "console.log('secret repo');"}
    zip_buf = create_test_zip(files)

    create_res = client_a.post(
        "/api/v1/repositories/ingest/upload",
        files={"file": ("alice-secret.zip", zip_buf.getvalue(), "application/zip")},
        data={"name": "alice-secret-repo"},
    )
    assert create_res.status_code == 201
    repo_id = create_res.json()["id"]

    # Bob attempts to inspect Alice's ingestion status -> 403 Forbidden
    bob_res = client_b.get(f"/api/v1/repositories/{repo_id}/ingestion-status")
    assert bob_res.status_code == 403
    assert bob_res.json()["error"]["code"] == "FORBIDDEN"


def test_git_branch_option_injection_rejected(client_a: TestClient):
    """Verify that malicious branch parameters starting with '-' or containing path traversal are rejected."""
    # Option injection: --upload-pack
    res_opt = client_a.post(
        "/api/v1/repositories/ingest/git",
        json={"git_url": "https://github.com/xerova/test.git", "default_branch": "--upload-pack=touch /tmp/pwned"},
    )
    assert res_opt.status_code == 422

    # Option injection: -u
    res_flag = client_a.post(
        "/api/v1/repositories/ingest/git",
        json={"git_url": "https://github.com/xerova/test.git", "default_branch": "-u"},
    )
    assert res_flag.status_code == 422


def test_unencrypted_http_git_rejected(client_a: TestClient):
    """Verify that unencrypted HTTP git URLs are rejected with 403 Forbidden."""
    res_http = client_a.post(
        "/api/v1/repositories/ingest/git",
        json={"git_url": "http://github.com/xerova/test.git", "name": "insecure-http"},
    )
    assert res_http.status_code == 403
    assert "unsupported git protocol" in res_http.json()["error"]["message"].lower()
