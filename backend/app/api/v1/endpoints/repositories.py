"""Repositories management and secure ingestion API endpoints."""
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import List, Optional
from fastapi import APIRouter, Depends, File, Form, Query, UploadFile, status
from sqlalchemy.orm import Session

from ....core.audit import record_audit_event
from ....core.auth import get_current_user, verify_repository_ownership
from ....core.config import settings
from ....core.errors import SecurityPolicyViolationError, ValidationError
from ....core.ingestion import (
    clone_git_repository,
    get_repository_workspace,
    validate_and_extract_zip,
    validate_git_url,
)
from ....db.session import get_db
from ....models.repository import Repository
from ....models.user import User
from ....schemas.repository import (
    RepositoryCreate,
    RepositoryGitIngestRequest,
    RepositoryIngestionStatusResponse,
    RepositoryRead,
)

router = APIRouter()


@router.get(
    "",
    response_model=List[RepositoryRead],
    summary="List code repositories owned by the authenticated user",
)
def list_repositories(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    active_only: bool = Query(True),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[Repository]:
    query = db.query(Repository).filter(Repository.owner_id == current_user.id)
    if active_only:
        query = query.filter(Repository.is_active == True)
    return query.offset(skip).limit(limit).all()


@router.post(
    "",
    response_model=RepositoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register a repository under the authenticated user account",
)
def create_repository(
    repo_in: RepositoryCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Repository:
    # Check if this user already registered a repo with this name
    existing = db.query(Repository).filter(
        Repository.name == repo_in.name,
        Repository.owner_id == current_user.id,
    ).first()
    if existing:
        raise ValidationError(f"Repository '{repo_in.name}' is already registered under your account.")

    repo = Repository(
        owner_id=current_user.id,
        name=repo_in.name,
        source_type=repo_in.source_type,
        language_metadata=repo_in.language_metadata,
        git_url=repo_in.git_url,
        default_branch=repo_in.default_branch,
        health_score=repo_in.health_score,
        critical_count=repo_in.critical_count,
        high_count=repo_in.high_count,
        medium_count=repo_in.medium_count,
        low_count=repo_in.low_count,
        is_active=repo_in.is_active,
        ingestion_status="completed",
    )
    db.add(repo)
    db.commit()
    db.refresh(repo)

    record_audit_event(
        db=db,
        action="REPOSITORY_REGISTERED",
        resource_type="repository",
        resource_identifier=repo.id,
        actor_id=current_user.id,
        metadata={"repo_name": repo.name},
    )

    return repo


@router.post(
    "/ingest/upload",
    response_model=RepositoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a source code repository from a secure ZIP archive",
)
async def ingest_zip_archive(
    file: UploadFile = File(..., description="ZIP archive containing source code"),
    name: Optional[str] = Form(None, description="Optional custom repository name"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Repository:
    """Securely uploads and unpacks a ZIP archive into an isolated repository workspace.

    Enforces:
    - Upload file size quota (50 MB)
    - Zip Slip / path traversal rejection
    - Absolute path rejection
    - Zip Bomb expansion ratio check
    - Max file count limit (5,000 files)
    - Executable/binary file filtration
    """
    # 1. Determine safe repository display name
    raw_filename = file.filename or "uploaded-archive.zip"
    if name and name.strip():
        repo_name = name.strip()
    else:
        # Strip dangerous extension and chars from filename
        clean_base = re.sub(r"[^a-zA-Z0-9_\-\.]", "-", raw_filename)
        clean_base = re.sub(r"\.zip$", "", clean_base, flags=re.IGNORECASE)
        repo_name = clean_base.strip(".-") or "unnamed-repository"

    # Check name collision for this user
    existing = db.query(Repository).filter(
        Repository.name == repo_name,
        Repository.owner_id == current_user.id,
    ).first()
    if existing:
        raise ValidationError(f"Repository '{repo_name}' is already registered under your account.")

    # 2. Initialize repository record in database
    repo = Repository(
        owner_id=current_user.id,
        name=repo_name,
        source_type="zip_upload",
        ingestion_status="in_progress",
        is_active=True,
    )
    db.add(repo)
    db.commit()
    db.refresh(repo)

    # 3. Stream upload into isolated temporary file with size cap
    temp_zip_file = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
            temp_zip_file = Path(tmp.name)
            bytes_received = 0
            chunk_size = 1024 * 1024  # 1 MB chunk

            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                bytes_received += len(chunk)
                if bytes_received > settings.MAX_UPLOAD_SIZE_BYTES:
                    raise ValidationError(
                        f"Upload size exceeded maximum limit of {settings.MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB."
                    )
                tmp.write(chunk)

        # 4. Resolve isolated workspace path
        workspace_dir = get_repository_workspace(current_user.id, repo.id)

        # 5. Validate and extract with Zip Slip & bomb defenses
        file_count, total_bytes, language_metadata = validate_and_extract_zip(
            zip_path=temp_zip_file,
            dest_dir=workspace_dir,
        )

        # 6. Update repository with metadata
        repo.ingestion_status = "completed"
        repo.file_count = file_count
        repo.total_size_bytes = total_bytes
        repo.language_metadata = language_metadata
        repo.workspace_path = str(workspace_dir)
        db.commit()
        db.refresh(repo)

        record_audit_event(
            db=db,
            action="REPOSITORY_INGESTION_ZIP_SUCCESS",
            resource_type="repository",
            resource_identifier=repo.id,
            actor_id=current_user.id,
            metadata={
                "repo_name": repo.name,
                "file_count": file_count,
                "total_bytes": total_bytes,
                "languages": language_metadata,
            },
        )

        return repo

    except Exception as exc:
        db.rollback()
        repo.ingestion_status = "failed"
        repo.ingestion_error = str(exc)[:1000]
        db.commit()

        record_audit_event(
            db=db,
            action="REPOSITORY_INGESTION_ZIP_FAILED",
            resource_type="repository",
            resource_identifier=repo.id,
            actor_id=current_user.id,
            metadata={"error": str(exc)},
        )
        raise exc

    finally:
        # Clean up temporary upload file
        if temp_zip_file and temp_zip_file.exists():
            try:
                os.remove(temp_zip_file)
            except OSError:
                pass


@router.post(
    "/ingest/git",
    response_model=RepositoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a public Git repository with SSRF defense",
)
def ingest_git_repository(
    payload: RepositoryGitIngestRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Repository:
    """Clones a public Git repository safely with strict SSRF defense.

    Enforces:
    - Allowed protocols (HTTPS only)
    - IP range restrictions (blocks 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254, ::1)
    - DNS resolution validation for every resolved IP
    - Credentials in URL blocked
    - Git hooks disabled during clone
    - Execution timeout (60s)
    """
    # 1. Strictly validate and sanitize URL against SSRF
    sanitized_url = validate_git_url(payload.git_url, allow_private=settings.ALLOW_PRIVATE_NETWORKS)

    # 2. Determine repository name
    if payload.name and payload.name.strip():
        repo_name = payload.name.strip()
    else:
        # Extract name from URL path, e.g., "https://github.com/xerova/core.git" -> "core"
        url_path = sanitized_url.rstrip("/").split("/")[-1]
        repo_name = re.sub(r"\.git$", "", url_path, flags=re.IGNORECASE) or "git-repo"

    # Check collision for user
    existing = db.query(Repository).filter(
        Repository.name == repo_name,
        Repository.owner_id == current_user.id,
    ).first()
    if existing:
        raise ValidationError(f"Repository '{repo_name}' is already registered under your account.")

    # 3. Create repository record
    repo = Repository(
        owner_id=current_user.id,
        name=repo_name,
        source_type="public_git",
        git_url=sanitized_url,
        default_branch=payload.default_branch or "main",
        ingestion_status="in_progress",
        is_active=True,
    )
    db.add(repo)
    db.commit()
    db.refresh(repo)

    try:
        workspace_dir = get_repository_workspace(current_user.id, repo.id)

        file_count, total_bytes, language_metadata = clone_git_repository(
            git_url=sanitized_url,
            dest_dir=workspace_dir,
            branch=payload.default_branch or "main",
            timeout=settings.GIT_CLONE_TIMEOUT_SECONDS,
        )

        repo.ingestion_status = "completed"
        repo.file_count = file_count
        repo.total_size_bytes = total_bytes
        repo.language_metadata = language_metadata
        repo.workspace_path = str(workspace_dir)
        db.commit()
        db.refresh(repo)

        record_audit_event(
            db=db,
            action="REPOSITORY_INGESTION_GIT_SUCCESS",
            resource_type="repository",
            resource_identifier=repo.id,
            actor_id=current_user.id,
            metadata={
                "repo_name": repo.name,
                "git_url": sanitized_url,
                "file_count": file_count,
                "total_bytes": total_bytes,
                "languages": language_metadata,
            },
        )

        return repo

    except Exception as exc:
        db.rollback()
        repo.ingestion_status = "failed"
        repo.ingestion_error = str(exc)[:1000]
        db.commit()

        record_audit_event(
            db=db,
            action="REPOSITORY_INGESTION_GIT_FAILED",
            resource_type="repository",
            resource_identifier=repo.id,
            actor_id=current_user.id,
            metadata={"git_url": sanitized_url, "error": str(exc)},
        )
        raise exc


@router.get(
    "/{repo_id}/ingestion-status",
    response_model=RepositoryIngestionStatusResponse,
    summary="Get ingestion processing status and metadata for a repository",
)
def get_ingestion_status(
    repo_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> RepositoryIngestionStatusResponse:
    repo = verify_repository_ownership(repo_id=repo_id, current_user=current_user, db=db)
    return RepositoryIngestionStatusResponse(
        id=repo.id,
        name=repo.name,
        status=repo.ingestion_status,
        source_type=repo.source_type,
        file_count=repo.file_count,
        total_size_bytes=repo.total_size_bytes,
        language_metadata=repo.language_metadata,
        error=repo.ingestion_error,
        created_at=repo.created_at,
        updated_at=repo.updated_at,
    )


@router.get(
    "/{repo_id}",
    response_model=RepositoryRead,
    summary="Get repository details by ID, enforcing tenant ownership",
)
def get_repository(
    repo_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Repository:
    repo = verify_repository_ownership(repo_id=repo_id, current_user=current_user, db=db)
    return repo


@router.delete(
    "/{repo_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete repository, cascading findings/scans and purging workspace files",
)
def delete_repository(
    repo_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    repo = verify_repository_ownership(repo_id=repo_id, current_user=current_user, db=db)
    workspace = repo.workspace_path
    repo_name = repo.name

    # 1. Purge workspace from filesystem
    if workspace and os.path.exists(workspace):
        shutil.rmtree(workspace, ignore_errors=True)

    # 2. Delete database entity (cascades to findings and scans)
    db.delete(repo)
    db.commit()

    # 3. Log audit event
    record_audit_event(
        db=db,
        action="REPOSITORY_DELETED",
        resource_type="repository",
        resource_identifier=repo_id,
        actor_id=current_user.id,
        metadata={"repo_name": repo_name},
    )

