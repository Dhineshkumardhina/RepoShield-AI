"""Pydantic schemas for Repositories and Ingestion workflows."""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class RepositoryBase(BaseModel):
    name: str = Field(min_length=1, max_length=255, examples=["xerova/auth-gateway"])
    source_type: str = Field(default="github", examples=["github", "zip_upload", "public_git"])
    language_metadata: Optional[str] = Field(default=None, examples=["Python, TypeScript"])
    git_url: Optional[str] = None
    default_branch: str = "main"
    health_score: int = Field(default=100, ge=0, le=100)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    is_active: bool = True
    ingestion_status: str = Field(default="completed", examples=["pending", "in_progress", "completed", "failed"])
    ingestion_error: Optional[str] = None
    file_count: int = 0
    total_size_bytes: int = 0


class RepositoryCreate(RepositoryBase):
    pass


class RepositoryRead(RepositoryBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    owner_id: str
    last_scanned_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class RepositoryGitIngestRequest(BaseModel):
    git_url: str = Field(..., description="Public Git clone URL using HTTPS protocol")
    name: Optional[str] = Field(default=None, description="Optional custom repository display name")
    default_branch: str = Field(default="main", pattern=r"^[a-zA-Z0-9_\-\./]+$", description="Git branch to clone")


class RepositoryIngestionStatusResponse(BaseModel):
    id: str
    name: str
    status: str
    source_type: str
    file_count: int
    total_size_bytes: int
    language_metadata: Optional[str] = None
    error: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
