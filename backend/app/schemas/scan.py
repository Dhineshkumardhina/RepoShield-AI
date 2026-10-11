"""Pydantic schemas for AppSec Scans."""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ScanCreate(BaseModel):
    repository_id: str
    scanner_configuration: Optional[str] = Field(default=None, examples=["rules: p/default, p/owasp-top-ten"])
    summary: Optional[str] = Field(default=None, examples=["Automated daily scan"])
    tools: Optional[List[str]] = Field(default=None, description="Optional list of specific scanner tools to run")
    timeout_seconds: Optional[int] = Field(default=60, ge=5, le=300, description="Timeout limit per scanner in seconds")


class ScanRead(BaseModel):
    id: str
    repository_id: str
    status: str
    scanner_configuration: Optional[str] = None
    started_at: datetime
    completed_at: Optional[datetime] = None
    summary: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScannerToolInfo(BaseModel):
    name: str
    display_name: str
    category: str
    is_available: bool
    version: Optional[str] = None


class ScannerRunSummary(BaseModel):
    scanner_name: str
    version: Optional[str] = None
    category: str
    status: str
    execution_time_seconds: float
    findings_count: int
    exit_code: Optional[int] = None
    error_message: Optional[str] = None


class ScanResultDetail(BaseModel):
    id: str
    repository_id: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    raw_summary: Optional[str] = None
    total_findings: int = 0
    scanners: List[ScannerRunSummary] = Field(default_factory=list)
    health_score_after: Optional[int] = None

