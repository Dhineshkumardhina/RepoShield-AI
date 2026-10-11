"""Pydantic schemas for service health checks."""
from datetime import datetime
from pydantic import BaseModel, Field


class DatabaseHealth(BaseModel):
    status: str = Field(description="Database connection state (connected, disconnected)")
    dialect: str = Field(description="SQL dialect in use (sqlite, postgresql, etc.)")


class HealthResponse(BaseModel):
    status: str = Field(examples=["ok"], description="Overall service status")
    service: str = Field(examples=["RepoShield AI API"], description="Service identifier")
    version: str = Field(examples=["0.1.0"], description="Semver version")
    environment: str = Field(examples=["development"], description="Runtime environment")
    timestamp: datetime = Field(description="UTC timestamp of the check")
    database: DatabaseHealth = Field(description="Database connectivity health")
    uptime_seconds: float = Field(description="Seconds since service start")
