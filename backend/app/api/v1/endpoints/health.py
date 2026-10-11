"""Health-check and readiness endpoints."""
import time
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ....core.config import settings
from ....db.session import check_db_connection, get_db
from ....schemas.health import HealthResponse, DatabaseHealth

router = APIRouter()
START_TIME = time.time()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Comprehensive service and database health check",
    description="Returns service availability, version, environment, database status, and uptime.",
)
def get_service_health() -> HealthResponse:
    db_connected = check_db_connection()
    dialect = "sqlite" if settings.is_sqlite else "postgresql"
    uptime = round(time.time() - START_TIME, 2)

    status_str = "ok" if db_connected else "degraded"

    return HealthResponse(
        status=status_str,
        service=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.APP_ENV,
        timestamp=datetime.now(timezone.utc),
        database=DatabaseHealth(
            status="connected" if db_connected else "disconnected",
            dialect=dialect,
        ),
        uptime_seconds=uptime,
    )


@router.get(
    "/ready",
    summary="Kubernetes / Docker readiness probe",
    description="Returns 200 OK only when backend database connections are verified.",
)
def readiness_probe() -> JSONResponse:
    if check_db_connection():
        return JSONResponse(status_code=status.HTTP_200_OK, content={"status": "ready"})
    return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"status": "database_unavailable"})


@router.get(
    "/live",
    summary="Kubernetes / Docker liveness probe",
    description="Returns 200 OK if the ASGI process is running.",
)
def liveness_probe() -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_200_OK, content={"status": "alive"})
