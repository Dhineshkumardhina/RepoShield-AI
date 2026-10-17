"""FastAPI application bootstrap for RepoShield AI."""
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from .api.v1.router import api_v1_router
from .core.config import settings
from .core.errors import (
    AppSecException,
    appsec_exception_handler,
    http_exception_handler,
    unhandled_exception_handler,
    validation_exception_handler,
)
from .core.logging import get_logger, setup_logging
from .core.security import RequestSizeLimitMiddleware, SecurityHeadersMiddleware, hash_password
from .db.base import Base
from .db.session import engine, SessionLocal
from .models.user import User
from .models.repository import Repository
from .models.finding import SecurityFinding

# Initialize structured logging
setup_logging(level=settings.LOG_LEVEL, json_format=settings.LOG_FORMAT_JSON)
logger = get_logger("reposhield.main")


def seed_initial_dev_data() -> None:
    """Populates development database with initial sample AppSec entities if empty."""
    if settings.is_production or settings.APP_ENV not in ("development", "local_mock_dev"):
        logger.warning("Default seed data creation blocked in non-development environment.")
        return
    db = SessionLocal()
    try:
        # 1. Ensure dev seed user exists
        dev_user = db.query(User).filter(User.email == "dev@xerova.com").first()
        if not dev_user:
            dev_user = User(
                id="usr-dev-seed-001",
                email="dev@xerova.com",
                password_hash=hash_password("XerovaDevPass2026!"),
                account_status="active",
            )
            db.add(dev_user)
            db.commit()
            db.refresh(dev_user)

        if db.query(Repository).count() == 0:
            logger.info("Initializing development database with seed repositories and findings...")
            repos = [
                Repository(
                    id="repo-auth-gateway",
                    owner_id=dev_user.id,
                    name="xerova/auth-gateway",
                    source_type="github",
                    git_url="https://github.com/xerova/auth-gateway",
                    default_branch="main",
                    health_score=84,
                    critical_count=1,
                    high_count=2,
                    medium_count=4,
                    low_count=0,
                    is_active=True,
                ),
                Repository(
                    id="repo-billing-service",
                    owner_id=dev_user.id,
                    name="xerova/billing-service",
                    source_type="github",
                    git_url="https://github.com/xerova/billing-service",
                    default_branch="main",
                    health_score=72,
                    critical_count=2,
                    high_count=3,
                    medium_count=1,
                    low_count=1,
                    is_active=True,
                ),
                Repository(
                    id="repo-user-api",
                    owner_id=dev_user.id,
                    name="xerova/user-api",
                    source_type="github",
                    git_url="https://github.com/xerova/user-api",
                    default_branch="main",
                    health_score=96,
                    critical_count=0,
                    high_count=0,
                    medium_count=2,
                    low_count=1,
                    is_active=True,
                ),
            ]
            db.add_all(repos)
            db.commit()

            findings = [
                SecurityFinding(
                    id="FIND-418",
                    repo_id="repo-auth-gateway",
                    cwe="CWE-89: SQL Injection",
                    title="Raw SQL Query String Interpolation in user_query.py",
                    severity="CRITICAL",
                    scanner_name="Semgrep OSS",
                    file_path="auth-gateway/src/dao/user_query.py",
                    line_number=42,
                    status="open",
                    code_excerpt="cursor.execute(f'SELECT * FROM users WHERE tenant_id = {tenant_id} AND email = {email}')",
                    pr_number=418,
                    confidence_score=0.98,
                ),
                SecurityFinding(
                    id="FIND-402",
                    repo_id="repo-billing-service",
                    cwe="CWE-79: Cross-Site Scripting",
                    title="Unescaped HTML rendering in invoice template renderer",
                    severity="HIGH",
                    scanner_name="CodeQL",
                    file_path="billing/templates/invoice.py",
                    line_number=118,
                    status="open",
                    code_excerpt="return render_template_string(f'<div>Invoice for: {customer_name}</div>')",
                    pr_number=402,
                    confidence_score=0.92,
                ),
            ]
            db.add_all(findings)
            db.commit()
            logger.info("Seed data successfully committed.")
    except Exception as exc:
        db.rollback()
        logger.warning(f"Seed data insertion skipped: {exc}")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifecycle management."""
    logger.info(
        f"Starting {settings.APP_NAME} v{settings.APP_VERSION} [{settings.APP_ENV}] "
        f"for {settings.ORGANIZATION}"
    )

    # In local development with SQLite, ensure tables exist
    if settings.is_sqlite:
        logger.info("Verifying local SQLite database schema...")
        Base.metadata.create_all(bind=engine)
        seed_initial_dev_data()

    # Reconcile any interrupted or hanging jobs from previous server restarts
    try:
        reconcile_db = SessionLocal()
        from .core.quotas import reconcile_interrupted_jobs
        reconcile_interrupted_jobs(reconcile_db)
        reconcile_db.close()
    except Exception as exc:
        logger.warning(f"Failed to reconcile interrupted jobs on startup: {exc}")

    yield

    logger.info(f"Shutting down {settings.APP_NAME}...")


def create_application() -> FastAPI:
    """FastAPI application factory."""
    docs_url = "/docs" if (settings.DOCS_ENABLED and not settings.is_production) else None
    redoc_url = "/redoc" if (settings.DOCS_ENABLED and not settings.is_production) else None
    openapi_url = f"{settings.API_V1_PREFIX}/openapi.json" if (settings.DOCS_ENABLED and not settings.is_production) else None

    app = FastAPI(
        title=f"{settings.APP_NAME} API",
        description="Application Security & Automated Fix Verification Engine by Xerova Digital Solutions.",
        version=settings.APP_VERSION,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=lifespan,
    )

    # 1. Custom Security Headers & Correlation ID
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestSizeLimitMiddleware)

    # 2. CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # 3. Centralized Exception Handlers
    app.add_exception_handler(AppSecException, appsec_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)

    # 4. Mount API Routes
    app.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)

    # Root route for API discovery
    @app.get("/", tags=["Discovery"])
    def root_discovery():
        return {
            "name": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "organization": settings.ORGANIZATION,
            "status": "operational",
            "documentation": "/docs",
            "health": f"{settings.API_V1_PREFIX}/health",
        }

    # Top-level health endpoints
    @app.get("/health", tags=["Health & Diagnostics"])
    @app.get("/api/health", tags=["Health & Diagnostics"])
    def top_level_health():
        from .api.v1.endpoints.health import get_service_health
        return get_service_health()

    @app.get("/live", tags=["Health & Diagnostics"])
    def top_level_live():
        from .api.v1.endpoints.health import liveness_probe
        return liveness_probe()

    @app.get("/ready", tags=["Health & Diagnostics"])
    def top_level_ready():
        from .api.v1.endpoints.health import readiness_probe
        return readiness_probe()

    return app


app = create_application()
