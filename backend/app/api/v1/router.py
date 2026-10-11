"""Aggregated router for API v1."""
from fastapi import APIRouter
from .endpoints.health import router as health_router
from .endpoints.auth import router as auth_router
from .endpoints.repositories import router as repositories_router
from .endpoints.findings import router as findings_router
from .endpoints.scans import router as scans_router
from .endpoints.analyzer import router as analyzer_router
from .endpoints.verification import router as verification_router
from .endpoints.evidence import router as evidence_router
from .endpoints.integrations import router as integrations_router
from .endpoints.validation import router as validation_router
from .endpoints.prioritization import router as prioritization_router

api_v1_router = APIRouter()

api_v1_router.include_router(health_router, prefix="", tags=["Health & Diagnostics"])
api_v1_router.include_router(auth_router, prefix="/auth", tags=["Authentication & Session"])
api_v1_router.include_router(repositories_router, prefix="/repositories", tags=["Repositories"])
api_v1_router.include_router(findings_router, prefix="/findings", tags=["Findings"])
api_v1_router.include_router(prioritization_router, prefix="/prioritization", tags=["Contextual Risk Prioritization & Remediation Queue"])
api_v1_router.include_router(validation_router, prefix="/findings", tags=["Evidence-Driven Vulnerability Validation"])
api_v1_router.include_router(scans_router, prefix="/scans", tags=["Scans"])
api_v1_router.include_router(analyzer_router, prefix="", tags=["AI Security Analysis"])
api_v1_router.include_router(verification_router, prefix="/verifications", tags=["Fix Verification Engine"])
api_v1_router.include_router(evidence_router, prefix="/evidence", tags=["Security Evidence Management"])
api_v1_router.include_router(integrations_router, prefix="/integrations", tags=["GitHub & CI/CD Integrations"])


