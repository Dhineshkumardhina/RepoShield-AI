"""Centralized API error handling and custom domain exceptions."""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .logging import get_logger

logger = get_logger("reposhield.errors")


class AppSecException(Exception):
    """Base exception for RepoShield AI domain errors."""

    def __init__(
        self,
        message: str,
        code: str = "APPSEC_ERROR",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Optional[List[Dict[str, Any]]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or []


class NotFoundError(AppSecException):
    def __init__(self, message: str = "Resource not found", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=message,
            code="RESOURCE_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
            details=details,
        )


class ValidationError(AppSecException):
    def __init__(self, message: str = "Validation failed", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=message,
            code="VALIDATION_FAILED",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details,
        )


class SecurityPolicyViolationError(AppSecException):
    def __init__(self, message: str = "Security policy violation", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=message,
            code="SECURITY_POLICY_VIOLATION",
            status_code=status.HTTP_403_FORBIDDEN,
            details=details,
        )


class RevokedCredentialError(AppSecException):
    def __init__(self, message: str = "GitHub integration credentials have expired or were revoked", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=message,
            code="CREDENTIALS_REVOKED",
            status_code=status.HTTP_401_UNAUTHORIZED,
            details=details,
        )


class UnauthorizedError(AppSecException):
    def __init__(self, message: str = "Authentication required or credentials invalid", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=message,
            code="UNAUTHORIZED",
            status_code=status.HTTP_401_UNAUTHORIZED,
            details=details,
        )


class ForbiddenError(AppSecException):
    def __init__(self, message: str = "Access forbidden: you do not have permission to access this resource", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=message,
            code="FORBIDDEN",
            status_code=status.HTTP_403_FORBIDDEN,
            details=details,
        )


class SessionExpiredError(AppSecException):
    def __init__(self, message: str = "Session or token has expired. Please log in again", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=message,
            code="SESSION_EXPIRED",
            status_code=status.HTTP_401_UNAUTHORIZED,
            details=details,
        )


class AccountInactiveError(AppSecException):
    def __init__(self, message: str = "Account is inactive or suspended", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=message,
            code="ACCOUNT_INACTIVE",
            status_code=status.HTTP_403_FORBIDDEN,
            details=details,
        )


class DatabaseError(AppSecException):
    def __init__(self, message: str = "Database operation failed", details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(
            message=message,
            code="DATABASE_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            details=details,
        )


def _get_request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "unknown")


def make_error_response(
    status_code: int,
    code: str,
    message: str,
    details: Optional[List[Dict[str, Any]]] = None,
    request_id: str = "unknown",
) -> JSONResponse:
    """Build a unified, standardized RFC-compatible JSON error envelope."""
    payload = {
        "success": False,
        "error": {
            "code": code,
            "message": message,
            "details": details or [],
        },
        "request_id": request_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return JSONResponse(status_code=status_code, content=payload)


async def appsec_exception_handler(request: Request, exc: AppSecException) -> JSONResponse:
    """Handler for domain-specific AppSec exceptions."""
    req_id = _get_request_id(request)
    logger.warning(
        f"Domain exception [{exc.code}] on {request.method} {request.url.path}: {exc.message}",
        extra={"request_id": req_id, "status_code": exc.status_code},
    )
    return make_error_response(
        status_code=exc.status_code,
        code=exc.code,
        message=exc.message,
        details=exc.details,
        request_id=req_id,
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Handler for Starlette/FastAPI HTTPExceptions."""
    req_id = _get_request_id(request)
    logger.warning(
        f"HTTP exception {exc.status_code} on {request.method} {request.url.path}: {exc.detail}",
        extra={"request_id": req_id, "status_code": exc.status_code},
    )
    return make_error_response(
        status_code=exc.status_code,
        code=f"HTTP_{exc.status_code}",
        message=str(exc.detail),
        request_id=req_id,
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handler for Pydantic input validation errors."""
    req_id = _get_request_id(request)
    formatted_errors = []
    for err in exc.errors():
        loc = " -> ".join([str(x) for x in err.get("loc", [])])
        formatted_errors.append({
            "field": loc,
            "message": err.get("msg", "Invalid value"),
            "type": err.get("type", "value_error"),
        })

    logger.info(
        f"Request validation failure on {request.method} {request.url.path}: {len(formatted_errors)} error(s)",
        extra={"request_id": req_id, "status_code": 422},
    )
    return make_error_response(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        code="VALIDATION_ERROR",
        message="Request payload failed schema validation",
        details=formatted_errors,
        request_id=req_id,
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler for unhandled exceptions."""
    req_id = _get_request_id(request)
    logger.error(
        f"Unhandled server error on {request.method} {request.url.path}: {str(exc)}",
        exc_info=True,
        extra={"request_id": req_id, "status_code": 500},
    )
    return make_error_response(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        code="INTERNAL_SERVER_ERROR",
        message="An unexpected server error occurred. Please contact the Xerova security operations team.",
        request_id=req_id,
    )
