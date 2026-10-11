"""Safe audit event logger preventing secret leakage."""
import json
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

from .logging import get_logger
from ..models.audit import AuditEvent

logger = get_logger("reposhield.audit")

SENSITIVE_KEYS = {
    "password", "password_hash", "token", "access_token", "refresh_token",
    "secret", "secret_key", "authorization", "cookie", "api_key", "key"
}


def sanitize_metadata(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Recursively redact passwords, keys, and tokens from metadata."""
    if not data:
        return {}
    clean = {}
    for k, v in data.items():
        if any(sens in k.lower() for sens in SENSITIVE_KEYS):
            clean[k] = "[REDACTED]"
        elif isinstance(v, dict):
            clean[k] = sanitize_metadata(v)
        elif isinstance(v, (str, int, float, bool)) or v is None:
            clean[k] = v
        else:
            clean[k] = str(v)
    return clean


def record_audit_event(
    db: Session,
    action: str,
    resource_type: str,
    resource_identifier: Optional[str] = None,
    actor_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[AuditEvent]:
    """Persist an audit event safely to the database and logger."""
    try:
        clean_meta = sanitize_metadata(metadata)
        meta_json = json.dumps(clean_meta) if clean_meta else None
        
        event = AuditEvent(
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_identifier=str(resource_identifier) if resource_identifier else None,
            safe_metadata=meta_json,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        
        logger.info(
            f"AUDIT [{action}] by actor={actor_id or 'anonymous'} on {resource_type}:{resource_identifier or 'none'}",
            extra={"action": action, "actor_id": actor_id, "resource_type": resource_type},
        )
        return event
    except Exception as exc:
        db.rollback()
        logger.error(f"Failed to record audit event: {exc}", exc_info=True)
        return None
