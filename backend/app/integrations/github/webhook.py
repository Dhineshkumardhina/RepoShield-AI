"""GitHub Webhook security validator with HMAC-SHA256 signature check and replay defense."""
import hashlib
import hmac
from typing import Optional, Tuple
from sqlalchemy.orm import Session

from ...core.errors import AppSecException, ForbiddenError, UnauthorizedError
from ...core.logging import get_logger
from ...models.github import WebhookDelivery

logger = get_logger("reposhield.github.webhook")


class WebhookSecurityError(AppSecException):
    def __init__(self, message: str = "Webhook security verification failed"):
        super().__init__(message=message, code="WEBHOOK_SECURITY_ERROR", status_code=403)


def verify_webhook_signature(
    raw_payload: bytes,
    signature_header: Optional[str],
    webhook_secret: str,
) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature using constant-time comparison.
    
    Header format: sha256=<hex_digest>
    """
    if not signature_header or not webhook_secret:
        logger.warning("Webhook verification failed: missing signature header or secret")
        return False

    if not signature_header.startswith("sha256="):
        logger.warning(f"Webhook verification failed: invalid signature scheme in '{signature_header[:10]}'")
        return False

    expected_sig = signature_header[7:].strip()
    computed_mac = hmac.new(
        key=webhook_secret.encode("utf-8"),
        msg=raw_payload,
        digestmod=hashlib.sha256,
    ).hexdigest()

    # Constant-time comparison prevents timing attacks
    is_valid = hmac.compare_digest(expected_sig, computed_mac)
    if not is_valid:
        logger.warning("Webhook signature mismatch detected")
    return is_valid


def record_and_check_replay(
    db: Session,
    delivery_id: Optional[str],
    event_type: str,
    raw_payload: bytes,
) -> Tuple[bool, Optional[str]]:
    """Check X-GitHub-Delivery GUID to prevent webhook replay attacks.
    
    Returns:
        (is_accepted: bool, reason_if_rejected: Optional[str])
    """
    if not delivery_id:
        return False, "Missing X-GitHub-Delivery header (required for replay defense)"

    delivery_clean = delivery_id.strip()
    payload_hash = hashlib.sha256(raw_payload).hexdigest()

    existing = db.query(WebhookDelivery).filter(WebhookDelivery.id == delivery_clean).first()
    if existing:
        logger.warning(f"Replay attack or duplicate delivery blocked: {delivery_clean}")
        return False, f"Duplicate webhook delivery ID '{delivery_clean}' already processed (replay blocked)"

    # Record delivery
    record = WebhookDelivery(
        id=delivery_clean,
        event_type=event_type,
        payload_sha256=payload_hash,
        status="processed",
    )
    db.add(record)
    db.commit()

    return True, None


# Convenient aliases
verify_github_signature = verify_webhook_signature


def record_and_check_delivery(
    db: Session,
    delivery_id: Optional[str],
    event_type: str,
    installation_id: Optional[str] = None,
    repository_id: Optional[str] = None,
    raw_payload: bytes = b"",
) -> bool:
    """Record delivery and check for replay, returning True if accepted."""
    accepted, _ = record_and_check_replay(
        db=db,
        delivery_id=delivery_id,
        event_type=event_type,
        raw_payload=raw_payload,
    )
    return accepted
