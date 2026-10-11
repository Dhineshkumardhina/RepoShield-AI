"""Sanitization and content hashing utilities for Security Evidence."""
import hashlib
import json
import re
from typing import Any

# Regex patterns for high-entropy secrets and sensitive tokens
SECRET_PATTERNS = [
    # Private keys
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    # AWS Access Key ID & Secret
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "[REDACTED_AWS_KEY]"),
    # GitHub Tokens: Fine-grained PATs, classic PATs, OAuth, server, user-to-server
    (re.compile(r"\b(github_pat_[a-zA-Z0-9_]{22,82})\b"), "[REDACTED_GITHUB_PAT]"),
    (re.compile(r"\b(gh[pousr]_[a-zA-Z0-9]{36,255})\b"), "[REDACTED_GITHUB_TOKEN]"),
    # Slack, Stripe, Generic API Keys
    (re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48}|sk_live_[0-9a-zA-Z]{24}|sk_test_[0-9a-zA-Z]{24}|FAKE_STRIPE_KEY[A-Za-z0-9_]*)\b"), "[REDACTED_API_KEY]"),
    # HTTP Authorization Bearer Tokens
    (re.compile(r"(?i)\b(bearer\s+)([a-zA-Z0-9_\-\.]{16,})\b"), r"\1[REDACTED_BEARER_TOKEN]"),
    # JWT Tokens
    (re.compile(r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b"), "[REDACTED_JWT_TOKEN]"),
    # Webhook Secrets
    (re.compile(r"\b(whsec_[a-zA-Z0-9_]{24,})\b"), "[REDACTED_WEBHOOK_SECRET]"),

    # Password & secret assignments in code/configs
    (re.compile(r'(?i)(password|secret|passwd|token|api_key|client_secret)\s*[:=]\s*["\'](?!\[REDACTED_)([^"\']{4,})["\']'), r'\1="[REDACTED_CREDENTIAL]"'),
    # Database URIs with credentials
    (re.compile(r"(postgres|mysql|mongodb|redis):\/\/([^:]+):([^@]+)@"), r"\1://\2:[REDACTED_DB_PASSWORD]@"),
]

MAX_EVIDENCE_LINES = 50


def sanitize_evidence_text(raw_text: str) -> str:
    """Scrubs sensitive credentials, secrets, and bounds excerpt length."""
    if not raw_text:
        return ""

    sanitized = raw_text
    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    # Bound line count to avoid unnecessary storage of full source files
    lines = sanitized.splitlines()
    if len(lines) > MAX_EVIDENCE_LINES:
        truncated_lines = lines[:MAX_EVIDENCE_LINES]
        sanitized = "\n".join(truncated_lines) + f"\n\n... [TRUNCATED: {len(lines) - MAX_EVIDENCE_LINES} lines omitted to avoid unnecessary full-file storage]"

    return sanitized


def sanitize_payload(payload: Any) -> str:
    """Serializes and scrubs any evidence payload (string, dict, or list)."""
    if isinstance(payload, str):
        return sanitize_evidence_text(payload)
    try:
        raw_json = json.dumps(payload, indent=2, default=str)
        return sanitize_evidence_text(raw_json)
    except Exception:
        return sanitize_evidence_text(str(payload))


def compute_evidence_hash(sanitized_content: str) -> str:
    """Computes SHA-256 hash to assist in detecting accidental alterations.
    
    CRITICAL DISCLAIMER: A content hash can help detect accidental alterations,
    but hashing alone does NOT establish evidence authenticity or original provenance.
    """
    return hashlib.sha256(sanitized_content.encode("utf-8")).hexdigest()


def verify_evidence_integrity(stored_hash: str, content: Any) -> bool:
    """Checks whether the content matches the stored SHA-256 content hash.
    
    Used to detect accidental evidence modification or corruption.
    NOTE: A matching hash does NOT claim or prove evidence authenticity or provenance.
    """
    import hmac
    if not stored_hash or content is None:
        return False
    if isinstance(content, str):
        computed = compute_evidence_hash(content)
    else:
        computed = compute_evidence_hash(sanitize_payload(content))
    return hmac.compare_digest(stored_hash.lower(), computed.lower())

