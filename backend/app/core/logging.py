"""Structured logging setup for RepoShield AI."""
import json
import logging
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict

# Regex patterns to scrub credentials from console and JSON log records
LOG_SCRUB_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|xox[baprs]-[0-9a-zA-Z]{10,48}|sk_live_[0-9a-zA-Z]{24})\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b"), "[REDACTED_JWT_TOKEN]"),
    (re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9-_\.]+"), r"\1[REDACTED_BEARER_TOKEN]"),
    (re.compile(r'(?i)(password|secret|passwd|token|raw_credential)\s*[:=]\s*["\'](?!\[REDACTED_)([^"\']{4,})["\']'), r'\1="[REDACTED_SECRET]"'),
    (re.compile(r"(postgres|postgresql|mysql|mongodb|redis):\/\/([^:]+):([^@]+)@"), r"\1://\2:[REDACTED_DB_PASSWORD]@"),
]


def scrub_log_message(text: str) -> str:
    """Mask high-entropy secrets and sensitive authentication tokens in log strings."""
    if not text:
        return ""
    for pattern, replacement in LOG_SCRUB_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class JSONFormatter(logging.Formatter):
    """Format logs as structured JSON strings with secret scrubbing."""

    def format(self, record: logging.LogRecord) -> str:
        raw_msg = record.getMessage()
        clean_msg = scrub_log_message(raw_msg)

        log_record: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": clean_msg,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Include custom attributes (e.g., request_id, client_ip)
        for key in ["request_id", "method", "path", "status_code", "duration_ms", "correlation_id"]:
            if hasattr(record, key):
                val = getattr(record, key)
                log_record[key] = scrub_log_message(str(val)) if isinstance(val, str) else val

        if record.exc_info:
            log_record["exception"] = scrub_log_message(self.formatException(record.exc_info))

        return json.dumps(log_record)


class StandardFormatter(logging.Formatter):
    """Clean, human-readable structured console format with secret scrubbing."""

    def format(self, record: logging.LogRecord) -> str:
        req_id = getattr(record, "request_id", "-")
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        prefix = f"[{timestamp}] [{record.levelname:<8}] [{record.name}] [req:{req_id}]"
        clean_msg = scrub_log_message(record.getMessage())
        msg = f"{prefix} {clean_msg}"
        if record.exc_info:
            msg += f"\n{scrub_log_message(self.formatException(record.exc_info))}"
        return msg


def setup_logging(level: str = "INFO", json_format: bool = False) -> None:
    """Configure root and app loggers."""
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Clear existing handlers to prevent duplicates
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    console_handler = logging.StreamHandler(sys.stdout)
    if json_format:
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(StandardFormatter())

    root_logger.addHandler(console_handler)

    # Adjust external loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a logger instance with the given module name."""
    return logging.getLogger(name)
