"""Base scanner adapter interface and normalized finding schema.

Enforces:
1. Explicit argument passing (no shell=True).
2. Execution timeouts and resource bounding.
3. Machine-readable output parsing.
4. Error vs finding distinction without hallucination.
5. Secret redaction in evidence and metadata.
"""
import os
import shutil
import site
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
import uuid


class ScannerStatus(str, Enum):
    SUCCESS = "success"
    NO_FINDINGS = "no_findings"
    TOOL_NOT_INSTALLED = "tool_not_installed"
    EXECUTION_ERROR = "execution_error"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


def get_scanner_search_paths() -> List[str]:
    """Return directories where scanner binaries might reside."""
    paths = []
    try:
        userbase = site.getuserbase()
        for py_dir in ("Python314", "Python313", "Python312", "Python311", "Python310"):
            candidate = os.path.join(userbase, py_dir, "Scripts")
            if os.path.isdir(candidate) and candidate not in paths:
                paths.append(candidate)
        base_scripts = os.path.join(userbase, "Scripts")
        if os.path.isdir(base_scripts) and base_scripts not in paths:
            paths.append(base_scripts)
    except Exception:
        pass

    try:
        sys_scripts = os.path.join(os.path.dirname(sys.executable), "Scripts")
        if os.path.isdir(sys_scripts) and sys_scripts not in paths:
            paths.append(sys_scripts)
    except Exception:
        pass
    return paths


def get_scanner_env() -> Dict[str, str]:
    """Construct environment dictionary with Python Scripts directories included in PATH."""
    env = os.environ.copy()
    candidate_paths = get_scanner_search_paths()
    current_path = env.get("PATH", "")
    all_paths = candidate_paths + [p for p in current_path.split(os.pathsep) if p]
    env["PATH"] = os.pathsep.join(all_paths)
    return env


def resolve_tool_binary(tool_name: str) -> Optional[str]:
    """Find binary executable for tool across candidate search paths."""
    search_path = os.pathsep.join(get_scanner_search_paths()) + os.pathsep + os.environ.get("PATH", "")
    return shutil.which(tool_name, path=search_path)



# Sensitive patterns to redact from findings, evidence, and messages
SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"glpat-[a-zA-Z0-9_\-]{20}"), "[REDACTED_GITLAB_TOKEN]"),
    (re.compile(r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"), "[REDACTED_JWT_TOKEN]"),
    (re.compile(r"sk_live_[0-9a-zA-Z]{24}"), "[REDACTED_STRIPE_SECRET]"),
    (re.compile(r"(password|passwd|secret|api_key|token)\s*[:=]\s*['\"][^'\"]+['\"]", re.IGNORECASE), r"\1 = '[REDACTED_SECRET]'"),
]


def redact_secrets(text: Optional[str]) -> Optional[str]:
    """Recursively mask secrets and tokens in excerpts and evidence."""
    if not text:
        return text
    clean = text
    for pattern, replacement in SECRET_PATTERNS:
        clean = pattern.sub(replacement, clean)
    return clean


@dataclass
class NormalizedFinding:
    """Standardized finding schema across all integrated AppSec scanners."""
    finding_id: str = field(default_factory=lambda: f"fnd-{uuid.uuid4().hex[:12]}")
    scan_id: str = ""
    scanner_name: str = ""
    scanner_rule_id: str = ""
    vulnerability_category: str = "vulnerability"
    severity: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: str = "HIGH"   # HIGH, MEDIUM, LOW, UNDEFINED
    file_path: str = ""
    start_line: int = 1
    end_line: int = 1
    scanner_message: str = ""
    evidence_reference: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    cwe: Optional[str] = None

    def __post_init__(self):
        # Sanitize evidence and message on initialization
        if self.evidence_reference:
            self.evidence_reference = redact_secrets(self.evidence_reference)
        if self.scanner_message:
            self.scanner_message = redact_secrets(self.scanner_message)
        # Normalize severity
        sev_upper = self.severity.upper()
        if sev_upper in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self.severity = sev_upper
        else:
            self.severity = "MEDIUM"


@dataclass
class ScanJobResult:
    """Result of an individual scanner adapter execution."""
    scanner_name: str
    scanner_version: Optional[str]
    category: str  # sast, sca, secret
    status: ScannerStatus
    execution_time_seconds: float
    findings: List[NormalizedFinding] = field(default_factory=list)
    error_message: Optional[str] = None
    exit_code: Optional[int] = None
    raw_output_snippet: Optional[str] = None


class BaseScannerAdapter(ABC):
    """Abstract base class for all security scanner adapters."""

    name: str = "base"
    display_name: str = "Base Security Scanner"
    category: str = "sast"  # sast, sca, secret

    @abstractmethod
    def is_available(self) -> bool:
        """Check whether the scanner binary or module is installed and executable."""
        pass

    @abstractmethod
    def get_version(self) -> Optional[str]:
        """Query scanner version string safely."""
        pass

    @abstractmethod
    def scan(
        self,
        target_dir: Path,
        scan_id: str,
        timeout_seconds: int = 60,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanJobResult:
        """Execute scanner against target repository directory with resource bounding."""
        pass
