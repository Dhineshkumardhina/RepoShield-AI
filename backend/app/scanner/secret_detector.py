"""Built-in Secret and Credential Scanner for RepoShield AI.

Provides deterministic detection of credentials, API tokens, and private keys.
Always sanitizes and redacts secrets before storing or reporting.
"""
import os
from pathlib import Path
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseScannerAdapter, NormalizedFinding, ScanJobResult, ScannerStatus, redact_secrets

# High-fidelity regex signatures for credential detection
SECRET_SIGNATURES: List[Tuple[str, str, str, re.Pattern]] = [
    (
        "SEC-AWS-KEY",
        "AWS Access Key ID",
        "CRITICAL",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    ),
    (
        "SEC-GITHUB-TOKEN",
        "GitHub Personal Access Token",
        "CRITICAL",
        re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b"),
    ),
    (
        "SEC-GITLAB-TOKEN",
        "GitLab Personal Access Token",
        "CRITICAL",
        re.compile(r"\b(glpat-[a-zA-Z0-9_\-]{20})\b"),
    ),
    (
        "SEC-STRIPE-KEY",
        "Stripe Live API Secret Key",
        "CRITICAL",
        re.compile(r"\b(sk_live_[0-9a-zA-Z]{24})\b"),
    ),
    (
        "SEC-SLACK-TOKEN",
        "Slack Bot/User Token",
        "HIGH",
        re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"),
    ),
    (
        "SEC-PRIVATE-KEY",
        "Unencrypted Private Key",
        "CRITICAL",
        re.compile(r"-----BEGIN (?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----"),
    ),
    (
        "SEC-GENERIC-SECRET",
        "Hardcoded Credential or API Secret Assignment",
        "HIGH",
        re.compile(r"""(?:api_key|apikey|secret|password|passwd|auth_token)\s*[:=]\s*['"]([a-zA-Z0-9_\-\.!@#$%^&*]{10,128})['"]""", re.IGNORECASE),
    ),
]

# File extensions to ignore during secret scanning (binaries, lockfiles, images)
IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".pdf", ".zip", ".tar", ".gz",
    ".pyc", ".pyo", ".lock", ".sum", ".exe", ".dll", ".so",
}


class SecretScannerAdapter(BaseScannerAdapter):
    """Built-in secret and credential detection engine."""

    name: str = "secret_detector"
    display_name: str = "RepoShield Secret Engine"
    category: str = "secret"

    def is_available(self) -> bool:
        return True

    def get_version(self) -> Optional[str]:
        return "RepoShield Secret Engine v1.0.0"

    def scan(
        self,
        target_dir: Path,
        scan_id: str,
        timeout_seconds: int = 60,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanJobResult:
        start_time = time.perf_counter()
        findings: List[NormalizedFinding] = []

        try:
            for root, _, files in os.walk(target_dir):
                for file in files:
                    file_path = Path(root) / file
                    if file_path.suffix.lower() in IGNORE_EXTENSIONS:
                        continue
                    if file_path.stat().st_size > 2 * 1024 * 1024:  # Skip files > 2 MB
                        continue

                    try:
                        rel_path = str(file_path.resolve().relative_to(target_dir.resolve())).replace("\\", "/")
                    except ValueError:
                        rel_path = file_path.name

                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            lines = f.readlines()
                    except Exception:
                        continue

                    for line_idx, line in enumerate(lines, start=1):
                        for rule_id, desc, severity, pattern in SECRET_SIGNATURES:
                            if pattern.search(line):
                                sanitized_line = redact_secrets(line.strip())
                                finding = NormalizedFinding(
                                    scan_id=scan_id,
                                    scanner_name=self.display_name,
                                    scanner_rule_id=rule_id,
                                    vulnerability_category="CWE-798: Use of Hard-coded Credentials",
                                    cwe="CWE-798: Use of Hard-coded Credentials",
                                    severity=severity,
                                    confidence="HIGH",
                                    file_path=rel_path,
                                    start_line=line_idx,
                                    end_line=line_idx,
                                    scanner_message=f"{desc} detected in {rel_path}:{line_idx}",
                                    evidence_reference=sanitized_line,
                                    metadata={"rule_id": rule_id, "pattern_desc": desc},
                                )
                                findings.append(finding)

            duration = round(time.perf_counter() - start_time, 2)
            status = ScannerStatus.SUCCESS if findings else ScannerStatus.NO_FINDINGS

            return ScanJobResult(
                scanner_name=self.display_name,
                scanner_version=self.get_version(),
                category=self.category,
                status=status,
                execution_time_seconds=duration,
                findings=findings,
            )

        except Exception as exc:
            duration = round(time.perf_counter() - start_time, 2)
            return ScanJobResult(
                scanner_name=self.display_name,
                scanner_version=self.get_version(),
                category=self.category,
                status=ScannerStatus.EXECUTION_ERROR,
                execution_time_seconds=duration,
                error_message=str(exc),
            )
