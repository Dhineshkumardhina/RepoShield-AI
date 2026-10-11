"""Bandit SAST adapter for Python source code analysis."""
import json
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

from .base import (
    BaseScannerAdapter,
    NormalizedFinding,
    ScanJobResult,
    ScannerStatus,
    get_scanner_env,
    resolve_tool_binary,
)
from ..core.logging import get_logger

logger = get_logger("reposhield.scanner.bandit")

# Map Bandit issue severities to standard AppSec severities
BANDIT_SEVERITY_MAP = {
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "UNDEFINED": "INFO",
}

# Map common Bandit rule IDs to specific CWE categories
BANDIT_CWE_MAP = {
    "B608": "CWE-89: SQL Injection",
    "B602": "CWE-78: OS Command Injection",
    "B603": "CWE-78: OS Command Injection",
    "B604": "CWE-78: OS Command Injection",
    "B605": "CWE-78: OS Command Injection",
    "B607": "CWE-78: OS Command Injection",
    "B303": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
    "B304": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
    "B305": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
    "B105": "CWE-798: Use of Hard-coded Credentials",
    "B106": "CWE-798: Use of Hard-coded Credentials",
    "B107": "CWE-798: Use of Hard-coded Credentials",
    "B301": "CWE-502: Deserialization of Untrusted Data",
    "B302": "CWE-502: Deserialization of Untrusted Data",
    "B201": "CWE-94: Improper Control of Generation of Code ('Code Injection')",
    "B506": "CWE-20: Improper Input Validation",
}


class BanditScannerAdapter(BaseScannerAdapter):
    """Adapter for Bandit: Python AST Security Linter."""

    name: str = "bandit"
    display_name: str = "Bandit Python SAST"
    category: str = "sast"

    def _get_executable_cmd(self) -> Optional[List[str]]:
        """Return executable command list for Bandit."""
        bandit_bin = resolve_tool_binary("bandit")
        if bandit_bin:
            return [bandit_bin]
        try:
            res = subprocess.run(
                ["python", "-m", "bandit", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=get_scanner_env(),
                timeout=5,
            )
            if res.returncode == 0:
                return ["python", "-m", "bandit"]
        except Exception:
            pass
        return None

    def is_available(self) -> bool:
        return self._get_executable_cmd() is not None

    def get_version(self) -> Optional[str]:
        cmd = self._get_executable_cmd()
        if not cmd:
            return None
        try:
            res = subprocess.run(
                cmd + ["--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=get_scanner_env(),
                timeout=5,
            )
            out = res.stdout.strip()
            # Typically e.g. "python.exe -m bandit 1.9.4" or "bandit 1.9.4"
            match = out.split("\n")[0]
            return match
        except Exception:
            return None


    def scan(
        self,
        target_dir: Path,
        scan_id: str,
        timeout_seconds: int = 60,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScanJobResult:
        cmd_base = self._get_executable_cmd()
        if not cmd_base:
            return ScanJobResult(
                scanner_name=self.display_name,
                scanner_version=None,
                category=self.category,
                status=ScannerStatus.TOOL_NOT_INSTALLED,
                execution_time_seconds=0.0,
                error_message="Bandit is not installed on this system. Install using: pip install bandit",
            )

        # Build explicit argument list (avoid shell interpolation)
        target_path = str(target_dir.resolve())
        args = cmd_base + ["-f", "json", "-r", target_path]

        start_time = time.perf_counter()
        version_str = self.get_version()

        try:
            result = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=get_scanner_env(),
                timeout=timeout_seconds,
            )
            duration = round(time.perf_counter() - start_time, 2)

            raw_stdout = result.stdout or ""
            # Bandit returns exit code 0 if clean, 1 if issues found, or other on error
            if result.returncode not in (0, 1):
                err = result.stderr.strip() or f"Bandit exited with code {result.returncode}"
                return ScanJobResult(
                    scanner_name=self.display_name,
                    scanner_version=version_str,
                    category=self.category,
                    status=ScannerStatus.EXECUTION_ERROR,
                    execution_time_seconds=duration,
                    exit_code=result.returncode,
                    error_message=err,
                    raw_output_snippet=result.stdout[:500] if result.stdout else None,
                )

            # Parse machine-readable JSON
            try:
                data = json.loads(raw_stdout)
            except json.JSONDecodeError as jde:
                return ScanJobResult(
                    scanner_name=self.display_name,
                    scanner_version=version_str,
                    category=self.category,
                    status=ScannerStatus.EXECUTION_ERROR,
                    execution_time_seconds=duration,
                    exit_code=result.returncode,
                    error_message=f"Failed to parse Bandit JSON output: {str(jde)}",
                    raw_output_snippet=raw_stdout[:500],
                )

            raw_findings = data.get("results", [])
            normalized: List[NormalizedFinding] = []

            for item in raw_findings:
                file_abs = item.get("filename", "")
                try:
                    rel_path = str(Path(file_abs).resolve().relative_to(target_dir.resolve())).replace("\\", "/")
                except ValueError:
                    rel_path = Path(file_abs).name

                rule_id = item.get("test_id", "BANDIT_RULE")
                test_name = item.get("test_name", "Security Issue")
                severity_raw = item.get("issue_severity", "MEDIUM")
                severity = BANDIT_SEVERITY_MAP.get(severity_raw.upper(), "MEDIUM")
                confidence = item.get("issue_confidence", "HIGH")
                msg = item.get("issue_text", "")
                line_no = item.get("line_number", 1)
                line_range = item.get("line_range", [line_no])
                end_line = max(line_range) if line_range else line_no
                code_snippet = item.get("code", "")
                cwe = BANDIT_CWE_MAP.get(rule_id, f"CWE-Other: {test_name}")

                finding = NormalizedFinding(
                    scan_id=scan_id,
                    scanner_name=self.display_name,
                    scanner_rule_id=rule_id,
                    vulnerability_category=cwe,
                    cwe=cwe,
                    severity=severity,
                    confidence=confidence.upper(),
                    file_path=rel_path,
                    start_line=line_no,
                    end_line=end_line,
                    scanner_message=msg,
                    evidence_reference=code_snippet.strip() if code_snippet else None,
                    metadata={
                        "test_name": test_name,
                        "more_info": item.get("more_info", ""),
                    },
                )
                normalized.append(finding)

            status = ScannerStatus.SUCCESS if normalized else ScannerStatus.NO_FINDINGS

            return ScanJobResult(
                scanner_name=self.display_name,
                scanner_version=version_str,
                category=self.category,
                status=status,
                execution_time_seconds=duration,
                exit_code=result.returncode,
                findings=normalized,
                raw_output_snippet=raw_stdout[:500] if raw_stdout else None,
            )

        except subprocess.TimeoutExpired:
            duration = round(time.perf_counter() - start_time, 2)
            return ScanJobResult(
                scanner_name=self.display_name,
                scanner_version=version_str,
                category=self.category,
                status=ScannerStatus.TIMEOUT,
                execution_time_seconds=duration,
                error_message=f"Bandit scan timed out after {timeout_seconds} seconds.",
            )
        except Exception as exc:
            duration = round(time.perf_counter() - start_time, 2)
            return ScanJobResult(
                scanner_name=self.display_name,
                scanner_version=version_str,
                category=self.category,
                status=ScannerStatus.EXECUTION_ERROR,
                execution_time_seconds=duration,
                error_message=str(exc),
            )
