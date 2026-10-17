"""Semgrep OSS adapter for multi-language static analysis."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
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

logger = get_logger("reposhield.scanner.semgrep")

SEMGREP_SEVERITY_MAP = {
    "ERROR": "CRITICAL",
    "WARNING": "HIGH",
    "INFO": "LOW",
}


class SemgrepScannerAdapter(BaseScannerAdapter):
    """Adapter for Semgrep OSS static code analysis engine."""

    name: str = "semgrep"
    display_name: str = "Semgrep OSS"
    category: str = "sast"

    def _get_executable_cmd(self) -> Optional[List[str]]:
        semgrep_bin = resolve_tool_binary("semgrep")
        if semgrep_bin:
            try:
                res = subprocess.run(
                    [semgrep_bin, "--version"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=get_scanner_env(),
                    timeout=5,
                )
                if res.returncode == 0:
                    return [semgrep_bin]
            except Exception:
                pass
        try:
            res = subprocess.run(
                [sys.executable, "-m", "semgrep", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=get_scanner_env(),
                timeout=5,
            )
            if res.returncode == 0:
                return [sys.executable, "-m", "semgrep"]
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
            if res.returncode == 0:
                return res.stdout.strip()
            return None
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
                error_message="Semgrep CLI is not installed or functional in this environment. Install via: pip install semgrep or brew install semgrep",
            )

        start_time = time.perf_counter()
        version_str = self.get_version()
        config_ruleset = (options or {}).get("config", "p/default")
        if config_ruleset == "auto":
            config_ruleset = "p/default"

        args = cmd_base + [
            "scan",
            "--json",
            "--config", config_ruleset,
            "--disable-version-check",
            "--metrics=off",
            str(target_dir.resolve()),
        ]

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
            if result.returncode not in (0, 1):
                err = result.stderr.strip() or f"Semgrep exited with code {result.returncode}"
                return ScanJobResult(
                    scanner_name=self.display_name,
                    scanner_version=version_str,
                    category=self.category,
                    status=ScannerStatus.EXECUTION_ERROR,
                    execution_time_seconds=duration,
                    exit_code=result.returncode,
                    error_message=err,
                    raw_output_snippet=raw_stdout[:500],
                )

            data = json.loads(raw_stdout)
            raw_findings = data.get("results", [])
            normalized: List[NormalizedFinding] = []

            for item in raw_findings:
                rule_id = item.get("check_id", "semgrep-rule")
                file_abs = item.get("path", "")
                try:
                    rel_path = str(Path(file_abs).resolve().relative_to(target_dir.resolve())).replace("\\", "/")
                except ValueError:
                    rel_path = Path(file_abs).name

                start_line = item.get("start", {}).get("line", 1)
                end_line = item.get("end", {}).get("line", start_line)
                extra = item.get("extra", {})
                msg = extra.get("message", "Semgrep security pattern matched")
                raw_sev = extra.get("severity", "WARNING").upper()
                severity = SEMGREP_SEVERITY_MAP.get(raw_sev, "MEDIUM")
                lines_code = extra.get("lines", "")
                meta = extra.get("metadata", {})
                cwe_meta = meta.get("cwe", [])
                cwe_str = cwe_meta[0] if isinstance(cwe_meta, list) and cwe_meta else str(cwe_meta) if cwe_meta else "CWE-General"

                finding = NormalizedFinding(
                    scan_id=scan_id,
                    scanner_name=self.display_name,
                    scanner_rule_id=rule_id,
                    vulnerability_category=cwe_str,
                    cwe=cwe_str,
                    severity=severity,
                    confidence="HIGH",
                    file_path=rel_path,
                    start_line=start_line,
                    end_line=end_line,
                    scanner_message=msg,
                    evidence_reference=lines_code.strip() if lines_code else None,
                    metadata=meta,
                )
                normalized.append(finding)

            status = ScannerStatus.SUCCESS if normalized else ScannerStatus.NO_FINDINGS

            return ScanJobResult(
                scanner_name=self.display_name,
                scanner_version=version_str,
                category=self.category,
                status=status,
                execution_time_seconds=duration,
                findings=normalized,
                raw_output_snippet=raw_stdout[:500],
            )

        except subprocess.TimeoutExpired:
            duration = round(time.perf_counter() - start_time, 2)
            return ScanJobResult(
                scanner_name=self.display_name,
                scanner_version=version_str,
                category=self.category,
                status=ScannerStatus.TIMEOUT,
                execution_time_seconds=duration,
                error_message=f"Semgrep timed out after {timeout_seconds} seconds.",
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
