"""pip-audit SCA adapter for Python dependency vulnerability analysis."""
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

logger = get_logger("reposhield.scanner.pip_audit")


class PipAuditScannerAdapter(BaseScannerAdapter):
    """Adapter for pip-audit: Software Composition Analysis (SCA) for Python."""

    name: str = "pip_audit"
    display_name: str = "pip-audit Dependency SCA"
    category: str = "sca"

    def _get_executable_cmd(self) -> Optional[List[str]]:
        audit_bin = resolve_tool_binary("pip-audit")
        if audit_bin:
            return [audit_bin]
        try:
            res = subprocess.run(
                [sys.executable, "-m", "pip_audit", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=get_scanner_env(),
                timeout=5,
            )
            if res.returncode == 0:
                return [sys.executable, "-m", "pip_audit"]
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
            return res.stdout.strip()
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
                error_message="pip-audit is not installed on this system. Install using: pip install pip-audit",
            )

        # Look for Python dependency manifests in target directory
        manifests: List[Path] = []
        for candidate in ("requirements.txt", "requirements-dev.txt", "Pipfile.lock", "pyproject.toml"):
            m_path = target_dir / candidate
            if m_path.exists() and m_path.is_file():
                manifests.append(m_path)

        # Also search subdirectories for requirements*.txt (up to depth 2)
        if not manifests:
            for sub_req in target_dir.glob("**/requirements*.txt"):
                if sub_req.is_file():
                    manifests.append(sub_req)

        if not manifests:
            return ScanJobResult(
                scanner_name=self.display_name,
                scanner_version=self.get_version(),
                category=self.category,
                status=ScannerStatus.SKIPPED,
                execution_time_seconds=0.0,
                error_message="No Python dependency manifest (requirements.txt, Pipfile.lock) found in repository.",
            )

        start_time = time.perf_counter()
        version_str = self.get_version()
        all_findings: List[NormalizedFinding] = []

        # Run pip-audit for each discovered requirement manifest
        for manifest in manifests:
            rel_manifest = str(manifest.resolve().relative_to(target_dir.resolve())).replace("\\", "/")
            args = cmd_base + ["-f", "json", "--no-deps", "--disable-pip", "-r", str(manifest.resolve())]

            try:
                res = subprocess.run(
                    args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    env=get_scanner_env(),
                    timeout=timeout_seconds,
                )

                # If --no-deps failed due to unpinned dependencies, retry without --no-deps
                if res.returncode not in (0, 1) and "not pinned" in res.stderr.lower():
                    logger.info(f"Unpinned requirements in {rel_manifest}, retrying pip-audit with resolver")
                    res = subprocess.run(
                        cmd_base + ["-f", "json", "-r", str(manifest.resolve())],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        env=get_scanner_env(),
                        timeout=timeout_seconds,
                    )

                # pip-audit returns 0 if clean, 1 if vulnerabilities found
                if res.returncode not in (0, 1):
                    err = res.stderr.strip() or f"pip-audit exited with code {res.returncode}"
                    logger.warning(f"pip-audit error on {rel_manifest}: {err}")
                    continue

                raw_json = res.stdout.strip()
                if not raw_json:
                    continue

                data = json.loads(raw_json)
                dependencies = data.get("dependencies", [])

                for dep in dependencies:
                    dep_name = dep.get("name", "unknown")
                    dep_version = dep.get("version", "unknown")
                    vulns = dep.get("vulns", [])

                    for vuln in vulns:
                        vuln_id = vuln.get("id", "VULN-UNKNOWN")
                        aliases = vuln.get("aliases", [])
                        cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
                        fix_versions = vuln.get("fix_versions", [])
                        desc = vuln.get("description", "Vulnerable dependency detected")
                        fix_str = f"Upgrade to {', '.join(fix_versions)}" if fix_versions else "No fix version published"

                        finding = NormalizedFinding(
                            scan_id=scan_id,
                            scanner_name=self.display_name,
                            scanner_rule_id=cve_id,
                            vulnerability_category="CWE-1395: Dependency on Vulnerable Component",
                            cwe="CWE-1395: Dependency on Vulnerable Third-Party Component",
                            severity="HIGH",
                            confidence="HIGH",
                            file_path=rel_manifest,
                            start_line=1,
                            end_line=1,
                            scanner_message=f"{dep_name}=={dep_version} is vulnerable to {vuln_id}: {desc[:200]}...",
                            evidence_reference=f"Package: {dep_name}=={dep_version}\nAdvisory: {vuln_id}\nRemediation: {fix_str}",
                            metadata={
                                "package_name": dep_name,
                                "installed_version": dep_version,
                                "advisory_id": vuln_id,
                                "aliases": aliases,
                                "fix_versions": fix_versions,
                            },
                        )
                        all_findings.append(finding)

            except subprocess.TimeoutExpired:
                duration = round(time.perf_counter() - start_time, 2)
                return ScanJobResult(
                    scanner_name=self.display_name,
                    scanner_version=version_str,
                    category=self.category,
                    status=ScannerStatus.TIMEOUT,
                    execution_time_seconds=duration,
                    error_message=f"pip-audit timed out scanning {rel_manifest}",
                )
            except Exception as exc:
                logger.error(f"Failed scanning manifest {rel_manifest}: {exc}")

        duration = round(time.perf_counter() - start_time, 2)
        status = ScannerStatus.SUCCESS if all_findings else ScannerStatus.NO_FINDINGS

        return ScanJobResult(
            scanner_name=self.display_name,
            scanner_version=version_str,
            category=self.category,
            status=status,
            execution_time_seconds=duration,
            findings=all_findings,
        )
