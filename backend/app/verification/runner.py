"""Execution Engine for Scanners and Tests in Isolated Workspaces.

Enforces:
1. Re-running relevant static analysis rules.
2. Executing existing unit and regression tests with subprocess bounding.
3. Timeouts and memory-conscious execution.
4. Capturing test failures, timeouts, and execution errors without leaking secrets.
"""
import ast
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple
from ..scanner.base import NormalizedFinding, ScannerStatus, ScanJobResult
from ..scanner.registry import scanner_registry
from .workspace import get_sanitized_runner_env


# Prohibited call names in untrusted test files to prevent host command execution
DISALLOWED_CALL_NAMES = {
    "os.system", "os.popen", "os.spawnl", "os.spawnle", "os.spawnlp",
    "os.spawnlpe", "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
    "pty.spawn", "socket.socket",
}


def inspect_test_safety(workspace_dir: Path, target_path: Optional[Path] = None) -> Optional[str]:
    """Scan test files for high-risk system commands that violate the runner sandbox policy.
    
    Uses AST parsing to distinguish actual executable system calls from string literals
    (such as benign exploit payload test data).
    """
    files_to_check: List[Path] = []
    if target_path and target_path.is_file():
        files_to_check.append(target_path)
    else:
        for p in workspace_dir.rglob("*.py"):
            if "test" in p.name.lower() and p.is_file():
                files_to_check.append(p)

    for test_file in files_to_check:
        try:
            content = test_file.read_text(encoding="utf-8", errors="replace")
            try:
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        call_name = ""
                        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                            call_name = f"{node.func.value.id}.{node.func.attr}"
                        elif isinstance(node.func, ast.Name):
                            call_name = node.func.id

                        if call_name in DISALLOWED_CALL_NAMES or call_name.startswith("subprocess."):
                            rel_name = test_file.name
                            return (
                                f"Security policy violation in test '{rel_name}': "
                                f"Detected prohibited call ({call_name}). "
                                f"Untrusted test suites cannot invoke host shell or subprocess commands."
                            )
            except SyntaxError:
                # If syntax error in test file, fallback to call pattern regex
                if re.search(r"\b(os\.system|os\.popen|subprocess\.(Popen|run|call))\s*\(", content):
                    return (
                        f"Security policy violation in test '{test_file.name}': "
                        f"Detected prohibited system call invocation. "
                        f"Untrusted test suites cannot invoke host shell or subprocess commands."
                    )
        except Exception as e:
            return f"Failed to inspect test safety for {test_file.name}: {str(e)}"

    return None



@dataclass
class TestExecutionOutcome:
    test_suite_name: str
    status: str  # passed, failed, timeout, skipped, error
    passed_count: int = 0
    failed_count: int = 0
    skipped_count: int = 0
    execution_time_seconds: float = 0.0
    output_log: str = ""
    error_message: Optional[str] = None


@dataclass
class VerificationChecksOutcome:
    baseline_findings: List[NormalizedFinding] = field(default_factory=list)
    patched_findings: List[NormalizedFinding] = field(default_factory=list)
    scanners_executed: List[str] = field(default_factory=list)
    scanner_metadata: Dict[str, Any] = field(default_factory=dict)
    test_outcomes: List[TestExecutionOutcome] = field(default_factory=list)
    execution_errors: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)


def run_scanners_on_directory(
    target_dir: Path,
    scanner_names: Optional[List[str]] = None,
    timeout_seconds: int = 30,
    options: Optional[Dict[str, Any]] = None,
) -> Tuple[List[NormalizedFinding], Dict[str, Any], List[str]]:
    """Execute configured scanners against a directory and return normalized findings."""
    findings: List[NormalizedFinding] = []
    metadata: Dict[str, Any] = {}
    errors: List[str] = []

    available_adapters = scanner_registry.list_all()
    if scanner_names:
        adapters = [a for a in available_adapters if a.name in scanner_names]
        unregistered = [name for name in scanner_names if not any(a.name == name for a in available_adapters)]
        for name in unregistered:
            errors.append(f"Scanner '{name}' is not registered in this environment.")
    else:
        adapters = available_adapters

    for adapter in adapters:
        meta_entry = {
            "name": adapter.name,
            "display_name": adapter.display_name,
            "category": adapter.category,
            "is_available": adapter.is_available(),
            "version": adapter.get_version(),
        }
        metadata[adapter.name] = meta_entry

        if not adapter.is_available():
            if scanner_names and adapter.name in scanner_names:
                errors.append(f"{adapter.display_name} is not installed or available in this environment.")
            continue

        try:
            job_result = adapter.scan(
                target_dir=target_dir,
                scan_id="verify_scan",
                timeout_seconds=timeout_seconds,
                options=options,
            )
            findings.extend(job_result.findings)
            meta_entry["status"] = job_result.status.value
            meta_entry["execution_time"] = job_result.execution_time_seconds

            if job_result.status in (ScannerStatus.EXECUTION_ERROR, ScannerStatus.TIMEOUT):
                errors.append(f"{adapter.display_name}: {job_result.error_message or 'Scanner execution failed'}")
        except Exception as e:
            errors.append(f"Failed executing scanner {adapter.name}: {str(e)}")

    return findings, metadata, errors


def run_pytest_in_workspace(
    workspace_dir: Path,
    test_target: Optional[str] = None,
    timeout_seconds: int = 30
) -> TestExecutionOutcome:
    """Execute pytest within the isolated disposable workspace with sanitized environment."""
    env = get_sanitized_runner_env()
    
    # Determine test arguments
    cmd = [sys.executable, "-m", "pytest", "-v"]

    # Check if tests directory or test target exists
    if test_target:
        clean_target = test_target.strip()
        if clean_target.startswith("-"):
            return TestExecutionOutcome(
                test_suite_name=test_target,
                status="error",
                error_message=f"Command option injection attempt rejected in test target: {test_target}"
            )

        resolved_ws = workspace_dir.resolve()
        target_path = (resolved_ws / clean_target).resolve()
        try:
            target_path.relative_to(resolved_ws)
        except ValueError:
            return TestExecutionOutcome(
                test_suite_name=test_target,
                status="error",
                error_message=f"Path traversal detected in test target: {test_target}"
            )

        if not target_path.exists():
            return TestExecutionOutcome(
                test_suite_name=test_target,
                status="skipped",
                error_message=f"Specified test target does not exist: {test_target}"
            )
        cmd.extend(["--", clean_target])
    else:
        # Check if any tests directory exists
        has_tests = (workspace_dir / "tests").is_dir() or any(workspace_dir.glob("test_*.py")) or any(workspace_dir.glob("*_test.py"))
        if not has_tests:
            return TestExecutionOutcome(
                test_suite_name="project_tests",
                status="skipped",
                output_log="No unit tests found in workspace."
            )

    # Pre-execution safety inspection to block dangerous commands in untrusted tests
    target_file_to_check = target_path if test_target else None
    safety_violation = inspect_test_safety(workspace_dir=workspace_dir, target_path=target_file_to_check)
    if safety_violation:
        return TestExecutionOutcome(
            test_suite_name=test_target or "project_tests",
            status="error",
            error_message=safety_violation,
            output_log=safety_violation,
        )

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(workspace_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds
        )
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        
        # Simple parsing of pytest output
        passed = 0
        failed = 0
        if " passed" in output:
            for part in output.split():
                if "passed" in part:
                    idx = output.find(part)
                    prev_word = output[:idx].strip().split()[-1] if output[:idx].strip() else "0"
                    if prev_word.isdigit():
                        passed = int(prev_word)

        if " failed" in output:
            for part in output.split():
                if "failed" in part:
                    idx = output.find(part)
                    prev_word = output[:idx].strip().split()[-1] if output[:idx].strip() else "0"
                    if prev_word.isdigit():
                        failed = int(prev_word)

        status = "passed" if proc.returncode == 0 else "failed"
        return TestExecutionOutcome(
            test_suite_name=test_target or "project_tests",
            status=status,
            passed_count=passed,
            failed_count=failed,
            output_log=output[:4000],
            error_message=None if status == "passed" else f"Test run exited with code {proc.returncode}"
        )
    except subprocess.TimeoutExpired:
        return TestExecutionOutcome(
            test_suite_name=test_target or "project_tests",
            status="timeout",
            error_message=f"Test execution exceeded {timeout_seconds}s timeout limit."
        )
    except Exception as e:
        return TestExecutionOutcome(
            test_suite_name=test_target or "project_tests",
            status="error",
            error_message=f"Failed launching test runner: {str(e)}"
        )
