"""Evidence collector gathering scanner findings, source context, AST facts, and limitations."""
import ast
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

from ..analyzer.context import get_bounded_source_context
from ..models.finding import SecurityFinding
from ..models.repository import Repository
from ..scanner.base import redact_secrets
from ..schemas.validation import EvidenceItem, OriginalFindingSnapshot
from .enums import EvidenceType

PROMPT_INJECTION_PATTERN = re.compile(
    r"(ignore\s+(all\s+)?(previous|prior)\s+instructions|"
    r"mark\s+this\s+(finding\s+as\s+)?(false\s+positive|harmless|safe|verified)|"
    r"system\s*:\s*(override|do\s+not\s+report)|"
    r"disregard\s+(previous\s+)?security\s+rules|"
    r"assistant\s*:\s*this\s+is\s+harmless)",
    re.IGNORECASE,
)

TEST_PATH_PATTERN = re.compile(
    r"(^|/|\\)(tests?|fixtures?|mocks?|test_.*|\.*_test)\.py$",
    re.IGNORECASE,
)


class EvidenceDossier:
    """Consolidated evidentiary dossier for an AppSec scanner finding."""
    def __init__(
        self,
        original_finding: OriginalFindingSnapshot,
        code_excerpt: Optional[str] = None,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
        is_truncated: bool = False,
        is_incomplete: bool = False,
        is_test_file: bool = False,
        has_prompt_injection: bool = False,
        prompt_injection_details: Optional[str] = None,
        supporting_evidence: Optional[List[EvidenceItem]] = None,
        refuting_evidence: Optional[List[EvidenceItem]] = None,
        missing_evidence: Optional[List[str]] = None,
        analysis_limitations: Optional[List[str]] = None,
        dependency_info: Optional[str] = None,
        evidence_hash: str = "",
    ):
        self.original_finding = original_finding
        self.code_excerpt = code_excerpt
        self.start_line = start_line
        self.end_line = end_line
        self.is_truncated = is_truncated
        self.is_incomplete = is_incomplete
        self.is_test_file = is_test_file
        self.has_prompt_injection = has_prompt_injection
        self.prompt_injection_details = prompt_injection_details
        self.supporting_evidence = supporting_evidence if supporting_evidence is not None else []
        self.refuting_evidence = refuting_evidence if refuting_evidence is not None else []
        self.missing_evidence = missing_evidence if missing_evidence is not None else []
        self.analysis_limitations = analysis_limitations if analysis_limitations is not None else []
        self.dependency_info = dependency_info
        self.evidence_hash = evidence_hash


def _strip_line_number_prefixes(text: str) -> str:
    """Removes line number indicators (e.g. '   1 >> | ') so AST parsing succeeds."""
    clean_lines = []
    for line in text.splitlines():
        if "|" in line:
            parts = line.split("|", 1)
            if re.match(r'^\s*\d+\s*(?:>>|\s+)*$', parts[0]):
                clean_lines.append(parts[1][1:] if parts[1].startswith(" ") else parts[1])
                continue
        clean_lines.append(line)
    return "\n".join(clean_lines)


def _detect_ast_properties(
    code_snippet: str,
    finding_line: int,
) -> Tuple[bool, List[EvidenceItem], List[EvidenceItem]]:
    """Inspect AST to detect literal constants, sanitization calls, and taint patterns."""
    supporting: List[EvidenceItem] = []
    refuting: List[EvidenceItem] = []
    is_constant_sink = False

    clean_code = _strip_line_number_prefixes(code_snippet)

    try:
        tree = ast.parse(clean_code)
    except SyntaxError:
        # Fallback to regex pattern analysis if snippet is incomplete fragment
        if re.search(r'cursor\.execute\s*\(\s*["\'][^"\']*["\']\s*\)', code_snippet):
            is_constant_sink = True
            refuting.append(EvidenceItem(
                evidence_type=EvidenceType.CONSTANT_ARGUMENT.value,
                description="Database sink receives a static string literal without variable interpolation or formatting.",
                code_snippet=code_snippet.strip(),
                line_number=finding_line,
                polarity="REFUTING",
            ))
        elif re.search(r'f["\'].*SELECT.*\{.*\}', code_snippet, re.IGNORECASE):
            supporting.append(EvidenceItem(
                evidence_type=EvidenceType.SOURCE_TAINT_SINK.value,
                description="Raw SQL query string formatted via f-string containing user variable interpolation.",
                code_snippet=code_snippet.strip(),
                line_number=finding_line,
                polarity="SUPPORTING",
            ))

        if re.search(r'\b(clean|sanitize|escape|quote|safe_load|parameterize)\w*\(', code_snippet, re.IGNORECASE):
            refuting.append(EvidenceItem(
                evidence_type=EvidenceType.SANITIZATION_ROUTINE.value,
                description="Observed potential sanitization or escaping routine invocation.",
                code_snippet=code_snippet.strip(),
                line_number=finding_line,
                polarity="REFUTING",
            ))
        return is_constant_sink, supporting, refuting

    for node in ast.walk(tree):
        # 1. Check for function/method calls representing sinks or sanitizers
        if isinstance(node, ast.Call):
            call_name = ""
            if isinstance(node.func, ast.Attribute):
                call_name = node.func.attr
            elif isinstance(node.func, ast.Name):
                call_name = node.func.id

            # Check database execution sinks
            if call_name in ("execute", "executemany"):
                if node.args:
                    first_arg = node.args[0]
                    # If arg is pure Constant string with no formatting
                    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                        is_constant_sink = True
                        refuting.append(EvidenceItem(
                            evidence_type=EvidenceType.CONSTANT_ARGUMENT.value,
                            description=f"Sink argument in '{call_name}' is a static compile-time string literal without variable interpolation.",
                            code_snippet=ast.unparse(node),
                            line_number=getattr(node, "lineno", finding_line),
                            polarity="REFUTING",
                        ))
                    elif isinstance(first_arg, ast.JoinedStr):  # f-string
                        supporting.append(EvidenceItem(
                            evidence_type=EvidenceType.SOURCE_TAINT_SINK.value,
                            description=f"Dangerous f-string interpolation directly supplied to SQL execution sink '{call_name}'.",
                            code_snippet=ast.unparse(node),
                            line_number=getattr(node, "lineno", finding_line),
                            polarity="SUPPORTING",
                        ))
                    elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, (ast.Add, ast.Mod)):
                        supporting.append(EvidenceItem(
                            evidence_type=EvidenceType.SOURCE_TAINT_SINK.value,
                            description=f"Dynamic string concatenation/formatting passed directly to execution sink '{call_name}'.",
                            code_snippet=ast.unparse(node),
                            line_number=getattr(node, "lineno", finding_line),
                            polarity="SUPPORTING",
                        ))

            # Check shell execution sinks
            elif call_name in ("run", "Popen", "system", "call"):
                # Check for shell=True
                has_shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                if has_shell_true or call_name == "system":
                    if node.args and isinstance(node.args[0], ast.JoinedStr):
                        supporting.append(EvidenceItem(
                            evidence_type=EvidenceType.SOURCE_TAINT_SINK.value,
                            description=f"OS command execution via '{call_name}' with shell=True and dynamic f-string concatenation.",
                            code_snippet=ast.unparse(node),
                            line_number=getattr(node, "lineno", finding_line),
                            polarity="SUPPORTING",
                        ))
                    elif node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                        is_constant_sink = True
                        refuting.append(EvidenceItem(
                            evidence_type=EvidenceType.CONSTANT_ARGUMENT.value,
                            description=f"Command invocation '{call_name}' uses static constant argument without user variables.",
                            code_snippet=ast.unparse(node),
                            line_number=getattr(node, "lineno", finding_line),
                            polarity="REFUTING",
                        ))

            # Check sanitization routines
            if any(term in call_name.lower() for term in ("sanitize", "escape", "clean", "quote", "safe_load", "parameterize")):
                refuting.append(EvidenceItem(
                    evidence_type=EvidenceType.SANITIZATION_ROUTINE.value,
                    description=f"Observed sanitization or safe-loading routine invocation: '{call_name}'.",
                    code_snippet=ast.unparse(node),
                    line_number=getattr(node, "lineno", finding_line),
                    polarity="REFUTING",
                ))

        elif isinstance(node, ast.JoinedStr):
            # Dynamic f-string interpolation observed within function scope
            supporting.append(EvidenceItem(
                evidence_type=EvidenceType.DATA_FLOW_PATH.value,
                description="Dynamic f-string formatting observed within function scope.",
                code_snippet=ast.unparse(node),
                line_number=getattr(node, "lineno", finding_line),
                polarity="SUPPORTING",
            ))

    return is_constant_sink, supporting, refuting


def collect_finding_evidence(
    finding: SecurityFinding,
    repo: Optional[Repository] = None,
    custom_code: Optional[str] = None,
) -> EvidenceDossier:
    """Collects comprehensive evidence, source lines, and AST indicators for a finding."""
    # 1. Preserve original scanner finding
    original_snapshot = OriginalFindingSnapshot(
        finding_id=finding.id,
        scanner_name=finding.scanner_name or finding.scanner_identifier or "Security Scanner",
        rule_identifier=finding.rule_identifier or finding.cwe or "RULE-UNKNOWN",
        cwe=finding.cwe or "CWE-General",
        original_severity=finding.severity,
        scanner_message=redact_secrets(finding.title or finding.evidence_reference or "Finding reported"),
        file_path=finding.file_path,
        line_number=finding.line_number,
    )

    # 2. Retrieve source code context
    code_excerpt: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    is_truncated = False
    is_incomplete = False

    if custom_code is not None:
        code_excerpt = redact_secrets(custom_code)
        lines = code_excerpt.strip().splitlines()
        start_line = finding.line_number
        end_line = finding.line_number + len(lines) - 1
        if len(lines) <= 1 or len(code_excerpt.strip()) == 0:
            is_incomplete = True
    elif repo and repo.workspace_path:
        ctx = get_bounded_source_context(
            repo=repo,
            file_path=finding.file_path,
            target_line=finding.line_number,
            window_lines=12,
        )
        if ctx:
            code_excerpt = redact_secrets(ctx.code_excerpt)
            start_line = ctx.start_line
            end_line = ctx.end_line
            is_truncated = ctx.is_truncated
        else:
            is_incomplete = True
    elif finding.code_excerpt:
        code_excerpt = redact_secrets(finding.code_excerpt)
        start_line = finding.line_number
        lines = code_excerpt.strip().splitlines()
        end_line = finding.line_number + len(lines) - 1
        if len(lines) <= 1:
            is_incomplete = True
    else:
        is_incomplete = True

    # 3. Detect file context (test or mock context)
    is_test = bool(TEST_PATH_PATTERN.search(finding.file_path or ""))

    # 4. Detect prompt-injection attempts in source comments or text
    has_prompt_injection = False
    prompt_injection_details = None
    if code_excerpt and PROMPT_INJECTION_PATTERN.search(code_excerpt):
        has_prompt_injection = True
        matched = PROMPT_INJECTION_PATTERN.search(code_excerpt).group(0)
        prompt_injection_details = f"Detected adversarial directive in source text: '{matched}'."

    # 5. Extract AST evidence
    supporting_evidence: List[EvidenceItem] = []
    refuting_evidence: List[EvidenceItem] = []

    if code_excerpt and not is_incomplete:
        _, ast_sup, ast_ref = _detect_ast_properties(code_excerpt, finding.line_number)
        supporting_evidence.extend(ast_sup)
        refuting_evidence.extend(ast_ref)

    if is_test:
        refuting_evidence.append(EvidenceItem(
            evidence_type=EvidenceType.TEST_OR_MOCK_CONTEXT.value,
            description="Finding is located within a test suite or mock fixture, where hardcoded credentials or mock SQL queries are typically intentional.",
            file_path=finding.file_path,
            line_number=finding.line_number,
            polarity="REFUTING",
        ))

    if has_prompt_injection:
        refuting_evidence.append(EvidenceItem(
            evidence_type=EvidenceType.PROMPT_INJECTION_SIGNAL.value,
            description=f"Source code contains untrusted instructions attempting to coerce validation assessment: {prompt_injection_details}",
            file_path=finding.file_path,
            line_number=finding.line_number,
            polarity="NEUTRAL",
        ))

    # 6. Missing evidence identification
    missing_evidence: List[str] = []
    if is_incomplete:
        missing_evidence.append("Source code excerpt is missing, unreadable, or insufficient to inspect surrounding block.")
    else:
        missing_evidence.append("Inter-procedural data flow from caller/controller to this function is not visible in this file.")
        missing_evidence.append("Caller validation contracts and database connection configuration require inter-file analysis.")
        missing_evidence.append("Runtime exploit reproduction test asserting payload execution.")

    # 7. Unsupported analysis capabilities & limitations
    analysis_limitations: List[str] = [
        "Single-file AST analysis does not perform cross-file whole-program pointer analysis.",
        "Dynamic runtime exploitability is not guaranteed without executing targeted regression tests in an isolated sandbox.",
        "Custom application-level sanitizer functions are evaluated syntactically; semantic correctness requires test verification.",
    ]

    # 8. Dependency information
    dependency_info = None
    if repo and repo.workspace_path:
        req_file = Path(repo.workspace_path) / "requirements.txt"
        if req_file.exists():
            try:
                dependency_info = f"Found requirements.txt ({len(req_file.read_text().splitlines())} dependencies specified)"
            except Exception:
                pass

    # 9. Compute cryptographic hash
    hash_payload = {
        "finding_id": finding.id,
        "rule_identifier": original_snapshot.rule_identifier,
        "file_path": original_snapshot.file_path,
        "line_number": original_snapshot.line_number,
        "code_excerpt": code_excerpt,
    }
    evidence_hash = hashlib.sha256(json.dumps(hash_payload, sort_keys=True).encode("utf-8")).hexdigest()

    return EvidenceDossier(
        original_finding=original_snapshot,
        code_excerpt=code_excerpt,
        start_line=start_line,
        end_line=end_line,
        is_truncated=is_truncated,
        is_incomplete=is_incomplete,
        is_test_file=is_test,
        has_prompt_injection=has_prompt_injection,
        prompt_injection_details=prompt_injection_details,
        supporting_evidence=supporting_evidence,
        refuting_evidence=refuting_evidence,
        missing_evidence=missing_evidence,
        analysis_limitations=analysis_limitations,
        dependency_info=dependency_info,
        evidence_hash=evidence_hash,
    )
