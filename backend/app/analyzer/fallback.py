"""Deterministic AppSec rule engine fallback for when AI service is unavailable.

Ensures RepoShield AI functions reliably offline, in air-gapped environments, or
during LLM API outages without sacrificing objective security quality.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..schemas.analyzer import FindingAnalysisResponse
from ..scanner.base import redact_secrets
from .prompts import detect_prompt_injection


def generate_fallback_analysis(
    finding_dict: Dict[str, Any],
    source_context: Optional[str] = None,
    dependency_info: Optional[str] = None,
    is_truncated: bool = False,
) -> FindingAnalysisResponse:
    """Generate high-fidelity, deterministic AppSec analysis from rule taxonomy."""
    finding_id = finding_dict.get("finding_id", "unknown")
    rule_id = finding_dict.get("scanner_rule_id", finding_dict.get("rule_identifier", "RULE-GENERIC"))
    cwe = finding_dict.get("vulnerability_category", finding_dict.get("cwe", "CWE-General"))
    file_path = finding_dict.get("file_path", "unknown")
    line_number = finding_dict.get("line_number", 1)
    message = finding_dict.get("scanner_message", finding_dict.get("title", ""))
    raw_code = redact_secrets(source_context or finding_dict.get("code_excerpt") or "") or ""


    has_injection = detect_prompt_injection(raw_code)

    evidence_list = [
        f"Verified location: {file_path}:{line_number}",
        f"Scanner signature: {finding_dict.get('scanner_name', 'Security Scanner')} ({finding_dict.get('severity', 'MEDIUM')})",
        f"Rule ID: {rule_id}",
    ]
    if raw_code.strip():
        first_line = raw_code.strip().splitlines()[0][:120]
        evidence_list.append(f"Source excerpt: {first_line}")
    if dependency_info:
        evidence_list.append(f"Dependency advisory: {dependency_info[:150]}")

    missing_context: List[str] = []
    limitations: List[str] = ["Analysis generated via RepoShield Deterministic Security Rule Engine."]

    if has_injection:
        limitations.append("Adversarial prompt injection keywords detected in code comments; treated strictly as untrusted text.")

    if is_truncated or not raw_code:
        missing_context.append("Surrounding call-graph, function signatures, and caller sanitizers not fully visible.")
        limitations.append("Confidence moderated due to limited source window.")

    # Taxonomy-driven root cause and remediation mapping
    is_sql = "CWE-89" in cwe or "sql" in message.lower() or "b608" in rule_id.lower()
    is_cmd = "CWE-78" in cwe or "command" in message.lower() or "b605" in rule_id.lower() or "b602" in rule_id.lower()
    is_cred = "CWE-798" in cwe or "secret" in message.lower() or "credential" in message.lower() or "sec-" in rule_id.lower()
    is_sca = "CWE-1395" in cwe or "dependency" in message.lower() or "pip_audit" in str(finding_dict).lower()
    is_crypto = "CWE-327" in cwe or "crypto" in message.lower() or "hash" in message.lower()

    if is_sql:
        explanation = (
            f"The scanner flagged a database operation at {file_path}:{line_number} where query strings appear to be constructed "
            "dynamically using string formatting or concatenation rather than parameterized query bindings."
        )
        impact = (
            "Untrusted inputs could modify the SQL query structure, leading to unauthorized data extraction, "
            "authentication bypass, or data modification."
        )
        root_cause = "Direct interpolation of variable inputs into SQL command string without database-driver parameterization."
        remediation = [
            "Use parameterized queries with positional or named bind parameters (e.g. cursor.execute(query, (param,)))",
            "Employ an established Object-Relational Mapper (ORM) using bound expressions",
            "Avoid string formatting (f-strings, format(), %) when assembling database statements",
        ]
        tests = [
            f"test_{file_path.replace('.', '_').replace('/', '_')}_sql_special_characters_rejected()",
            f"test_{file_path.replace('.', '_').replace('/', '_')}_parameterized_binding_enforced()",
        ]
        confidence = "0.90 (High)" if not is_truncated else "0.45 (Low - Limited Context)"
        exploitable_supported = not is_truncated and ("'" in raw_code or "+" in raw_code or "f\"" in raw_code or "f'" in raw_code)

    elif is_cmd:
        explanation = (
            f"The scanner identified an operating system command execution call at {file_path}:{line_number} "
            "(e.g. os.system, subprocess with shell=True) that may execute arbitrary shell commands."
        )
        impact = (
            "If user input reaches this sink, an attacker could execute arbitrary operating system commands "
            "under the privileges of the application process."
        )
        root_cause = "Invocation of shell interpreter or unescaped command line construction with variable arguments."
        remediation = [
            "Pass arguments as an explicit vector list with shell=False (e.g. subprocess.run(['cmd', arg1, arg2]))",
            "Use native language library APIs instead of spawning external shell processes where possible",
            "Validate all dynamic parameters against a strict alphanumeric allowlist",
        ]
        tests = [
            f"test_{file_path.replace('.', '_').replace('/', '_')}_command_metacharacters_rejected()",
            f"test_{file_path.replace('.', '_').replace('/', '_')}_vector_arguments_used()",
        ]
        confidence = "0.92 (High)" if not is_truncated else "0.50 (Medium)"
        exploitable_supported = not is_truncated and ("os.system" in raw_code or "shell=True" in raw_code)

    elif is_cred:
        explanation = (
            f"Static pattern matching detected hardcoded sensitive credentials or API keys in {file_path}:{line_number}. "
            "Credentials committed to source repositories are susceptible to unauthorized access."
        )
        impact = (
            "Exposure of credentials could grant unauthorized access to connected cloud services, "
            "APIs, or third-party accounts, potentially causing data breaches or unauthorized infrastructure usage."
        )
        root_cause = "Sensitive secrets or tokens stored directly in source code instead of environment variables or secret vaults."
        remediation = [
            "Revoke and rotate the exposed credential immediately",
            "Load credentials dynamically from environment variables or a secret management service (e.g. AWS Secrets Manager, HashiCorp Vault)",
            "Add pre-commit hooks to prevent future credential commits",
        ]
        tests = [
            f"test_{file_path.replace('.', '_').replace('/', '_')}_credential_loaded_from_env()",
            "test_no_hardcoded_secrets_in_repo()",
        ]
        confidence = "0.98 (High)"
        exploitable_supported = True

    elif is_sca:
        explanation = (
            f"Software Composition Analysis identified a known third-party dependency vulnerability at {file_path}. "
            f"The referenced package version is tracked in vulnerability advisory feeds: {message[:120]}."
        )
        impact = (
            "Vulnerabilities in third-party libraries may allow remote code execution, denial of service, "
            "or security policy bypass depending on the specific CVE advisory."
        )
        root_cause = "Outdated or vulnerable dependency pin specified in manifest file."
        remediation = [
            "Upgrade the dependency package to the patched version recommended in the advisory",
            "Run test suites to verify backward compatibility with the upgraded package",
            "Enable automated dependency vulnerability alerting in CI/CD pipeline",
        ]
        tests = [
            "test_dependency_version_upgrade_passes_integration_tests()",
            "test_lockfile_integrity()",
        ]
        confidence = "0.95 (High)"
        exploitable_supported = False  # SCA findings require runtime execution proof to claim exploitability

    elif is_crypto:
        explanation = (
            f"The scanner flagged use of an insecure or broken cryptographic algorithm at {file_path}:{line_number} "
            "(e.g. MD5, SHA1 for signatures, or DES/RC4)."
        )
        impact = (
            "Vulnerable algorithms are susceptible to collision attacks, preimage attacks, or trivial decryption, "
            "compromising data confidentiality and integrity."
        )
        root_cause = "Selection of deprecated or mathematically broken cryptographic primitives."
        remediation = [
            "Upgrade to strong modern cryptographic standards (e.g. SHA-256/SHA-3 for hashing, AES-256-GCM for encryption)",
            "Use Argon2id, bcrypt, or PBKDF2 for password hashing rather than general-purpose digests",
        ]
        tests = [
            f"test_{file_path.replace('.', '_').replace('/', '_')}_uses_strong_crypto_primitive()",
        ]
        confidence = "0.90 (High)"
        exploitable_supported = False

    else:
        explanation = (
            f"Static analysis detected a potential security issue at {file_path}:{line_number} "
            f"matching rule '{rule_id}': {message}."
        )
        impact = (
            "Unvalidated security warnings can represent code quality defects, resource leaks, "
            "or security edge cases that degrade application robustness."
        )
        root_cause = f"Violation of security rule {rule_id}."
        remediation = [
            "Review the flagged line and refactor to adhere to recommended security best practices",
            "Implement defensive input validation and boundary checks",
        ]
        tests = [
            f"test_{file_path.replace('.', '_').replace('/', '_')}_security_regression()",
        ]
        confidence = "0.75 (Medium)"
        exploitable_supported = False

    return FindingAnalysisResponse(
        finding_id=finding_id,
        vulnerability_category=cwe,
        plain_language_explanation=explanation,
        potential_impact=impact,
        relevant_code_evidence=evidence_list,
        likely_root_cause=root_cause,
        suggested_remediation=remediation,
        suggested_targeted_tests=tests,
        missing_context=missing_context,
        limitations=limitations,
        ai_model="reposhield-deterministic-fallback-v1.0",
        analysis_timestamp=datetime.now(timezone.utc),
        confidence=confidence,
        is_exploitable_claim_supported=exploitable_supported,
        requires_human_review=True,
        user_authorized=True,
    )
