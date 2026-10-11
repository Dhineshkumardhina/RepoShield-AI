"""Deterministic rule engine evaluating collected evidence against explicit validation rules."""
from typing import List, Tuple
from .collector import EvidenceDossier
from .enums import ValidationStatus


class RuleEvaluationResult:
    """Outcome of evaluating evidence rules against a finding dossier."""
    def __init__(
        self,
        assessment_status: ValidationStatus,
        confidence_score: float,
        confidence_level: str,
        explanation: str,
        evidence_summary: str,
        suggested_next_steps: List[str],
    ):
        self.assessment_status = assessment_status
        self.confidence_score = confidence_score
        self.confidence_level = confidence_level
        self.explanation = explanation
        self.evidence_summary = evidence_summary
        self.suggested_next_steps = suggested_next_steps


def evaluate_evidence_rules(dossier: EvidenceDossier) -> RuleEvaluationResult:
    """Evaluates evidence facts according to formal AppSec validation policies."""
    
    # RULE 1: Prompt-Injection Defense
    # If untrusted comments or text attempt to hijack the evaluation, flag as untrusted commentary
    # and require human review. Never let untrusted directives override security status.
    if dossier.has_prompt_injection:
        return RuleEvaluationResult(
            assessment_status=ValidationStatus.HUMAN_REVIEW_REQUIRED,
            confidence_score=0.85,
            confidence_level="HIGH",
            explanation=(
                f"Source code contains active prompt-injection directive ({dossier.prompt_injection_details}). "
                "RepoShield AI isolates repository content as untrusted input. The directive has been "
                "neutralized and flagged for mandatory human security review."
            ),
            evidence_summary="Prompt-injection payload detected in source comments/literals. Automated assessment halted to protect pipeline integrity.",
            suggested_next_steps=[
                "Manually inspect the affected file for malicious code or unauthorized instructions.",
                "Review git blame to identify author of prompt-injection payload.",
                "Verify whether the original scanner finding is valid without relying on source comments.",
            ],
        )

    # RULE 2: Incomplete Code Context -> INSUFFICIENT_EVIDENCE
    # If source excerpt is missing, unreadable, or only a single detached line
    if dossier.is_incomplete or not dossier.code_excerpt:
        return RuleEvaluationResult(
            assessment_status=ValidationStatus.INSUFFICIENT_EVIDENCE,
            confidence_score=0.30,
            confidence_level="LOW",
            explanation=(
                "Available source code excerpt is missing or insufficient to observe function boundaries, "
                "parameter origins, or caller sanitization routines. Without surrounding context, "
                "an authoritative evidence-backed determination cannot be made."
            ),
            evidence_summary="Incomplete code excerpt prevents inspecting data-flow or sanitization context.",
            suggested_next_steps=[
                "Retrieve surrounding function and caller context from repository workspace.",
                "Run a targeted test or local SAST pass to inspect full file boundaries.",
                "Provide complete file context for manual validation.",
            ],
        )

    # RULE 3: Test Context or Constant Literal Argument -> POSSIBLE_FALSE_POSITIVE
    has_constant_sink = any(
        e.evidence_type == "CONSTANT_ARGUMENT" for e in dossier.refuting_evidence
    )

    # Check if finding is in a test/mock fixture
    if dossier.is_test_file and not dossier.supporting_evidence:
        return RuleEvaluationResult(
            assessment_status=ValidationStatus.POSSIBLE_FALSE_POSITIVE,
            confidence_score=0.85,
            confidence_level="HIGH" if has_constant_sink else "MEDIUM",
            explanation=(
                f"Finding is located in test file '{dossier.original_finding.file_path}'. "
                "Test fixtures and unit assertions frequently utilize mock data, dummy passwords, or simulated payloads. "
                "This code is not reachable in production execution paths."
            ),
            evidence_summary="Code resides in a test/mock file outside the production application runtime.",
            suggested_next_steps=[
                "Configure scanner rule targets to exclude test directories from production SAST gates.",
                "Verify that test utilities are not imported into production entry points.",
            ],
        )

    # Check if all sinks are constant arguments with zero user variables
    if has_constant_sink and not dossier.supporting_evidence:
        return RuleEvaluationResult(
            assessment_status=ValidationStatus.POSSIBLE_FALSE_POSITIVE,
            confidence_score=0.90,
            confidence_level="HIGH",
            explanation=(
                f"Static analysis finding '{dossier.original_finding.rule_identifier}' flagged a sensitive sink, "
                "but AST inspection confirms the argument is a static compile-time constant string with "
                "no user variable interpolation or external data formatting."
            ),
            evidence_summary="Target sink receives an immutable literal constant; no unescaped user data flow observed.",
            suggested_next_steps=[
                "Confirm that the constant string is never modified dynamically upstream.",
                "Consider adding a scanner inline exclusion annotation if constant usage is intentional.",
            ],
        )

    # RULE 4: Conflicting Evidence -> HUMAN_REVIEW_REQUIRED
    # If both supporting evidence (e.g. untrusted variable into sink) AND refuting evidence (e.g. custom sanitizer) exist
    if dossier.supporting_evidence and dossier.refuting_evidence:
        sanitizer_names = [
            e.description for e in dossier.refuting_evidence if e.evidence_type == "SANITIZATION_ROUTINE"
        ]
        return RuleEvaluationResult(
            assessment_status=ValidationStatus.HUMAN_REVIEW_REQUIRED,
            confidence_score=0.60,
            confidence_level="MEDIUM",
            explanation=(
                "Conflicting evidentiary signals detected: Untrusted data appears to flow into a sensitive sink, "
                f"but a potential sanitization routine was also observed ({'; '.join(sanitizer_names) if sanitizer_names else 'mitigating context'}). "
                "Static analysis cannot prove whether the custom sanitizer completely neutralizes all bypass vectors."
            ),
            evidence_summary="Sensitive sink receives input, but an unverified sanitization call exists. Requires human verification.",
            suggested_next_steps=[
                "Auditor review of the sanitization function implementation to ensure parameterization or full escaping.",
                "Implement a targeted security regression test with adversarial exploit payloads to empirically verify safety.",
            ],
        )

    # RULE 5: Clear Supporting Evidence -> SUPPORTED_BY_EVIDENCE
    # Untrusted data flows directly into dangerous sink with zero sanitization observed
    if dossier.supporting_evidence and not dossier.refuting_evidence:
        return RuleEvaluationResult(
            assessment_status=ValidationStatus.SUPPORTED_BY_EVIDENCE,
            confidence_score=0.92,
            confidence_level="HIGH",
            explanation=(
                f"Observable code evidence strongly supports scanner finding '{dossier.original_finding.rule_identifier}'. "
                "AST analysis reveals direct dynamic formatting or unparameterized variable interpolation "
                "into an execution sink without sanitizing or boundary-checking routines."
            ),
            evidence_summary="Direct source-to-sink variable interpolation observed without sanitization.",
            suggested_next_steps=[
                "Refactor code to use safe parameterized APIs (e.g. SQL query placeholders, execve list arguments, safe YAML loader).",
                "Generate an evidence-backed patch proposal using RepoShield Fix Verification Engine.",
            ],
        )

    # DEFAULT: HUMAN_REVIEW_REQUIRED
    return RuleEvaluationResult(
        assessment_status=ValidationStatus.HUMAN_REVIEW_REQUIRED,
        confidence_score=0.50,
        confidence_level="MEDIUM",
        explanation=(
            "The available static evidence is neither definitively corroborating nor refuting. "
            "Human application security review is recommended to evaluate business context."
        ),
        evidence_summary="Ambiguous static signals require human security triage.",
        suggested_next_steps=[
            "Triage finding during code review before production deployment.",
            "Inspect caller entry points and API routing controllers.",
        ],
    )
