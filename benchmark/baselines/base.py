"""Abstract Baseline Interface for Fix Verification Evaluation."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
import tempfile
from typing import Any, Dict, Optional, Tuple

from ..models import BenchmarkCaseDefinition, CandidatePatchDefinition


@dataclass
class BaselineEvaluationOutcome:
    baseline_id: str
    baseline_name: str
    decision: str  # "VERIFIED", "FAILED", "INCONCLUSIVE"
    latency_ms: float
    error_message: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)


class BaseVerificationBaseline(ABC):
    """Abstract base class for all benchmark evaluation baselines."""

    @property
    @abstractmethod
    def baseline_id(self) -> str:
        """Machine-readable identifier (e.g. B1_sast_alone)."""
        pass

    @property
    @abstractmethod
    def baseline_name(self) -> str:
        """Human-readable display name."""
        pass

    @abstractmethod
    def evaluate_patch(
        self,
        case: BenchmarkCaseDefinition,
        patch: CandidatePatchDefinition,
        timeout_seconds: int = 20,
    ) -> BaselineEvaluationOutcome:
        """Evaluate candidate patch against the specified benchmark case."""
        pass


def setup_temporary_sandbox(
    case: BenchmarkCaseDefinition,
    patch_diff: Optional[str] = None,
) -> Tuple[Path, bool]:
    """Create isolated sandbox directory populated with source files and optional patch."""
    from app.verification.patch_applier import apply_patch_to_workspace
    from app.verification.patch_parser import parse_unified_diff

    tmp_dir = Path(tempfile.mkdtemp(prefix=f"bm_{case.case_id}_"))
    source_file = tmp_dir / case.source_file
    source_file.parent.mkdir(parents=True, exist_ok=True)
    source_file.write_text(case.vulnerable_code, encoding="utf-8")

    # Add existing test if present
    if case.existing_unit_test:
        test_file = tmp_dir / "tests" / "test_existing.py"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text(case.existing_unit_test, encoding="utf-8")

    # Add init files for clean Python module imports
    (tmp_dir / "src" / "__init__.py").touch()
    (tmp_dir / "tests" / "__init__.py").touch()

    patch_success = True
    if patch_diff:
        parsed = parse_unified_diff(patch_diff)
        if not parsed.is_valid:
            patch_success = False
        else:
            patch_success, _ = apply_patch_to_workspace(tmp_dir, parsed)

    return tmp_dir, patch_success
