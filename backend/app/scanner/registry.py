"""Scanner registry managing adapters and tool availability."""
from typing import Any, Dict, List, Optional
from .base import BaseScannerAdapter
from .bandit import BanditScannerAdapter
from .pip_audit import PipAuditScannerAdapter
from .semgrep import SemgrepScannerAdapter
from .gitleaks import GitleaksScannerAdapter
from .secret_detector import SecretScannerAdapter


class ScannerRegistry:
    """Central registry for discovering, configuring, and invoking security scanners."""

    def __init__(self):
        self._adapters: Dict[str, BaseScannerAdapter] = {}
        # Register initial security scanners
        self.register(BanditScannerAdapter())
        self.register(PipAuditScannerAdapter())
        self.register(SemgrepScannerAdapter())
        self.register(GitleaksScannerAdapter())
        self.register(SecretScannerAdapter())

    def register(self, adapter: BaseScannerAdapter) -> None:
        """Register a scanner adapter."""
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> Optional[BaseScannerAdapter]:
        """Retrieve adapter by short identifier."""
        return self._adapters.get(name)

    def list_all(self) -> List[BaseScannerAdapter]:
        """List all registered adapters."""
        return list(self._adapters.values())

    def get_available(self) -> List[BaseScannerAdapter]:
        """List adapters currently available on the host/worker environment."""
        return [adapter for adapter in self._adapters.values() if adapter.is_available()]

    def describe_scanners(self) -> List[Dict[str, Any]]:
        """Return metadata summary for all registered scanners."""
        info = []
        for adapter in self._adapters.values():
            available = adapter.is_available()
            version = adapter.get_version() if available else None
            info.append({
                "name": adapter.name,
                "display_name": adapter.display_name,
                "category": adapter.category,
                "is_available": available,
                "version": version,
            })
        return info


scanner_registry = ScannerRegistry()
