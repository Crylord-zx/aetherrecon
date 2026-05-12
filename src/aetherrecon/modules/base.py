"""
Base Module
-----------
Abstract base class for all scan modules.
"""

from abc import ABC, abstractmethod
from typing import Any

from aetherrecon.core.config import AetherConfig
from aetherrecon.core.database import Database
from aetherrecon.core.rate_limiter import RateLimiter


class BaseModule(ABC):
    """Base class all scan modules inherit from."""

    name: str = "base"
    category: str = "unknown"
    description: str = ""

    def __init__(
        self,
        config: AetherConfig,
        db: Database,
        scan_id: int,
        rate_limiter: RateLimiter,
        context: dict[str, Any] | None = None,
        plugin_manager: Any = None,
        console: Any = None,
    ):
        self.config = config
        self.db = db
        self.scan_id = scan_id
        self.rate_limiter = rate_limiter
        self.context = context or {}
        
        if console is None:
            try:
                from rich.console import Console
                self.console = Console()
            except ImportError:
                class DummyConsole:
                    def print(self, *args, **kwargs): pass
                self.console = DummyConsole()
        else:
            self.console = console

        # Instantiate plugin manager if not provided
        if plugin_manager is None:
            from aetherrecon.core.plugin_manager import PluginManager
            self.plugin_manager = PluginManager(self.config)
        else:
            self.plugin_manager = plugin_manager

    @abstractmethod
    async def run(self, target: str) -> Any:
        """Execute the module against the target. Must be implemented."""
        ...

    async def add_finding(self, title: str, severity: str = "info",
                          description: str = "", data: dict | None = None):
        await self.db.add_finding(
            scan_id=self.scan_id, module=self.name,
            category=self.category, severity=severity,
            title=title, description=description, data=data,
        )

    async def add_asset(self, asset_type: str, value: str,
                        metadata: dict | None = None):
        await self.db.add_asset(
            scan_id=self.scan_id, asset_type=asset_type,
            value=value, discovered_by=self.name, metadata=metadata,
        )

    async def add_subdomain(self, subdomain: str, ip: str | None = None, source: str = ""):
        await self.db.add_subdomain(self.scan_id, subdomain, ip, source)
        # Also add as asset for backward compatibility
        await self.add_asset("subdomain", subdomain, {"ip": ip, "source": source})

    async def add_vulnerability(self, host: str, name: str, severity: str, cve: str = "", desc: str = "", proof: str = ""):
        await self.db.add_vulnerability(self.scan_id, host, name, severity, cve, desc, proof)
        # Also add as finding
        await self.add_finding(f"Vulnerability: {name}", severity, desc, {"host": host, "cve": cve, "proof": proof})

    async def add_technology(self, host: str, name: str, version: str = "", category: str = ""):
        await self.db.add_technology(self.scan_id, host, name, version, category)

    async def add_screenshot(self, host: str, file_path: str):
        await self.db.add_screenshot(self.scan_id, host, file_path)

    async def add_live_host(self, host: str, port: int, scheme: str, status: int, title: str):
        await self.db.add_live_host(self.scan_id, host, port, scheme, status, title)

    async def add_evidence(self, evidence_type: str, host: str = "", description: str = "", data: dict | None = None, file_path: str = ""):
        await self.db.add_evidence(self.scan_id, evidence_type, host, self.name, description, data, file_path)
