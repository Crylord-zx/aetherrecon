"""
Scan Orchestrator v2.0
-----------------------
Central coordinator that runs scan modules in the correct order,
manages concurrency, and collects results.

Elite Architecture:
  Passive Intel → Asset Correlation → Live Infrastructure Mapper
  → Adaptive Fingerprinting → Endpoint Discovery AI
  → Technology-Specific Analysis → Verified Vulnerability Engine
  → Confidence Scoring → Evidence Collection → Risk Prioritization
  → Remediation Engine → Executive + Technical Reporting
"""

import asyncio
from datetime import datetime, timezone
from typing import Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

from aetherrecon.core.config import AetherConfig
from aetherrecon.core.database import Database
from aetherrecon.core.state import StateManager
from aetherrecon.core.plugin_manager import PluginManager
from aetherrecon.core.rate_limiter import AdaptiveRateLimiter

# Core Intelligence Engines
from aetherrecon.engines.confidence import ConfidenceEngine
from aetherrecon.engines.correlation_engine import CorrelationEngine
from aetherrecon.engines.evidence import EvidenceCollector
from aetherrecon.engines.fp_reducer import FalsePositiveReducer
from aetherrecon.engines.risk_prioritizer import RiskPrioritizer
from aetherrecon.engines.asset_relationships import AssetRelationshipEngine
from aetherrecon.engines.exposure_context import ExposureContextEngine
from aetherrecon.engines.remediation import RemediationEngine
from aetherrecon.engines.stability import ServiceStabilityGuard

# Module imports — Passive
from aetherrecon.modules.passive.whois_lookup import WhoisModule
from aetherrecon.modules.passive.dns_enum import DNSEnumModule
from aetherrecon.modules.passive.cert_transparency import CertTransparencyModule
from aetherrecon.modules.passive.subdomain_enum import SubdomainEnumModule
from aetherrecon.modules.passive.wayback import WaybackModule
from aetherrecon.modules.passive.theharvester import TheHarvesterModule
from aetherrecon.modules.passive.subfinder import SubfinderModule
from aetherrecon.modules.passive.amass import AmassModule
from aetherrecon.modules.passive.gau import GauModule
from aetherrecon.modules.passive.dnsx import DnsxModule
from aetherrecon.modules.passive.assetfinder import AssetfinderModule

# Module imports — Active
from aetherrecon.modules.active.http_probe import HTTPProbeModule
from aetherrecon.modules.active.port_scan import PortScanModule
from aetherrecon.modules.active.tech_fingerprint import TechFingerprintModule
from aetherrecon.modules.active.whatweb import WhatWebModule
from aetherrecon.modules.active.screenshot import ScreenshotModule
from aetherrecon.modules.active.feroxbuster import FeroxbusterModule
from aetherrecon.modules.active.tls_inspect import TLSInspectModule
from aetherrecon.modules.active.nmap_enum import NmapEnumModule
from aetherrecon.modules.active.katana import KatanaModule
from aetherrecon.modules.active.naabu import NaabuModule
from aetherrecon.modules.active.rustscan import RustScanModule
from aetherrecon.modules.active.ffuf import FfufModule
from aetherrecon.modules.active.paramspider import ParamspiderModule
from aetherrecon.modules.active.testssl import TestsslModule
from aetherrecon.modules.active.arjun import ArjunModule
from aetherrecon.modules.active.eyewitness import EyewitnessModule

# Module imports — Vulnerability
from aetherrecon.modules.vuln.headers_analysis import HeadersAnalysisModule
from aetherrecon.modules.vuln.cve_correlate import CVECorrelateModule
from aetherrecon.modules.vuln.wpscan import WPScanModule
from aetherrecon.modules.vuln.cmseek import CMSeekModule
from aetherrecon.modules.vuln.nuclei import NucleiModule
from aetherrecon.modules.vuln.dalfox import DalfoxModule
from aetherrecon.modules.vuln.sqlmap import SQLMapModule
from aetherrecon.modules.vuln.commix import CommixModule
from aetherrecon.modules.vuln.trufflehog import TrufflehogModule
from aetherrecon.modules.vuln.gitleaks import GitleaksModule
from aetherrecon.modules.vuln.nikto import NiktoModule

# Engine modules (act as scan modules)
from aetherrecon.engines.secrets_scanner import SecretsScanner
from aetherrecon.engines.api_discovery import APIDiscoveryModule
from aetherrecon.engines.misconfig_engine import MisconfigEngine
from aetherrecon.engines.tech_specific import TechSpecificAnalyzer
from aetherrecon.engines.login_surface import LoginSurfaceAnalyzer

# Reporting
from aetherrecon.modules.reporting.risk_analyzer import RiskAnalyzerModule


# Ghost Protocol Phase Order — 14 Elite Stages
PHASE_ORDER = {
    "passive_recon": [
        "whois", "theharvester", "wayback", "cert_transparency",
        "subfinder", "amass", "assetfinder", "gau",
    ],
    "subdomain_discovery": ["dns_enum", "dnsx", "subdomain_enum"],
    "live_host_detection": ["http_probe"],
    "port_discovery": ["port_scan", "naabu", "rustscan"],
    "service_fingerprinting": ["nmap_enum", "whatweb", "tls_inspect", "testssl"],
    "web_discovery": ["katana", "feroxbuster", "ffuf", "paramspider", "arjun"],
    "endpoint_discovery": ["api_discovery", "login_surface"],
    "tech_detection": ["tech_fingerprint"],
    "tech_specific_analysis": ["tech_specific"],
    "vuln_detection": [
        "nuclei", "nikto", "headers_analysis", "cve_correlate",
        "secrets_scanner", "trufflehog", "gitleaks", "misconfig_engine",
    ],
    "specialized_testing": ["wpscan", "cmseek", "dalfox", "sqlmap", "commix"],
    "screenshot_intel": ["screenshot", "eyewitness"],
    "risk_scoring": ["risk_analyzer"],
}

# Module registry: maps config names to module classes
MODULE_REGISTRY: dict[str, type] = {
    # Discovery & Recon (Passive)
    "whois": WhoisModule,
    "dns_enum": DNSEnumModule,
    "dnsx": DnsxModule,
    "cert_transparency": CertTransparencyModule,
    "subdomain_enum": SubdomainEnumModule,
    "assetfinder": AssetfinderModule,
    "wayback": WaybackModule,
    "theharvester": TheHarvesterModule,
    "subfinder": SubfinderModule,
    "amass": AmassModule,
    "gau": GauModule,

    # Active & Probing
    "http_probe": HTTPProbeModule,
    "port_scan": PortScanModule,
    "naabu": NaabuModule,
    "rustscan": RustScanModule,
    "nmap_enum": NmapEnumModule,
    "tech_fingerprint": TechFingerprintModule,
    "whatweb": WhatWebModule,
    "screenshot": ScreenshotModule,
    "tls_inspect": TLSInspectModule,
    "testssl": TestsslModule,

    # Content Discovery
    "katana": KatanaModule,
    "feroxbuster": FeroxbusterModule,
    "ffuf": FfufModule,
    "paramspider": ParamspiderModule,
    "arjun": ArjunModule,
    "eyewitness": EyewitnessModule,

    # Intelligence Engines (as modules)
    "api_discovery": APIDiscoveryModule,
    "login_surface": LoginSurfaceAnalyzer,
    "secrets_scanner": SecretsScanner,
    "misconfig_engine": MisconfigEngine,
    "tech_specific": TechSpecificAnalyzer,

    # Vulnerability & Specialized
    "nuclei": NucleiModule,
    "nikto": NiktoModule,
    "headers_analysis": HeadersAnalysisModule,
    "cve_correlate": CVECorrelateModule,
    "wpscan": WPScanModule,
    "cmseek": CMSeekModule,
    "dalfox": DalfoxModule,
    "sqlmap": SQLMapModule,
    "commix": CommixModule,
    "trufflehog": TrufflehogModule,
    "gitleaks": GitleaksModule,

    # Reporting
    "risk_analyzer": RiskAnalyzerModule,
}


class ScanOrchestrator:
    def __init__(
        self,
        target: str,
        profile: str,
        modules: list[str],
        config: AetherConfig,
        db: Database,
        state_manager: StateManager,
        plugin_manager: PluginManager,
        console: Console,
    ):
        self.target = target
        self.profile = profile
        self.requested_modules = modules
        self.config = config
        self.db = db
        self.state = state_manager
        self.plugins = plugin_manager
        self.console = console

        rate = config.get_rate_limit(profile)
        self.rate_limiter = AdaptiveRateLimiter(rate=rate, burst=rate * 2)

        # Initialize intelligence engines
        self.confidence_engine = ConfidenceEngine()
        self.correlation_engine = CorrelationEngine(self.confidence_engine)
        self.evidence_collector = EvidenceCollector(
            config.data.get("general", {}).get("output_dir", "./output")
        )
        self.fp_reducer = FalsePositiveReducer()
        self.risk_prioritizer = RiskPrioritizer()
        self.asset_engine = AssetRelationshipEngine()
        self.exposure_engine = ExposureContextEngine()
        self.remediation_engine = RemediationEngine()
        self.stability_guard = ServiceStabilityGuard()

    def _resolve_modules(self) -> list[str]:
        """Resolve 'all' keyword and filter to valid modules."""
        if "all" in self.requested_modules:
            return [m for phase in PHASE_ORDER.values() for m in phase]

        valid = []
        for m in self.requested_modules:
            if m in MODULE_REGISTRY:
                valid.append(m)
        return valid

    async def run(self) -> dict[str, Any]:
        """Execute the full scan pipeline and return aggregated results."""
        results: dict[str, Any] = {
            "timestamp_start": datetime.now(timezone.utc).isoformat(),
            "errors": [],
        }

        scan_id = await self.db.create_scan(self.target, self.profile, self.requested_modules)
        self.state.set_scan_info(self.target, self.profile, self.requested_modules)

        modules_to_run = self._resolve_modules()

        # Remove modules disabled by stability guard
        disabled = self.stability_guard.get_disabled_modules()
        modules_to_run = [m for m in modules_to_run if m not in disabled]

        total = len(modules_to_run)

        # Shared context: modules can deposit data here for later modules to use
        shared_context: dict[str, Any] = {
            "target": self.target,
            "subdomains": [],
            "ips": [],
            "open_ports": [],
            "http_services": [],
            "technologies": [],
            "discovered_urls": [],
            "api_endpoints": [],
            "auth_surfaces": [],
            "js_files": [],
            "secrets": [],
            "cloud_assets": [],
        }

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=30, style="cyan", complete_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
        ) as progress:
            task = progress.add_task("Scanning...", total=total)

            for phase_name, phase_modules in PHASE_ORDER.items():
                for mod_name in phase_modules:
                    if mod_name not in modules_to_run:
                        continue

                    # Skip if stability guard says no
                    if mod_name in self.stability_guard.get_disabled_modules():
                        progress.update(task, advance=1,
                                        description=f"[dim]⚡ Skipped {mod_name} (stability)[/dim]")
                        continue

                    # Skip if already completed (resume mode)
                    if self.state.is_module_complete(mod_name):
                        progress.update(task, advance=1,
                                        description=f"[dim]↻ Skipping {mod_name} (cached)[/dim]")
                        continue

                    progress.update(task, description=f"Running [cyan]{mod_name}[/cyan]...")

                    try:
                        mod_class = MODULE_REGISTRY[mod_name]
                        mod_instance = mod_class(
                            config=self.config,
                            db=self.db,
                            scan_id=scan_id,
                            rate_limiter=self.rate_limiter,
                            context=shared_context,
                            plugin_manager=self.plugins,
                            console=self.console,
                        )
                        mod_results = await mod_instance.run(self.target)
                        results[mod_name] = mod_results

                        # Update shared context with module outputs
                        self._update_context(mod_name, mod_results, shared_context)

                        # Deduplicate context lists
                        for key in ["subdomains", "ips"]:
                            shared_context[key] = list(set(filter(None, shared_context[key])))

                        self.state.mark_module_complete(mod_name, mod_results)

                        # Run agentic analysis if enabled
                        if self.config.data.get("agent", {}).get("enabled", True):
                            from aetherrecon.agents.executor import AgentExecutor
                            agent = AgentExecutor(
                                config=self.config,
                                db=self.db,
                                scan_id=scan_id,
                                rate_limiter=self.rate_limiter,
                                context=shared_context,
                                console=self.console,
                            )
                            agent_results = await agent.process_results(mod_name, mod_results)
                            if agent_results:
                                if "agent" not in results:
                                    results["agent"] = []
                                results["agent"].extend(agent_results)
                    except Exception as e:
                        self.console.print(f"[bold red]Error in module {mod_name}:[/bold red] {e}")
                        results["errors"].append({"module": mod_name, "error": str(e)})
                        continue

                    progress.update(task, advance=1)

        # ── Post-Scan Intelligence ────────────────────────────────────────
        self.console.print("\n[bold magenta]🧠 Running AI Intelligence Engines...[/bold magenta]")

        # Asset Relationship Analysis
        self.asset_engine.ingest_scan_context(shared_context)
        results["asset_relationships"] = self.asset_engine.get_attack_surface_summary()
        results["asset_graph"] = self.asset_engine.to_graph_data()

        # AI Correlation Engine
        correlation_findings = self.correlation_engine.analyze(shared_context)
        results["correlation_findings"] = [f.to_dict() for f in correlation_findings]
        self.console.print(f"  [green]✓[/green] AI Correlation: {len(correlation_findings)} findings")

        # Confidence Scoring
        results["confidence_summary"] = self.confidence_engine.get_risk_summary()

        # False Positive Summary
        results["fp_reduction"] = self.fp_reducer.get_validation_summary()

        # Risk Prioritization
        for finding in correlation_findings:
            self.risk_prioritizer.prioritize(
                title=finding.title,
                host=finding.host,
                severity=finding.severity,
                cvss_score=finding.cvss_score,
                epss_score=finding.epss_score,
                exploit_maturity=finding.exploit_maturity,
                external_exposure=finding.exposure == "internet",
            )
        results["risk_summary"] = self.risk_prioritizer.get_executive_summary()
        results["risk_heatmap"] = self.risk_prioritizer.get_risk_heatmap()

        # Exposure Context Summary
        results["exposure_context"] = self.exposure_engine.get_summary()

        # Evidence Collection
        self.evidence_collector.save_to_disk()
        results["evidence_summary"] = self.evidence_collector.get_summary()

        # Stability Report
        results["stability"] = self.stability_guard.get_status()

        self.console.print(f"  [green]✓[/green] Risk Heatmap: {results['risk_heatmap'].get('total', 0)} items scored")
        self.console.print(f"  [green]✓[/green] Asset Graph: {results['asset_relationships'].get('total_assets', 0)} assets mapped")

        await self.db.finish_scan(scan_id)
        self.state.clear()

        return results

    def _update_context(self, mod_name: str, mod_results: Any,
                        shared_context: dict[str, Any]):
        """Update shared context with module outputs."""
        if mod_name == "dns_enum" and isinstance(mod_results, dict):
            for rtype in ("A", "AAAA"):
                if rtype in mod_results:
                    shared_context["ips"].extend(mod_results[rtype])

        elif mod_name in ("subdomain_enum", "subfinder", "amass") and isinstance(mod_results, list):
            shared_context["subdomains"].extend(
                [r.get("subdomain", "") for r in mod_results if isinstance(r, dict)]
            )

        elif mod_name == "cert_transparency" and isinstance(mod_results, list):
            shared_context["subdomains"].extend(
                [r.get("domain", "") for r in mod_results if isinstance(r, dict)]
            )

        elif mod_name == "theharvester" and isinstance(mod_results, list):
            for item in mod_results:
                if isinstance(item, dict):
                    if "subdomain" in item:
                        shared_context["subdomains"].append(item["subdomain"])
                    if "ip" in item:
                        shared_context["ips"].append(item["ip"])

        elif mod_name in ("wayback", "gau") and isinstance(mod_results, list):
            for item in mod_results:
                if isinstance(item, dict) and "url" in item:
                    shared_context["discovered_urls"].append(item)
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(item["url"])
                        if parsed.hostname and parsed.hostname.endswith(self.target):
                            shared_context["subdomains"].append(parsed.hostname)
                    except Exception:
                        pass

        elif mod_name in ("port_scan", "naabu") and isinstance(mod_results, list):
            shared_context["open_ports"].extend(mod_results)

        elif mod_name == "http_probe" and isinstance(mod_results, list):
            shared_context["http_services"].extend(mod_results)

        elif mod_name == "tech_fingerprint" and isinstance(mod_results, list):
            shared_context["technologies"].extend(mod_results)

        elif mod_name in ("katana", "feroxbuster", "ffuf", "paramspider", "arjun") and isinstance(mod_results, list):
            shared_context["discovered_urls"].extend(mod_results)
