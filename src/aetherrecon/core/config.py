"""
Configuration Manager
---------------------
Loads and validates the YAML configuration file, providing typed access
to all settings with sensible defaults.
"""

from pathlib import Path
from typing import Any

import yaml
from rich.console import Console

console = Console()

# Default configuration used when no config file exists or keys are missing
DEFAULTS: dict[str, Any] = {
    "general": {
        "project_name": "AetherRecon Scan",
        "output_dir": "./output",
        "log_level": "INFO",
    },
    "scope": {
        "require_confirmation": True,
        "allowed_targets": [],
        "blocked_targets": ["127.0.0.1", "localhost", "*.gov", "*.mil", "*.edu"],
        "respect_robots_txt": True,
    },
    "rate_limiting": {
        "requests_per_second": 10,
        "burst_size": 20,
        "backoff_factor": 1.5,
        "max_retries": 3,
        "timeout_seconds": 10,
        "concurrent_tasks": 50,
    },
    "profiles": {
        "safe": {
            "description": "Passive-only scan — no fuzzing, low concurrency",
            "modules": ["whois", "dns_enum", "cert_transparency", "subdomain_enum", "subfinder"],
            "rate_limit": 5,
        },
        "standard": {
            "description": "Moderate crawling, limited probing, tech detection",
            "modules": [
                "whois", "dns_enum", "cert_transparency", "subdomain_enum", "subfinder",
                "theharvester", "wayback", "gau", "http_probe", "tls_inspect", "headers_analysis",
            ],
            "rate_limit": 10,
        },
        "moderate": {
            "description": "Steady scanning for moderate production targets",
            "modules": [
                "whois", "dns_enum", "cert_transparency", "subdomain_enum", "subfinder",
                "theharvester", "wayback", "http_probe", "port_scan", "tech_fingerprint",
                "tls_inspect", "headers_analysis",
            ],
            "rate_limit": 15,
        },
        "high": {
            "description": "Thorough active scanning with all checks",
            "modules": [
                "whois", "dns_enum", "cert_transparency", "subdomain_enum", "subfinder", "amass",
                "theharvester", "wayback", "gau", "http_probe", "port_scan",
                "tech_fingerprint", "whatweb", "screenshot", "tls_inspect",
                "headers_analysis", "cve_correlate", "feroxbuster", "wpscan",
                "api_discovery", "secrets_scanner", "misconfig_engine",
            ],
            "rate_limit": 25,
        },
        "advanced": {
            "description": "Deep fingerprinting, targeted vulnerability checks, screenshot collection",
            "modules": [
                "whois", "dns_enum", "cert_transparency", "subdomain_enum", "subfinder", "amass",
                "theharvester", "wayback", "gau", "http_probe", "port_scan", "naabu",
                "nmap_enum", "tech_fingerprint", "whatweb", "screenshot", "tls_inspect",
                "headers_analysis", "cve_correlate", "katana", "api_discovery",
                "login_surface", "secrets_scanner", "misconfig_engine", "tech_specific",
            ],
            "rate_limit": 35,
        },
        "full_audit": {
            "description": "Full audit — endpoint discovery, parameter analysis, technology-aware validation",
            "modules": ["all"],
            "rate_limit": 35,
        },
        "aggressive": {
            "description": "Fast aggressive scanning for CTF/lab targets",
            "modules": ["all"],
            "rate_limit": 50,
        },
        "extreme": {
            "description": "Maximum speed, lab-only, all checks enabled",
            "modules": ["all"],
            "rate_limit": 100,
        },
    },
    "modules": {
        "port_scan": {"top_ports": 1000, "scan_type": "connect", "timeout": 2},
        "http_probe": {
            "follow_redirects": True,
            "user_agent": "AetherRecon/1.0 (Authorized Security Audit)",
            "check_ports": [80, 443, 8080, 8443, 8000, 8888],
        },
        "subdomain_enum": {
            "resolvers": ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
            "concurrent_resolves": 100,
        },
    },
    "tools": {},
    "reporting": {
        "formats": ["json", "html", "markdown"],
        "html_theme": "cyberpunk",
        "deduplicate_findings": True,
    },
}


class AetherConfig:
    """
    Loads YAML configuration with layered defaults.

    Usage:
        config = AetherConfig("config.yaml")
        rate = config.data["rate_limiting"]["requests_per_second"]
    """

    def __init__(self, path: str | Path = "config.yaml"):
        self.path = Path(path)
        self.data = self._load()

    def _load(self) -> dict[str, Any]:
        """Load config from YAML file, falling back to defaults if missing."""
        if self.path.exists():
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    user_cfg = yaml.safe_load(f) or {}
                return self._merge(DEFAULTS, user_cfg)
            except yaml.YAMLError as e:
                console.print(f"[yellow]⚠ Config parse error: {e}. Using defaults.[/yellow]")
                return DEFAULTS.copy()
        else:
            console.print(f"[dim]No config file at {self.path}. Using defaults.[/dim]")
            return DEFAULTS.copy()

    def _merge(self, base: dict, override: dict) -> dict:
        """Deep-merge override dict into base dict."""
        merged = base.copy()
        for key, val in override.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(val, dict):
                merged[key] = self._merge(merged[key], val)
            else:
                merged[key] = val
        return merged

    def get_profile(self, name: str) -> dict[str, Any]:
        """Get a named scanning profile configuration."""
        profiles = self.data.get("profiles", {})
        if name not in profiles:
            console.print(f"[yellow]Profile '{name}' not found. Using 'standard'.[/yellow]")
            name = "standard"
        return profiles.get(name, profiles.get("standard", {}))

    def get_module_config(self, module_name: str) -> dict[str, Any]:
        """Get module-specific configuration."""
        return self.data.get("modules", {}).get(module_name, {})

    def get_rate_limit(self, profile: str | None = None) -> int:
        """Get the effective rate limit for a profile or global default."""
        if profile:
            prof = self.get_profile(profile)
            return prof.get("rate_limit", self.data["rate_limiting"]["requests_per_second"])
        return self.data["rate_limiting"]["requests_per_second"]
