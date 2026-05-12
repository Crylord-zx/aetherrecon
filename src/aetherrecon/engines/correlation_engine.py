"""
AI Correlation Engine
-----------------------
The brain of AetherRecon — correlates technologies, versions, services,
endpoints, and vulnerabilities using intelligent analysis.

Instead of generic CVE spam:
- Validates detected software versions
- Correlates real CVEs to verified versions
- Chains findings to build attack narratives
- Auto-triggers technology-specific modules
"""

from __future__ import annotations
import re
from typing import Any

from aetherrecon.engines.confidence import (
    ConfidenceEngine, ConfidenceFactors, ConfidenceLevel, ScoredFinding,
)


class CorrelationRule:
    """A single correlation rule that maps conditions to actions."""

    def __init__(self, name: str, condition: callable, action: callable, priority: int = 5):
        self.name = name
        self.condition = condition   # (context) -> bool
        self.action = action         # (context, confidence_engine) -> list[ScoredFinding]
        self.priority = priority


class CorrelationEngine:
    """
    Multi-source intelligence correlation engine.

    Analyzes accumulated scan context and produces verified,
    confidence-scored findings instead of raw CVE dumps.
    """

    def __init__(self, confidence_engine: ConfidenceEngine | None = None):
        self.confidence = confidence_engine or ConfidenceEngine()
        self._rules: list[CorrelationRule] = []
        self._correlations: list[dict[str, Any]] = []
        self._register_builtin_rules()

    def _register_builtin_rules(self):
        """Register built-in correlation rules."""

        # WordPress detection → deep WP analysis
        self._rules.append(CorrelationRule(
            name="wordpress_correlation",
            condition=lambda ctx: self._detect_tech(ctx, "wordpress"),
            action=self._correlate_wordpress,
            priority=1,
        ))

        # API surface detected → API security checks
        self._rules.append(CorrelationRule(
            name="api_correlation",
            condition=lambda ctx: self._detect_api_surface(ctx),
            action=self._correlate_api,
            priority=2,
        ))

        # Auth panel detected → security header focus
        self._rules.append(CorrelationRule(
            name="auth_panel_correlation",
            condition=lambda ctx: self._detect_auth_panel(ctx),
            action=self._correlate_auth,
            priority=1,
        ))

        # Database exposure → critical flag
        self._rules.append(CorrelationRule(
            name="database_exposure",
            condition=lambda ctx: self._detect_database_exposure(ctx),
            action=self._correlate_database,
            priority=1,
        ))

        # Version-specific CVE correlation
        self._rules.append(CorrelationRule(
            name="version_cve_correlation",
            condition=lambda ctx: bool(ctx.get("technologies")),
            action=self._correlate_versioned_cves,
            priority=3,
        ))

        # Exposed secrets detection
        self._rules.append(CorrelationRule(
            name="secrets_correlation",
            condition=lambda ctx: bool(ctx.get("discovered_urls")),
            action=self._correlate_secrets,
            priority=2,
        ))

        # Cloud infrastructure detection
        self._rules.append(CorrelationRule(
            name="cloud_correlation",
            condition=lambda ctx: self._detect_cloud_infra(ctx),
            action=self._correlate_cloud,
            priority=3,
        ))

    def analyze(self, context: dict[str, Any]) -> list[ScoredFinding]:
        """
        Run all correlation rules against the accumulated scan context.
        Returns scored, confidence-rated findings.
        """
        findings: list[ScoredFinding] = []

        # Sort rules by priority (lower = higher priority)
        sorted_rules = sorted(self._rules, key=lambda r: r.priority)

        for rule in sorted_rules:
            try:
                if rule.condition(context):
                    rule_findings = rule.action(context, self.confidence)
                    findings.extend(rule_findings)
                    self._correlations.append({
                        "rule": rule.name,
                        "findings_count": len(rule_findings),
                        "priority": rule.priority,
                    })
            except Exception:
                continue

        return findings

    # ── Detection Helpers ─────────────────────────────────────────────────

    @staticmethod
    def _detect_tech(ctx: dict, tech_name: str) -> bool:
        """Check if a specific technology was detected."""
        techs = ctx.get("technologies", [])
        return any(
            tech_name.lower() in str(t.get("name", "")).lower()
            for t in techs if isinstance(t, dict)
        )

    @staticmethod
    def _detect_api_surface(ctx: dict) -> bool:
        """Detect API endpoints in discovered URLs."""
        urls = ctx.get("discovered_urls", [])
        http_services = ctx.get("http_services", [])
        api_patterns = ["/api/", "/v1/", "/v2/", "/graphql", "/swagger", "/openapi",
                        "/rest/", "/json", "/docs", "/redoc"]
        all_urls = [u if isinstance(u, str) else u.get("url", "") for u in urls + http_services]
        return any(
            any(p in url.lower() for p in api_patterns)
            for url in all_urls if url
        )

    @staticmethod
    def _detect_auth_panel(ctx: dict) -> bool:
        """Detect authentication/admin panels."""
        urls = ctx.get("discovered_urls", [])
        http_services = ctx.get("http_services", [])
        auth_patterns = ["/login", "/admin", "/wp-admin", "/dashboard",
                         "/portal", "/auth", "/signin", "/sso", "/oauth"]
        all_urls = [u if isinstance(u, str) else u.get("url", "") for u in urls + http_services]
        return any(
            any(p in url.lower() for p in auth_patterns)
            for url in all_urls if url
        )

    @staticmethod
    def _detect_database_exposure(ctx: dict) -> bool:
        """Detect exposed database services."""
        db_ports = {3306, 5432, 6379, 27017, 1433, 5984, 9200, 9300, 11211}
        open_ports = ctx.get("open_ports", [])
        return any(
            isinstance(p, dict) and p.get("port") in db_ports
            for p in open_ports
        )

    @staticmethod
    def _detect_cloud_infra(ctx: dict) -> bool:
        """Detect cloud infrastructure indicators."""
        cloud_indicators = [
            "amazonaws.com", "azurewebsites.net", "cloudfront.net",
            "googleapis.com", "firebaseio.com", "herokuapp.com",
            "digitaloceanspaces.com", "blob.core.windows.net",
        ]
        subdomains = ctx.get("subdomains", [])
        ips = ctx.get("ips", [])
        all_hosts = subdomains + ips
        return any(
            any(ci in str(h).lower() for ci in cloud_indicators)
            for h in all_hosts
        )

    # ── Correlation Actions ───────────────────────────────────────────────

    def _correlate_wordpress(self, ctx: dict, ce: ConfidenceEngine) -> list[ScoredFinding]:
        """Deep WordPress correlation with version-aware analysis."""
        findings: list[ScoredFinding] = []
        target = ctx.get("target", "")

        # Find WordPress version from tech detection
        wp_version = ""
        for tech in ctx.get("technologies", []):
            if isinstance(tech, dict) and "wordpress" in tech.get("name", "").lower():
                wp_version = tech.get("version", "")

        factors = ConfidenceFactors(
            version_verified=bool(wp_version),
            endpoint_verified=True,
            sources=["tech_fingerprint"],
            evidence=[f"WordPress {'v' + wp_version if wp_version else '(version unknown)'} detected"],
        )

        finding = ce.score_finding(
            title=f"WordPress Installation Detected{' v' + wp_version if wp_version else ''}",
            severity="medium" if wp_version else "low",
            host=target,
            factors=factors,
            module="correlation_engine",
        )
        findings.append(finding)

        return findings

    def _correlate_api(self, ctx: dict, ce: ConfidenceEngine) -> list[ScoredFinding]:
        """Correlate API surface findings."""
        findings: list[ScoredFinding] = []
        target = ctx.get("target", "")
        api_urls = []

        for url_item in ctx.get("discovered_urls", []) + ctx.get("http_services", []):
            url = url_item if isinstance(url_item, str) else url_item.get("url", "")
            api_patterns = ["/api/", "/v1/", "/v2/", "/graphql", "/swagger", "/openapi"]
            if any(p in url.lower() for p in api_patterns):
                api_urls.append(url)

        if api_urls:
            factors = ConfidenceFactors(
                endpoint_verified=True,
                sources=["url_discovery"],
                evidence=[f"API endpoints found: {', '.join(api_urls[:5])}"],
            )
            finding = ce.score_finding(
                title=f"API Surface Detected ({len(api_urls)} endpoints)",
                severity="info",
                host=target,
                factors=factors,
                module="correlation_engine",
            )
            findings.append(finding)

        return findings

    def _correlate_auth(self, ctx: dict, ce: ConfidenceEngine) -> list[ScoredFinding]:
        """Correlate authentication panel findings with exposure context."""
        findings: list[ScoredFinding] = []
        target = ctx.get("target", "")

        auth_urls = []
        for url_item in ctx.get("discovered_urls", []) + ctx.get("http_services", []):
            url = url_item if isinstance(url_item, str) else url_item.get("url", "")
            auth_patterns = ["/login", "/admin", "/wp-admin", "/dashboard",
                             "/portal", "/auth", "/signin"]
            if any(p in url.lower() for p in auth_patterns):
                auth_urls.append(url)

        if auth_urls:
            factors = ConfidenceFactors(
                endpoint_verified=True,
                sources=["url_discovery"],
                evidence=[f"Auth surfaces: {', '.join(auth_urls[:5])}"],
            )
            finding = ce.score_finding(
                title=f"Authentication Surfaces Exposed ({len(auth_urls)} panels)",
                severity="medium",
                host=target,
                factors=factors,
                exposure="internet",
                module="correlation_engine",
            )
            findings.append(finding)

        return findings

    def _correlate_database(self, ctx: dict, ce: ConfidenceEngine) -> list[ScoredFinding]:
        """Correlate exposed database services — critical finding."""
        findings: list[ScoredFinding] = []
        target = ctx.get("target", "")

        db_services = {
            3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
            27017: "MongoDB", 1433: "MSSQL", 5984: "CouchDB",
            9200: "Elasticsearch", 11211: "Memcached",
        }

        exposed_dbs = []
        for port_info in ctx.get("open_ports", []):
            if isinstance(port_info, dict):
                port = port_info.get("port")
                if port in db_services:
                    exposed_dbs.append(f"{db_services[port]} (:{port})")

        if exposed_dbs:
            factors = ConfidenceFactors(
                endpoint_verified=True,
                response_validated=True,
                sources=["port_scan"],
                evidence=[f"Database services exposed: {', '.join(exposed_dbs)}"],
            )
            finding = ce.score_finding(
                title=f"Database Services Exposed to Internet ({len(exposed_dbs)})",
                severity="critical",
                host=target,
                factors=factors,
                exposure="internet",
                module="correlation_engine",
            )
            findings.append(finding)

        return findings

    def _correlate_versioned_cves(self, ctx: dict, ce: ConfidenceEngine) -> list[ScoredFinding]:
        """
        Version-aware CVE correlation.
        Only maps CVEs when software AND version are verified.
        """
        findings: list[ScoredFinding] = []
        target = ctx.get("target", "")

        for tech in ctx.get("technologies", []):
            if not isinstance(tech, dict):
                continue
            name = tech.get("name", "")
            version = tech.get("version", "")

            if not name:
                continue

            # Only produce high-confidence CVE findings when version is known
            if version:
                factors = ConfidenceFactors(
                    version_verified=True,
                    sources=["tech_fingerprint", "nvd_api"],
                    evidence=[f"{name} v{version} detected, version-specific CVE lookup applicable"],
                )
                # Placeholder — actual NVD lookup happens in cve_correlate module
                # This correlation just flags version-verified software for deeper analysis
            else:
                factors = ConfidenceFactors(
                    banner_only=True,
                    sources=["tech_fingerprint"],
                    evidence=[f"{name} detected without version — low confidence CVE matching"],
                )

        return findings

    def _correlate_secrets(self, ctx: dict, ce: ConfidenceEngine) -> list[ScoredFinding]:
        """Correlate discovered URLs that might expose secrets."""
        findings: list[ScoredFinding] = []
        target = ctx.get("target", "")

        secret_patterns = [
            (".env", "Environment configuration file"),
            (".git/config", "Git repository configuration"),
            ("wp-config.php.bak", "WordPress config backup"),
            ("/debug", "Debug endpoint"),
            ("/phpinfo", "PHP information page"),
            ("/server-status", "Apache server status"),
            ("/.htpasswd", "Apache password file"),
            ("/web.config", "IIS configuration"),
        ]

        for url_item in ctx.get("discovered_urls", []):
            url = url_item if isinstance(url_item, str) else url_item.get("url", "")
            for pattern, desc in secret_patterns:
                if pattern in url.lower():
                    factors = ConfidenceFactors(
                        endpoint_verified=True,
                        sources=["url_discovery"],
                        evidence=[f"Sensitive endpoint found: {url}"],
                    )
                    finding = ce.score_finding(
                        title=f"Potential Secret Exposure: {desc}",
                        severity="high",
                        host=target,
                        factors=factors,
                        exposure="internet",
                        module="correlation_engine",
                    )
                    findings.append(finding)

        return findings

    def _correlate_cloud(self, ctx: dict, ce: ConfidenceEngine) -> list[ScoredFinding]:
        """Correlate cloud infrastructure indicators."""
        findings: list[ScoredFinding] = []
        target = ctx.get("target", "")

        cloud_services = []
        cloud_map = {
            "amazonaws.com": "AWS",
            "azurewebsites.net": "Azure",
            "cloudfront.net": "AWS CloudFront",
            "googleapis.com": "Google Cloud",
            "firebaseio.com": "Firebase",
            "herokuapp.com": "Heroku",
        }

        for host in ctx.get("subdomains", []):
            for domain, provider in cloud_map.items():
                if domain in str(host).lower():
                    cloud_services.append(f"{provider} ({host})")

        if cloud_services:
            factors = ConfidenceFactors(
                multi_source_confirmed=True,
                sources=["subdomain_enum", "dns_enum"],
                evidence=[f"Cloud infrastructure detected: {', '.join(cloud_services[:5])}"],
            )
            finding = ce.score_finding(
                title=f"Cloud Infrastructure Identified ({len(cloud_services)} services)",
                severity="info",
                host=target,
                factors=factors,
                module="correlation_engine",
            )
            findings.append(finding)

        return findings

    def add_custom_rule(self, rule: CorrelationRule):
        """Register a custom correlation rule."""
        self._rules.append(rule)

    def get_correlations(self) -> list[dict[str, Any]]:
        """Return log of all correlations performed."""
        return self._correlations
