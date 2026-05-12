"""
Exposure Context Engine
-------------------------
Not every exposed service is dangerous. This engine adds context
to determine actual risk based on exposure level.

if service_exposed_to_internet → increase_risk()
if internal_only → lower_priority()
if admin_panel_public → raise_attention()
"""

from __future__ import annotations
from typing import Any


class ExposureContextEngine:
    """Classifies findings by exposure context to reduce useless alerts."""

    def __init__(self):
        self._classifications: list[dict[str, Any]] = []

    def classify(self, finding: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        """Add exposure context to a finding."""
        host = finding.get("host", "")
        url = finding.get("url", "")
        port = finding.get("port", 0)

        exposure = self._determine_exposure(host, port, context)
        attention_level = self._determine_attention(finding, exposure)

        finding["exposure_context"] = {
            "level": exposure,
            "attention": attention_level,
            "risk_modifier": self._get_risk_modifier(exposure, attention_level),
        }

        self._classifications.append({
            "finding": finding.get("title", ""),
            "exposure": exposure,
            "attention": attention_level,
        })
        return finding

    def _determine_exposure(self, host: str, port: int,
                            context: dict[str, Any]) -> str:
        """Determine if a service is internet-exposed or internal."""
        # Internal indicators
        internal_patterns = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
                             "172.20.", "172.21.", "172.22.", "172.23.",
                             "172.24.", "172.25.", "172.26.", "172.27.",
                             "172.28.", "172.29.", "172.30.", "172.31.",
                             "192.168.", "127.", "localhost", "::1"]
        if any(host.startswith(p) or p in host for p in internal_patterns):
            return "internal"

        # Cloud/CDN protected
        waf_detected = bool(context.get("waf_detected", []))
        if waf_detected:
            return "protected"

        return "internet"

    def _determine_attention(self, finding: dict[str, Any], exposure: str) -> str:
        """Determine attention level based on finding + exposure."""
        severity = finding.get("severity", "info").lower()
        finding_type = finding.get("type", "")

        # Admin panels on internet = highest attention
        if exposure == "internet" and finding_type in ("admin_panel", "auth_portal"):
            return "critical"

        # Database on internet = critical
        if exposure == "internet" and finding_type == "database_exposed":
            return "critical"

        # High severity + internet exposed
        if exposure == "internet" and severity in ("critical", "high"):
            return "high"

        # Internal services are lower priority
        if exposure == "internal":
            return "low"

        return "medium"

    @staticmethod
    def _get_risk_modifier(exposure: str, attention: str) -> float:
        """Get risk score modifier based on exposure context."""
        modifiers = {
            ("internet", "critical"): 1.5,
            ("internet", "high"): 1.3,
            ("internet", "medium"): 1.0,
            ("protected", "critical"): 1.2,
            ("protected", "high"): 1.0,
            ("protected", "medium"): 0.8,
            ("internal", "high"): 0.6,
            ("internal", "medium"): 0.4,
            ("internal", "low"): 0.2,
        }
        return modifiers.get((exposure, attention), 1.0)

    def get_summary(self) -> dict[str, Any]:
        exposure_counts: dict[str, int] = {}
        attention_counts: dict[str, int] = {}
        for c in self._classifications:
            e = c["exposure"]
            a = c["attention"]
            exposure_counts[e] = exposure_counts.get(e, 0) + 1
            attention_counts[a] = attention_counts.get(a, 0) + 1
        return {
            "total_classified": len(self._classifications),
            "by_exposure": exposure_counts,
            "by_attention": attention_counts,
        }
