"""
Confidence Scoring System
--------------------------
Every finding gets a confidence label: Confirmed | High | Medium | Low
Multi-factor scoring based on version match, endpoint verification,
response behavior, exploit maturity, and multi-source confirmation.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ConfidenceLevel(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def numeric(self) -> float:
        return {
            ConfidenceLevel.CONFIRMED: 1.0,
            ConfidenceLevel.HIGH: 0.8,
            ConfidenceLevel.MEDIUM: 0.5,
            ConfidenceLevel.LOW: 0.2,
        }[self]


@dataclass
class ConfidenceFactors:
    """Factors that contribute to the confidence score of a finding."""
    version_verified: bool = False
    endpoint_verified: bool = False
    response_validated: bool = False
    multi_source_confirmed: bool = False
    exploit_exists: bool = False
    actively_exploited: bool = False
    banner_only: bool = False
    epss_score: float = 0.0
    kev_listed: bool = False
    sources: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def compute_confidence(self) -> ConfidenceLevel:
        """Calculate confidence level from weighted factors."""
        score = 0.0

        # Positive factors
        if self.version_verified:
            score += 0.30
        if self.endpoint_verified:
            score += 0.20
        if self.response_validated:
            score += 0.15
        if self.multi_source_confirmed:
            score += 0.15
        if self.exploit_exists:
            score += 0.10
        if self.actively_exploited:
            score += 0.10
        if self.kev_listed:
            score += 0.10
        if self.epss_score > 0.5:
            score += 0.05
        if len(self.sources) >= 3:
            score += 0.05

        # Negative factors — banner-only detection is unreliable
        if self.banner_only and not self.version_verified:
            score *= 0.4

        if score >= 0.85:
            return ConfidenceLevel.CONFIRMED
        elif score >= 0.55:
            return ConfidenceLevel.HIGH
        elif score >= 0.30:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW


@dataclass
class ScoredFinding:
    """A vulnerability finding with full confidence and risk scoring."""
    title: str
    severity: str
    host: str
    confidence: ConfidenceLevel
    confidence_factors: ConfidenceFactors
    risk_score: float = 0.0
    cvss_score: float = 0.0
    epss_score: float = 0.0
    exploit_maturity: str = "unknown"     # none | poc | weaponized | active
    exposure: str = "unknown"             # internet | internal | restricted
    remediation: str = ""
    evidence: list[str] = field(default_factory=list)
    false_positive_notes: str = ""
    cve_id: str = ""
    module: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)

    def compute_risk_score(self) -> float:
        """
        Weighted risk score combining multiple intelligence factors.
        Score range: 0.0 — 10.0
        """
        severity_weights = {
            "critical": 10.0, "high": 7.5, "medium": 5.0,
            "low": 2.0, "info": 0.5,
        }
        base = severity_weights.get(self.severity.lower(), 1.0)

        # Factor in CVSS if available
        if self.cvss_score > 0:
            base = (base + self.cvss_score) / 2.0

        # EPSS multiplier (probability of exploitation)
        epss_factor = 1.0 + (self.epss_score * 0.5)

        # Exploit maturity multiplier
        maturity_map = {"active": 1.5, "weaponized": 1.3, "poc": 1.1, "none": 0.8, "unknown": 1.0}
        maturity_factor = maturity_map.get(self.exploit_maturity, 1.0)

        # Exposure multiplier
        exposure_map = {"internet": 1.4, "internal": 0.7, "restricted": 0.5, "unknown": 1.0}
        exposure_factor = exposure_map.get(self.exposure, 1.0)

        # Confidence multiplier — low confidence reduces score
        conf_factor = self.confidence.numeric

        raw_score = base * epss_factor * maturity_factor * exposure_factor * conf_factor
        self.risk_score = min(10.0, round(raw_score, 2))
        return self.risk_score

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "host": self.host,
            "confidence": self.confidence.value,
            "risk_score": self.risk_score,
            "cvss_score": self.cvss_score,
            "epss_score": self.epss_score,
            "exploit_maturity": self.exploit_maturity,
            "exposure": self.exposure,
            "cve_id": self.cve_id,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "false_positive_notes": self.false_positive_notes,
            "module": self.module,
        }


class ConfidenceEngine:
    """
    Central engine for computing and managing confidence scores
    across all findings in a scan.
    """

    def __init__(self):
        self._findings: list[ScoredFinding] = []

    def score_finding(
        self,
        title: str,
        severity: str,
        host: str,
        factors: ConfidenceFactors,
        **kwargs,
    ) -> ScoredFinding:
        """Create a scored finding with computed confidence and risk."""
        confidence = factors.compute_confidence()
        finding = ScoredFinding(
            title=title,
            severity=severity,
            host=host,
            confidence=confidence,
            confidence_factors=factors,
            evidence=factors.evidence.copy(),
            **kwargs,
        )
        finding.compute_risk_score()
        self._findings.append(finding)
        return finding

    def get_findings(self, min_confidence: ConfidenceLevel | None = None) -> list[ScoredFinding]:
        """Retrieve findings, optionally filtered by minimum confidence."""
        if min_confidence is None:
            return self._findings
        threshold = min_confidence.numeric
        return [f for f in self._findings if f.confidence.numeric >= threshold]

    def get_risk_summary(self) -> dict[str, Any]:
        """Generate a risk summary across all scored findings."""
        if not self._findings:
            return {"total": 0, "avg_risk": 0.0, "max_risk": 0.0}

        scores = [f.risk_score for f in self._findings]
        conf_dist = {}
        for f in self._findings:
            conf_dist[f.confidence.value] = conf_dist.get(f.confidence.value, 0) + 1

        return {
            "total": len(self._findings),
            "avg_risk": round(sum(scores) / len(scores), 2),
            "max_risk": max(scores),
            "confidence_distribution": conf_dist,
            "severity_breakdown": self._severity_breakdown(),
        }

    def _severity_breakdown(self) -> dict[str, int]:
        breakdown: dict[str, int] = {}
        for f in self._findings:
            sev = f.severity.lower()
            breakdown[sev] = breakdown.get(sev, 0) + 1
        return breakdown
