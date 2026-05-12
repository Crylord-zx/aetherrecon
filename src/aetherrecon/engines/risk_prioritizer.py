"""
Risk-Based Prioritization Engine
-----------------------------------
Weighted scoring system combining CVSS, EPSS, exposure,
exploit maturity, and internet accessibility for real-world
risk prioritization.

Not all findings matter equally — this engine ensures the report
surfaces what actually matters.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RiskFactor:
    """A single risk factor with its weight and value."""
    name: str
    value: float       # 0.0 - 1.0 normalized
    weight: float      # Importance multiplier
    description: str = ""


@dataclass
class PrioritizedFinding:
    """A finding with full risk prioritization context."""
    title: str
    host: str
    severity: str
    composite_risk_score: float = 0.0
    risk_factors: list[RiskFactor] = field(default_factory=list)
    priority_rank: int = 0
    remediation_priority: str = "low"  # critical | high | medium | low
    business_impact: str = "unknown"
    attack_complexity: str = "unknown"
    auth_required: bool = False
    external_exposure: bool = True
    raw_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "host": self.host,
            "severity": self.severity,
            "composite_risk_score": self.composite_risk_score,
            "priority_rank": self.priority_rank,
            "remediation_priority": self.remediation_priority,
            "business_impact": self.business_impact,
            "attack_complexity": self.attack_complexity,
            "auth_required": self.auth_required,
            "external_exposure": self.external_exposure,
            "risk_factors": [
                {"name": rf.name, "value": rf.value, "weight": rf.weight}
                for rf in self.risk_factors
            ],
        }


class RiskPrioritizer:
    """
    Enterprise risk prioritization engine.

    Scoring formula:
        risk_score = Σ(factor_value × factor_weight) / Σ(weights)

    Factors:
    - CVSS base score (normalized to 0-1)
    - EPSS exploitation probability
    - Exposure (internet vs internal)
    - Exploit maturity
    - Known exploitation (KEV)
    - Attack complexity
    - Authentication requirements
    - Business impact estimation
    """

    def __init__(self):
        self._findings: list[PrioritizedFinding] = []

    def prioritize(
        self,
        title: str,
        host: str,
        severity: str,
        cvss_score: float = 0.0,
        epss_score: float = 0.0,
        exploit_maturity: str = "unknown",
        kev_listed: bool = False,
        external_exposure: bool = True,
        auth_required: bool = False,
        attack_complexity: str = "low",
        business_impact: str = "unknown",
        **kwargs,
    ) -> PrioritizedFinding:
        """Create a risk-prioritized finding with composite scoring."""
        factors = []

        # CVSS normalized (0-10 → 0-1)
        factors.append(RiskFactor(
            name="cvss_base",
            value=min(1.0, cvss_score / 10.0),
            weight=3.0,
            description=f"CVSS Base Score: {cvss_score}",
        ))

        # EPSS exploitation probability
        factors.append(RiskFactor(
            name="epss_probability",
            value=epss_score,
            weight=2.5,
            description=f"EPSS: {epss_score:.2%} exploitation probability",
        ))

        # Exposure factor
        exposure_value = 1.0 if external_exposure else 0.3
        factors.append(RiskFactor(
            name="exposure",
            value=exposure_value,
            weight=2.0,
            description="Internet-exposed" if external_exposure else "Internal only",
        ))

        # Exploit maturity
        maturity_map = {"active": 1.0, "weaponized": 0.8, "poc": 0.5, "none": 0.1, "unknown": 0.3}
        maturity_value = maturity_map.get(exploit_maturity, 0.3)
        factors.append(RiskFactor(
            name="exploit_maturity",
            value=maturity_value,
            weight=2.0,
            description=f"Exploit maturity: {exploit_maturity}",
        ))

        # KEV — known exploitation in wild
        if kev_listed:
            factors.append(RiskFactor(
                name="kev_listed",
                value=1.0,
                weight=3.0,
                description="CISA KEV: Known exploited vulnerability",
            ))

        # Attack complexity (inverse — lower complexity = higher risk)
        complexity_map = {"low": 1.0, "medium": 0.6, "high": 0.3}
        complexity_value = complexity_map.get(attack_complexity, 0.5)
        factors.append(RiskFactor(
            name="attack_complexity",
            value=complexity_value,
            weight=1.5,
            description=f"Attack complexity: {attack_complexity}",
        ))

        # Auth requirements (no auth = higher risk)
        auth_value = 0.3 if auth_required else 1.0
        factors.append(RiskFactor(
            name="auth_requirement",
            value=auth_value,
            weight=1.0,
            description="Authentication required" if auth_required else "No authentication required",
        ))

        # Compute composite score
        total_weighted = sum(f.value * f.weight for f in factors)
        total_weights = sum(f.weight for f in factors)
        composite = round((total_weighted / total_weights) * 10, 2) if total_weights > 0 else 0.0
        composite = min(10.0, composite)

        # Determine remediation priority
        if composite >= 8.0:
            rem_priority = "critical"
        elif composite >= 6.0:
            rem_priority = "high"
        elif composite >= 3.5:
            rem_priority = "medium"
        else:
            rem_priority = "low"

        finding = PrioritizedFinding(
            title=title,
            host=host,
            severity=severity,
            composite_risk_score=composite,
            risk_factors=factors,
            remediation_priority=rem_priority,
            business_impact=business_impact,
            attack_complexity=attack_complexity,
            auth_required=auth_required,
            external_exposure=external_exposure,
            raw_data=kwargs,
        )

        self._findings.append(finding)
        return finding

    def rank_findings(self) -> list[PrioritizedFinding]:
        """Sort and rank all findings by composite risk score."""
        sorted_findings = sorted(self._findings, key=lambda f: f.composite_risk_score, reverse=True)
        for i, finding in enumerate(sorted_findings, 1):
            finding.priority_rank = i
        return sorted_findings

    def get_risk_heatmap(self) -> dict[str, Any]:
        """Generate data for a risk heatmap visualization."""
        if not self._findings:
            return {"total": 0, "buckets": {}}

        buckets = {
            "critical": [],  # 8.0+
            "high": [],      # 6.0-7.9
            "medium": [],    # 3.5-5.9
            "low": [],       # 0-3.4
        }

        for f in self._findings:
            if f.composite_risk_score >= 8.0:
                buckets["critical"].append(f.title)
            elif f.composite_risk_score >= 6.0:
                buckets["high"].append(f.title)
            elif f.composite_risk_score >= 3.5:
                buckets["medium"].append(f.title)
            else:
                buckets["low"].append(f.title)

        return {
            "total": len(self._findings),
            "average_score": round(
                sum(f.composite_risk_score for f in self._findings) / len(self._findings), 2
            ),
            "buckets": {k: {"count": len(v), "items": v[:10]} for k, v in buckets.items()},
        }

    def get_executive_summary(self) -> dict[str, Any]:
        """Generate an executive-level risk summary."""
        ranked = self.rank_findings()
        return {
            "total_findings": len(ranked),
            "critical_count": sum(1 for f in ranked if f.remediation_priority == "critical"),
            "high_count": sum(1 for f in ranked if f.remediation_priority == "high"),
            "medium_count": sum(1 for f in ranked if f.remediation_priority == "medium"),
            "low_count": sum(1 for f in ranked if f.remediation_priority == "low"),
            "top_risks": [f.to_dict() for f in ranked[:10]],
            "heatmap": self.get_risk_heatmap(),
        }
