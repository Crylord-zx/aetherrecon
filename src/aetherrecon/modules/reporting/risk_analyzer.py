"""
Risk Analysis Module v2.0
---------------------------
Aggregates findings, assesses overall target risk,
and generates a prioritized scoring summary with
confidence-backed analysis.
"""

from typing import Any
from aetherrecon.modules.base import BaseModule
from aetherrecon.engines.risk_prioritizer import RiskPrioritizer
from aetherrecon.engines.remediation import RemediationEngine


class RiskAnalyzerModule(BaseModule):
    name = "risk_analyzer"
    category = "reporting"
    description = "Consolidated risk assessment with prioritization and remediation"

    async def run(self, target: str) -> dict[str, Any]:
        # Get all vulnerabilities from the DB for this scan
        vulns = await self.db.get_vulnerabilities(self.scan_id)
        findings = await self.db.get_findings(self.scan_id)

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        score = 0.0

        for v in vulns:
            sev = v.get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1

            # Weighted scoring
            weights = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.0}
            score += weights.get(sev, 0)

        # Normalize score (0-10)
        final_score = min(10.0, score / 5.0) if score > 0 else 0.0

        # Build risk prioritization
        prioritizer = RiskPrioritizer()
        for v in vulns:
            prioritizer.prioritize(
                title=v.get("vuln_name", ""),
                host=v.get("host", target),
                severity=v.get("severity", "info"),
                cvss_score=0.0,
                epss_score=v.get("epss_score", 0.0),
                exploit_maturity=v.get("exploit_maturity", "unknown"),
            )

        # Confidence distribution from findings
        conf_dist = {}
        for f in findings:
            conf = f.get("confidence", "medium")
            conf_dist[conf] = conf_dist.get(conf, 0) + 1

        # Build remediation guidance
        remediation_engine = RemediationEngine()

        result = {
            "target": target,
            "risk_score": final_score,
            "severity_counts": counts,
            "confidence_distribution": conf_dist,
            "total_vulnerabilities": len(vulns),
            "total_findings": len(findings),
            "risk_heatmap": prioritizer.get_risk_heatmap(),
            "executive_summary": prioritizer.get_executive_summary(),
            "status": "critical" if final_score > 7 else "vulnerable" if final_score > 4 else "moderate" if final_score > 2 else "secure",
        }

        await self.add_finding(
            title="Executive Risk Assessment",
            severity="high" if final_score > 7 else "medium" if final_score > 4 else "info",
            description=f"Overall risk score: {final_score:.1f}/10.0 | "
                        f"Vulns: {len(vulns)} | Status: {result['status'].upper()}",
            data=result,
        )

        return result
