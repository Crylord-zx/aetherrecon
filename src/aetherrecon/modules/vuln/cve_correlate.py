"""
CVE Correlation Module
-----------------------
Correlates discovered technologies and versions with known CVEs
using public APIs (NIST NVD, cvedetails).
"""

import asyncio
import re
from typing import Any

import aiohttp

from aetherrecon.modules.base import BaseModule

# NIST NVD API for CVE lookups (public, rate-limited)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CVECorrelateModule(BaseModule):
    name = "cve_correlate"
    category = "vuln"
    description = "CVE correlation for discovered technologies"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Gather technologies from context
        techs = self.context.get("technologies", [])
        banners = []
        for port_info in self.context.get("open_ports", []):
            if isinstance(port_info, dict) and port_info.get("banner"):
                banners.append(port_info)

        # Extract software names and versions from banners
        software_list = self._extract_software(techs, banners)

        if not software_list:
            await self.add_finding(
                title="CVE correlation skipped",
                severity="info",
                description="No versioned software detected to correlate",
            )
            return results

        for sw in software_list[:10]:  # Limit API calls
            await self.rate_limiter.acquire()
            cves = await self._query_nvd(sw["name"], sw.get("version", ""))
            if cves:
                for cve in cves:
                    finding = {
                        "software": sw["name"],
                        "version": sw.get("version", "unknown"),
                        "cve_id": cve.get("id", ""),
                        "description": cve.get("description", ""),
                        "severity": cve.get("severity", "unknown"),
                        "cvss_score": cve.get("cvss_score", 0),
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
                    }
                    results.append(finding)
                    await self.add_finding(
                        title=f"{cve.get('id', 'CVE')} — {sw['name']}",
                        severity=self._map_severity(cve.get("cvss_score", 0)),
                        description=cve.get("description", "")[:300],
                        data=finding,
                    )

        return results

    def _extract_software(self, techs: list, banners: list) -> list[dict]:
        """Extract software names and versions from fingerprint/banner data."""
        software = []

        for tech in techs:
            if isinstance(tech, dict):
                software.append({"name": tech.get("name", ""), "version": ""})

        # Try to extract version from banners
        version_pattern = re.compile(r"([\w.-]+)[/ ]([\d]+\.[\d]+[\d.]*)")
        for banner_info in banners:
            banner = banner_info.get("banner", "")
            matches = version_pattern.findall(banner)
            for name, ver in matches:
                software.append({"name": name, "version": ver})

        # Deduplicate
        seen = set()
        unique = []
        for sw in software:
            key = f"{sw['name']}:{sw.get('version', '')}"
            if key not in seen and sw["name"]:
                seen.add(key)
                unique.append(sw)

        return unique

    async def _query_nvd(self, product: str, version: str = "") -> list[dict]:
        """Query the NIST NVD API for CVEs matching a product."""
        params = {
            "keywordSearch": product,
            "resultsPerPage": "5",
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    NVD_API_URL, params=params,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json()

            vulnerabilities = data.get("vulnerabilities", [])
            cves = []
            for vuln in vulnerabilities:
                cve_data = vuln.get("cve", {})
                desc_list = cve_data.get("descriptions", [])
                desc = ""
                for d in desc_list:
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break

                # Get CVSS score
                metrics = cve_data.get("metrics", {})
                cvss_score = 0
                severity = "unknown"
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics:
                        metric_list = metrics[key]
                        if metric_list:
                            cvss_data = metric_list[0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore", 0)
                            severity = cvss_data.get("baseSeverity", "unknown")
                            break

                cves.append({
                    "id": cve_data.get("id", ""),
                    "description": desc,
                    "cvss_score": cvss_score,
                    "severity": severity,
                })

            return cves

        except (aiohttp.ClientError, asyncio.TimeoutError, Exception):
            return []

    def _map_severity(self, cvss_score: float) -> str:
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        elif cvss_score > 0:
            return "low"
        return "info"
