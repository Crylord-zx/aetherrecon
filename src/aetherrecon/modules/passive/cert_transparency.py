"""
Certificate Transparency Module
--------------------------------
Queries crt.sh (a public CT log aggregator) to discover subdomains
from SSL certificate transparency logs.
"""

import asyncio
from typing import Any

import aiohttp

from aetherrecon.modules.base import BaseModule

CRT_SH_URL = "https://crt.sh/?q=%.{domain}&output=json"


class CertTransparencyModule(BaseModule):
    name = "cert_transparency"
    category = "passive"
    description = "Certificate Transparency log subdomain discovery"

    async def run(self, target: str) -> list[dict[str, Any]]:
        await self.rate_limiter.acquire()

        url = CRT_SH_URL.format(domain=target)
        found_domains: set[str] = set()
        results: list[dict[str, Any]] = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json(content_type=None)

            for entry in data:
                name = entry.get("name_value", "")
                # crt.sh can return multiple domains separated by newlines
                for domain in name.split("\n"):
                    domain = domain.strip().lower()
                    # Remove wildcard prefix
                    if domain.startswith("*."):
                        domain = domain[2:]
                    if domain and domain.endswith(f".{target}") or domain == target:
                        if domain not in found_domains:
                            found_domains.add(domain)
                            record = {
                                "domain": domain,
                                "issuer": entry.get("issuer_name", ""),
                                "not_before": entry.get("not_before", ""),
                                "not_after": entry.get("not_after", ""),
                            }
                            results.append(record)
                            await self.add_subdomain(domain, None, "crt.sh")

        except Exception as e:
            await self.add_finding(
                title=f"CT log query failed for {target}",
                severity="info", description=str(e),
            )
            return []

        await self.add_finding(
            title=f"CT log subdomains for {target}",
            severity="info",
            description=f"Found {len(results)} unique domains from certificate transparency logs",
            data={"count": len(results), "domains": list(found_domains)},
        )

        return results
