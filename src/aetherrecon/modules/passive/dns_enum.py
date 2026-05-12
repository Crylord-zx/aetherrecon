"""
DNS Enumeration Module
----------------------
Performs comprehensive DNS record enumeration using dnspython.
Queries A, AAAA, MX, NS, TXT, SOA, CNAME, SRV, CAA records.
"""

import asyncio
from typing import Any

import dns.resolver
import dns.asyncresolver

from aetherrecon.modules.base import BaseModule

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"]


class DNSEnumModule(BaseModule):
    name = "dns_enum"
    category = "passive"
    description = "DNS record enumeration"

    async def run(self, target: str) -> dict[str, Any]:
        results: dict[str, list] = {}
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        for rtype in RECORD_TYPES:
            await self.rate_limiter.acquire()
            try:
                answers = await resolver.resolve(target, rtype)
                records = []
                for rdata in answers:
                    record_str = rdata.to_text()
                    records.append(record_str)

                    # Store IPs as assets
                    if rtype in ("A", "AAAA"):
                        await self.add_asset("ip", record_str, {"record_type": rtype})
                    elif rtype == "MX":
                        await self.add_asset("mail_server", record_str)
                    elif rtype == "NS":
                        await self.add_asset("nameserver", record_str)

                if records:
                    results[rtype] = records

            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except dns.resolver.NoNameservers:
                continue
            except Exception:
                continue

        await self.add_finding(
            title=f"DNS records for {target}",
            severity="info",
            description=f"Found {sum(len(v) for v in results.values())} records across {len(results)} types",
            data=results,
        )

        return results
