"""
WHOIS Lookup Module
-------------------
Queries WHOIS data for a domain to gather registrant info, nameservers, dates.
Uses the python-whois library for parsing.
"""

import asyncio
from typing import Any

import whois

from aetherrecon.modules.base import BaseModule


class WhoisModule(BaseModule):
    name = "whois"
    category = "passive"
    description = "WHOIS domain registration lookup"

    async def run(self, target: str) -> dict[str, Any]:
        await self.rate_limiter.acquire()

        # Run the blocking whois call in a thread executor
        loop = asyncio.get_event_loop()
        try:
            w = await loop.run_in_executor(None, whois.whois, target)
        except Exception as e:
            await self.add_finding(
                title=f"WHOIS lookup failed for {target}",
                severity="info",
                description=str(e),
            )
            return {"error": str(e)}

        # Extract key fields
        result = {
            "domain": target,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "updated_date": str(w.updated_date),
            "name_servers": list(w.name_servers) if w.name_servers else [],
            "status": w.status if isinstance(w.status, list) else [w.status] if w.status else [],
            "registrant": w.get("org", w.get("name", "")),
            "country": w.get("country", ""),
            "emails": list(w.emails) if w.emails else [],
            "dnssec": w.get("dnssec", ""),
        }

        await self.add_finding(
            title=f"WHOIS data for {target}",
            severity="info",
            description=f"Registrar: {result['registrar']}",
            data=result,
        )

        # Store nameservers as assets
        for ns in result["name_servers"]:
            await self.add_asset("nameserver", ns)

        return result
