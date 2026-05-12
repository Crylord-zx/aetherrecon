"""
Feroxbuster Module
------------------
Fast, simple, recursive content discovery.
"""

import asyncio
from typing import Any
from aetherrecon.modules.base import BaseModule

class FeroxbusterModule(BaseModule):
    name = "feroxbuster"
    category = "active"
    description = "Content discovery and directory brute-forcing"

    async def run(self, target: str) -> list[dict[str, Any]]:
        if not self.plugin_manager.is_available("feroxbuster"):
            return []

        # Find a primary URL to fuzz
        fuzz_url = f"https://{target}"
        assets = await self.db.get_assets(self.scan_id)
        for a in assets:
            if a.get("asset_type") == "http_service":
                fuzz_url = a.get("value")
                break

        try:
            # feroxbuster -u url --depth 1 -q
            args = ["-u", fuzz_url, "--depth", "1", "-q", "--time-limit", "3m"]
            
            await self.rate_limiter.acquire()
            stdout = await self.plugin_manager.run_tool("feroxbuster", args, timeout=200)
            
            if stdout.strip():
                results = []
                for line in stdout.splitlines():
                    line = line.strip()
                    if line.startswith("http"):
                        results.append({"url": line, "source": "feroxbuster"})
                
                if results:
                    await self.add_finding(
                        title=f"Feroxbuster Results: {fuzz_url}",
                        severity="medium",
                        description=f"Hidden directories or files were discovered ({len(results)} items).",
                        data={"raw": stdout}
                    )
                return results
        except asyncio.TimeoutError:
            await self.add_finding("Timeout", "warning", "feroxbuster hit the 3 minute limit.")
        except Exception:
            pass

        return []
