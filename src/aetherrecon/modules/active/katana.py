"""
Katana Crawler Module
----------------------
Next-generation web crawling and endpoint discovery.
Replaces traditional spiders with a faster, headless-capable engine.
"""

import asyncio
from typing import Any
from aetherrecon.modules.base import BaseModule

class KatanaModule(BaseModule):
    name = "katana"
    category = "active"
    description = "Next-gen web crawling and endpoint discovery"

    async def run(self, target: str) -> list[dict[str, Any]]:
        if not self.plugin_manager.is_available("katana"):
            return []

        # Start with the primary target
        fuzz_urls = [f"https://{target}", f"http://{target}"]
        
        # Add a few high-value subdomains if found
        for sd in self.context.get("subdomains", [])[:5]:
            fuzz_urls.append(f"https://{sd}")

        results = []
        
        for url in fuzz_urls:
            try:
                # katana -u url -silent -jc (js crawling) -kf (known files)
                args = ["-u", url, "-silent", "-jc", "-kf", "-timeout", "5"]
                
                await self.rate_limiter.acquire()
                stdout = await self.plugin_manager.run_tool("katana", args, timeout=120)
                
                if stdout:
                    lines = stdout.splitlines()
                    for line in lines[:50]: # Limit report size
                        results.append({"url": url, "discovered": line, "source": "katana"})
            except Exception:
                pass

            # 2. Hakrawler
            if self.plugin_manager.is_available("hakrawler"):
                try:
                    self.console.print(f"[dim]Running hakrawler on {url}...[/dim]")
                    stdout = await self.plugin_manager.run_tool("hakrawler", ["-url", url, "-plain"], timeout=60)
                    for line in stdout.splitlines():
                        results.append({"url": url, "discovered": line, "source": "hakrawler"})
                except Exception: pass

        if results:
            await self.add_finding(
                title=f"Endpoint Discovery Results",
                severity="info",
                description=f"Discovered {len(results)} total endpoints via Katana/Hakrawler.",
                data={"total": len(results)}
            )

        return results
