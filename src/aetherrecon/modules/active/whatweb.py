"""
WhatWeb Module
--------------
Next-generation web scanner to identify technologies.
"""

import asyncio
from typing import Any
from aetherrecon.modules.base import BaseModule

class WhatWebModule(BaseModule):
    name = "whatweb"
    category = "active"
    description = "Technology fingerprinting using WhatWeb"

    async def run(self, target: str) -> list[dict[str, Any]]:
        if not self.plugin_manager.is_available("whatweb"):
            return []

        urls = []
        for asset in await self.db.get_assets(self.scan_id):
            if asset.get("asset_type") == "http_service":
                urls.append(asset.get("value"))
        if not urls:
            urls = [f"http://{target}", f"https://{target}"]

        results = []
        sem = asyncio.Semaphore(10)

        async def run_whatweb(url):
            async with sem:
                try:
                    await self.rate_limiter.acquire()
                    stdout = await self.plugin_manager.run_tool("whatweb", ["-a", "1", "--color=never", url], timeout=60)
                    
                    if stdout.strip():
                        # Save to database
                        await self.add_finding(
                            title=f"WhatWeb Fingerprint: {url}",
                            severity="info",
                            description=stdout.strip()[:200],
                            data={"raw": stdout}
                        )
                        await self.add_technology(url, "Web Fingerprint", stdout.strip()[:100])
                        results.append({"url": url, "fingerprint": stdout.strip()})
                except Exception:
                    pass

        tasks = [run_whatweb(u) for u in urls[:20]]
        await asyncio.gather(*tasks)

        return results
