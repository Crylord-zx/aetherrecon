"""
Wayback Machine Module
-----------------------
Collects historical URLs from the Wayback Machine CDX API.
Useful for discovering forgotten endpoints, old parameters, etc.
"""

import asyncio
from typing import Any
from urllib.parse import urlparse

import aiohttp

from aetherrecon.modules.base import BaseModule

WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"


class WaybackModule(BaseModule):
    name = "wayback"
    category = "passive"
    description = "Wayback Machine URL collection"

    async def run(self, target: str) -> list[dict[str, Any]]:
        # ── High-Performance Tool Fallback ──────────────────────────────────
        plugin_mgr = self.plugin_manager
        tool_to_use = "gau" if plugin_mgr.is_available("gau") else \
                      "waybackurls" if plugin_mgr.is_available("waybackurls") else None

        if tool_to_use:
            try:
                await self.rate_limiter.acquire()
                stdout = await plugin_mgr.run_tool(tool_to_use, [target], timeout=120)
                urls = [u.strip() for u in stdout.splitlines() if u.strip()]
                
                results = [{"url": u, "source": tool_to_use} for u in urls[:500]]
                await self.add_finding(
                    title=f"Discovered {len(results)} URLs via {tool_to_use}",
                    severity="info",
                    description=f"Using {tool_to_use} for historical URL discovery.",
                    data={"count": len(results)}
                )
                return results
            except Exception as e:
                self.console.print(f"[dim]Note: {tool_to_use} failed, falling back to direct CDX: {e}[/dim]")

        # ── Native CDX Fallback ──────────────────────────────────────────────
        await self.rate_limiter.acquire()
        params = {
            "url": f"*.{target}/*",
            "output": "json",
            "fl": "timestamp,original,statuscode,mimetype",
            "collapse": "urlkey",
            "limit": "500",
        }

        results: list[dict[str, Any]] = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    WAYBACK_CDX_URL, params=params,
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as resp:
                    if resp.status != 200:
                        return []
                    data = await resp.json(content_type=None)

            if not data or len(data) < 2:
                return []

            # First row is headers
            headers = data[0]
            for row in data[1:]:
                entry = dict(zip(headers, row))
                url = entry.get("original", "")
                results.append({
                    "url": url,
                    "timestamp": entry.get("timestamp", ""),
                    "status_code": entry.get("statuscode", ""),
                    "mime_type": entry.get("mimetype", ""),
                })
        except Exception as e:
            await self.add_finding(
                title=f"Wayback query failed for {target}",
                severity="info", description=str(e),
            )
            return []

        # Deduplicate by URL path
        unique_paths: set[str] = set()
        deduped: list[dict] = []
        for r in results:
            parsed = urlparse(r["url"])
            if parsed.path not in unique_paths:
                unique_paths.add(parsed.path)
                deduped.append(r)

        await self.add_finding(
            title=f"Wayback URLs for {target}",
            severity="info",
            description=f"Found {len(deduped)} unique historical URL paths",
            data={"count": len(deduped)},
        )

        return deduped
