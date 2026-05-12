"""
Arjun Module — Hidden Parameter Discovery
"""

from __future__ import annotations
import asyncio
import json
import os
from typing import Any
from aetherrecon.modules.base import BaseModule


class ArjunModule(BaseModule):
    name = "arjun"
    category = "active"
    description = "Hidden parameter discovery using Arjun"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        tool_path = self.plugin_manager.get_tool_path("arjun") or "arjun"

        # Look for endpoints to test parameters on
        endpoints = []
        for url_item in self.context.get("discovered_urls", []):
            url = url_item if isinstance(url_item, str) else url_item.get("url", "")
            if "?" not in url and url.endswith((".php", ".asp", ".jsp")):
                endpoints.append(url)
                
        if not endpoints:
            for svc in self.context.get("http_services", []):
                if isinstance(svc, dict) and svc.get("url"):
                    endpoints.append(svc["url"])
        if not endpoints:
            endpoints = [f"https://{target}/"]

        for url in endpoints[:3]:
            await self.rate_limiter.acquire()
            try:
                output_file = f"arjun_out.json"
                cmd = [tool_path, "-u", url, "-oJ", output_file]
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=300)
                
                if os.path.exists(output_file):
                    with open(output_file, "r") as f:
                        try:
                            data = json.load(f)
                            for ep, params in data.items():
                                if params:
                                    finding = {
                                        "url": ep,
                                        "parameters": params,
                                        "source": "arjun"
                                    }
                                    results.append(finding)
                                    # Add to context for Dalfox/SQLMap
                                    param_url = f"{ep}?{'=1&'.join(params)}=1"
                                    self.context.setdefault("discovered_urls", []).append(param_url)
                        except json.JSONDecodeError:
                            pass
                    os.remove(output_file)
            except (FileNotFoundError, asyncio.TimeoutError, OSError):
                if os.path.exists("arjun_out.json"):
                    os.remove("arjun_out.json")
                continue

        return results
