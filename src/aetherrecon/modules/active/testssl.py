"""
TestSSL Module — Deep TLS Inspection
"""

from __future__ import annotations
import asyncio
import json
import os
from typing import Any
from aetherrecon.modules.base import BaseModule


class TestsslModule(BaseModule):
    name = "testssl"
    category = "active"
    description = "Deep TLS inspection using testssl.sh"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        tool_path = self.plugin_manager.get_tool_path("testssl") or "testssl.sh"

        base_urls = []
        for svc in self.context.get("http_services", []):
            if isinstance(svc, dict) and str(svc.get("port")) == "443":
                base_urls.append(svc.get("url"))
        if not base_urls:
            base_urls = [f"https://{target}"]

        for url in base_urls[:2]:
            await self.rate_limiter.acquire()
            try:
                cmd = [
                    tool_path, "--quiet", "--jsonfile-pretty", "testssl_out.json", url
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=300)
                
                if os.path.exists("testssl_out.json"):
                    with open("testssl_out.json", "r") as f:
                        data = json.load(f)
                        for item in data:
                            if isinstance(item, dict) and item.get("severity") in ("HIGH", "CRITICAL"):
                                finding = {
                                    "url": url,
                                    "finding": item.get("id"),
                                    "severity": item.get("severity").lower(),
                                    "cve": item.get("cve", "")
                                }
                                results.append(finding)
                                await self.add_vulnerability(
                                    host=target, name=f"TLS Issue: {item.get('id')}",
                                    severity=finding["severity"], cve=finding["cve"],
                                    desc=item.get("finding", "")
                                )
                    os.remove("testssl_out.json")
            except (FileNotFoundError, asyncio.TimeoutError, OSError):
                if os.path.exists("testssl_out.json"):
                    os.remove("testssl_out.json")
                continue

        return results
