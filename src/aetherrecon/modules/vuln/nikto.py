"""
Nikto Module — Web Server Scanner
"""

from __future__ import annotations
import asyncio
import os
import json
from typing import Any
from aetherrecon.modules.base import BaseModule


class NiktoModule(BaseModule):
    name = "nikto"
    category = "vuln"
    description = "Web server scanner for multiple vulnerabilities using Nikto"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        tool_path = self.config.data.get("tools", {}).get("nikto", "") or "nikto"

        base_urls = []
        for svc in self.context.get("http_services", []):
            if isinstance(svc, dict) and svc.get("url"):
                base_urls.append(svc["url"])
        if not base_urls:
            base_urls = [f"https://{target}"]

        for url in base_urls[:2]:
            await self.rate_limiter.acquire()
            try:
                output_file = f"nikto_{target}.json"
                cmd = [tool_path, "-h", url, "-Format", "json", "-o", output_file]
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=600)
                
                if os.path.exists(output_file):
                    with open(output_file, "r") as f:
                        try:
                            data = json.load(f)
                            for vuln in data.get("vulnerabilities", []):
                                finding = {
                                    "url": url,
                                    "issue": vuln.get("msg", ""),
                                    "method": vuln.get("method", ""),
                                    "url_path": vuln.get("url", "")
                                }
                                results.append(finding)
                                await self.add_vulnerability(
                                    host=target, name="Nikto Finding",
                                    severity="medium", desc=finding["issue"]
                                )
                        except json.JSONDecodeError:
                            pass
                    os.remove(output_file)
            except (FileNotFoundError, asyncio.TimeoutError, OSError):
                if os.path.exists(f"nikto_{target}.json"):
                    os.remove(f"nikto_{target}.json")
                continue

        return results
