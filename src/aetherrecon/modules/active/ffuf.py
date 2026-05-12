"""
FFUF Module — Fast Web Fuzzing
"""

from __future__ import annotations
import asyncio
import json
import os
from typing import Any
from aetherrecon.modules.base import BaseModule


class FfufModule(BaseModule):
    name = "ffuf"
    category = "active"
    description = "Fast web fuzzing using ffuf"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        tool_path = self.config.data.get("tools", {}).get("ffuf", "") or "ffuf"
        
        # Determine target URL
        base_urls = []
        for svc in self.context.get("http_services", []):
            if isinstance(svc, dict) and svc.get("url"):
                base_urls.append(svc["url"])
        if not base_urls:
            base_urls = [f"https://{target}", f"http://{target}"]

        # Basic wordlist (assume present or skip)
        wordlist = self.config.data.get("wordlists", {}).get("default_dirs", "wordlist.txt")
        if not os.path.exists(wordlist):
            return results

        for base_url in base_urls[:2]:
            await self.rate_limiter.acquire()
            try:
                cmd = [
                    tool_path, "-w", wordlist,
                    "-u", f"{base_url}/FUZZ",
                    "-mc", "200,204,301,302,307,401,403",
                    "-o", "ffuf_out.json", "-of", "json", "-s"
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=300)
                
                if os.path.exists("ffuf_out.json"):
                    with open("ffuf_out.json", "r") as f:
                        data = json.load(f)
                        for res in data.get("results", []):
                            url = res.get("url")
                            status = res.get("status")
                            if url:
                                result = {
                                    "url": url,
                                    "status": status,
                                    "content_type": res.get("content-type", ""),
                                    "content_length": res.get("length", 0)
                                }
                                results.append(result)
                                self.context.setdefault("discovered_urls", []).append(url)
                    os.remove("ffuf_out.json")
            except (FileNotFoundError, asyncio.TimeoutError, OSError):
                if os.path.exists("ffuf_out.json"):
                    os.remove("ffuf_out.json")
                continue

        return results
