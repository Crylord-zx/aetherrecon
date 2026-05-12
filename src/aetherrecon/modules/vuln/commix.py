"""
Commix Module — Command Injection Testing
"""

from __future__ import annotations
import asyncio
from typing import Any
from aetherrecon.modules.base import BaseModule


class CommixModule(BaseModule):
    name = "commix"
    category = "vuln"
    description = "Command injection testing using Commix"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        urls_with_params = []
        for url_item in self.context.get("discovered_urls", []):
            url = url_item if isinstance(url_item, str) else url_item.get("url", "")
            if "?" in url:
                urls_with_params.append(url)

        if not urls_with_params:
            return results

        for url in urls_with_params[:5]:
            await self.rate_limiter.acquire()
            try:
                cmd = ["commix", "--url", url, "--batch", "--level=1"]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                output = stdout.decode(errors="ignore")
                if "injectable" in output.lower() or "vulnerable" in output.lower():
                    results.append({
                        "url": url, "type": "command_injection",
                        "severity": "critical",
                    })
                    await self.add_vulnerability(
                        host=target, name="Command Injection",
                        severity="critical",
                        desc=f"Command injection at {url}",
                    )
            except (FileNotFoundError, asyncio.TimeoutError, OSError):
                continue
        return results
