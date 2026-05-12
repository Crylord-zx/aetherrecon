"""
Dalfox Module — XSS Detection
"""

from __future__ import annotations
import asyncio
import json
from typing import Any

from aetherrecon.modules.base import BaseModule


class DalfoxModule(BaseModule):
    name = "dalfox"
    category = "vuln"
    description = "XSS detection using Dalfox"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        # Gather parameterized URLs from context
        urls_with_params = []
        for url_item in self.context.get("discovered_urls", []):
            url = url_item if isinstance(url_item, str) else url_item.get("url", "")
            if "?" in url:
                urls_with_params.append(url)

        if not urls_with_params:
            return results

        tool_path = self.config.data.get("tools", {}).get("dalfox", "") or "dalfox"

        for url in urls_with_params[:10]:
            await self.rate_limiter.acquire()
            try:
                cmd = [tool_path, "url", url, "--silence", "--format", "json"]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
                if stdout:
                    for line in stdout.decode(errors="ignore").strip().split("\n"):
                        if line.strip():
                            try:
                                finding = json.loads(line)
                                finding["severity"] = "high"
                                results.append(finding)
                                await self.add_vulnerability(
                                    host=target, name="XSS Vulnerability",
                                    severity="high",
                                    cve="", desc=f"XSS found at {url}",
                                    proof=finding.get("poc", ""),
                                )
                            except json.JSONDecodeError:
                                if "Vulnerable" in line:
                                    results.append({"url": url, "finding": line, "severity": "high"})
            except (FileNotFoundError, asyncio.TimeoutError, OSError):
                continue
        return results
