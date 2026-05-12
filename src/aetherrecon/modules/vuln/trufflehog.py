"""
TruffleHog Module — Secret Discovery
"""

from __future__ import annotations
import asyncio
import json
from typing import Any
from aetherrecon.modules.base import BaseModule


class TrufflehogModule(BaseModule):
    name = "trufflehog"
    category = "vuln"
    description = "Secret discovery using TruffleHog"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        tool_path = self.config.data.get("tools", {}).get("trufflehog", "") or "trufflehog"

        urls_to_scan = []
        for svc in self.context.get("http_services", []):
            if isinstance(svc, dict) and svc.get("url"):
                urls_to_scan.append(svc["url"])
        if not urls_to_scan:
            urls_to_scan = [f"https://{target}"]

        for url in urls_to_scan[:3]:
            await self.rate_limiter.acquire()
            try:
                # Scan URL/domain directly without git context using filesystem or s3 if applicable,
                # but trufflehog's main usage is git. Let's just use it if we found a git repo in context
                # Otherwise, it might fail. We will use the 'filesystem' mode on downloaded artifacts if they exist,
                # or just skip if no clear path is defined. For now, try to scan the base url as a git repo just in case.
                cmd = [tool_path, "git", url, "--json", "--only-verified"]
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                
                for line in stdout.decode(errors="ignore").strip().split("\n"):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            secret_type = data.get("DetectorName", "unknown")
                            if secret_type:
                                finding = {
                                    "url": url,
                                    "secret_type": secret_type,
                                    "severity": "critical",
                                }
                                results.append(finding)
                                await self.add_finding(
                                    title=f"Verified Secret Exposed: {secret_type}",
                                    severity="critical",
                                    description=f"Trufflehog discovered {secret_type} at {url}",
                                    data=finding
                                )
                        except json.JSONDecodeError:
                            pass
            except (FileNotFoundError, asyncio.TimeoutError, OSError):
                continue

        return results
