"""
SQLMap Module — SQL Injection Testing
"""

from __future__ import annotations
import asyncio
from typing import Any

from aetherrecon.modules.base import BaseModule


class SQLMapModule(BaseModule):
    name = "sqlmap"
    category = "vuln"
    description = "SQL injection testing using sqlmap"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        urls_with_params = []
        for url_item in self.context.get("discovered_urls", []):
            url = url_item if isinstance(url_item, str) else url_item.get("url", "")
            if "?" in url:
                urls_with_params.append(url)

        if not urls_with_params:
            return results

        tool_path = self.config.data.get("tools", {}).get("sqlmap", "") or "sqlmap"

        for url in urls_with_params[:5]:
            await self.rate_limiter.acquire()
            try:
                cmd = [
                    tool_path, "-u", url,
                    "--batch", "--level=1", "--risk=1",
                    "--threads=1", "--timeout=10",
                    "--output-dir=/tmp/sqlmap_out",
                ]
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                output = stdout.decode(errors="ignore")
                if "is vulnerable" in output.lower() or "injectable" in output.lower():
                    results.append({
                        "url": url, "type": "sql_injection",
                        "severity": "critical", "output_snippet": output[:500],
                    })
                    await self.add_vulnerability(
                        host=target, name="SQL Injection",
                        severity="critical", desc=f"SQLi found at {url}",
                    )
            except (FileNotFoundError, asyncio.TimeoutError, OSError):
                continue
        return results
