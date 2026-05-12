"""
GAU Module — Historical URLs from web archives
"""

from __future__ import annotations
import asyncio
from typing import Any
from aetherrecon.modules.base import BaseModule


class GauModule(BaseModule):
    name = "gau"
    category = "passive"
    description = "Fetch known URLs from web archives using gau"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        tool_path = self.config.data.get("tools", {}).get("gau", "") or "gau"

        try:
            cmd = [tool_path, target, "--subs"]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            seen = set()
            for line in stdout.decode(errors="ignore").strip().split("\n"):
                url = line.strip()
                if url and url not in seen:
                    seen.add(url)
                    results.append({"url": url, "source": "gau"})
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            pass

        # Feed into shared context
        self.context.setdefault("discovered_urls", []).extend(results)
        return results
