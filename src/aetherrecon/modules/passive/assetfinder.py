"""
Assetfinder Module — Subdomain Discovery
"""

from __future__ import annotations
import asyncio
from typing import Any
from aetherrecon.modules.base import BaseModule


class AssetfinderModule(BaseModule):
    name = "assetfinder"
    category = "passive"
    description = "Subdomain discovery using assetfinder"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        tool_path = self.config.data.get("tools", {}).get("assetfinder", "") or "assetfinder"

        try:
            cmd = [tool_path, "-subs-only", target]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            
            for line in stdout.decode(errors="ignore").strip().split("\n"):
                sub = line.strip()
                if sub and "." in sub:
                    results.append({"subdomain": sub, "source": "assetfinder"})
                    await self.add_subdomain(sub, source="assetfinder")
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            pass

        return results
