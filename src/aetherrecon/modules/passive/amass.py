"""
Amass Module — Deep Asset Mapping
"""

from __future__ import annotations
import asyncio
from typing import Any
from aetherrecon.modules.base import BaseModule


class AmassModule(BaseModule):
    name = "amass"
    category = "passive"
    description = "Deep asset mapping using Amass"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        tool_path = self.config.data.get("tools", {}).get("amass", "") or "amass"

        try:
            cmd = [tool_path, "enum", "-passive", "-d", target]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            for line in stdout.decode(errors="ignore").strip().split("\n"):
                sub = line.strip()
                if sub and "." in sub:
                    results.append({"subdomain": sub, "source": "amass"})
                    await self.add_subdomain(sub, source="amass")
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            pass
        return results
