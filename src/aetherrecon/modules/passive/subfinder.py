"""
Subfinder Module — Passive Subdomain Discovery
"""

from __future__ import annotations
import asyncio
import json
from typing import Any
from aetherrecon.modules.base import BaseModule


class SubfinderModule(BaseModule):
    name = "subfinder"
    category = "passive"
    description = "Passive subdomain enumeration using Subfinder"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        tool_path = self.config.data.get("tools", {}).get("subfinder", "") or "subfinder"

        try:
            cmd = [tool_path, "-d", target, "-silent", "-json"]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            for line in stdout.decode(errors="ignore").strip().split("\n"):
                if line.strip():
                    try:
                        data = json.loads(line)
                        sub = data.get("host", "")
                        if sub:
                            results.append({"subdomain": sub, "source": "subfinder"})
                            await self.add_subdomain(sub, source="subfinder")
                    except json.JSONDecodeError:
                        if "." in line.strip():
                            results.append({"subdomain": line.strip(), "source": "subfinder"})
                            await self.add_subdomain(line.strip(), source="subfinder")
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            await self.add_finding(
                title="Subfinder not available", severity="info",
                description="Install subfinder for enhanced subdomain discovery",
            )
        return results
