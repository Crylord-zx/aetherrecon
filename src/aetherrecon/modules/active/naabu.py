"""
Naabu Module — Fast Port Discovery
"""

from __future__ import annotations
import asyncio
import json
from typing import Any
from aetherrecon.modules.base import BaseModule


class NaabuModule(BaseModule):
    name = "naabu"
    category = "active"
    description = "Fast port discovery using Naabu"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        tool_path = self.config.data.get("tools", {}).get("naabu", "") or "naabu"

        try:
            cmd = [tool_path, "-host", target, "-json", "-silent"]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            for line in stdout.decode(errors="ignore").strip().split("\n"):
                if line.strip():
                    try:
                        data = json.loads(line)
                        port = data.get("port", 0)
                        if port:
                            results.append({
                                "host": data.get("host", target),
                                "port": port,
                                "protocol": "tcp",
                            })
                    except json.JSONDecodeError:
                        pass
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            pass
        return results
