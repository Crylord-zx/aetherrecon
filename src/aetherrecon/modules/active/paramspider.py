"""
ParamSpider Module — Parameter Discovery
"""

from __future__ import annotations
import asyncio
import os
from typing import Any
from aetherrecon.modules.base import BaseModule


class ParamspiderModule(BaseModule):
    name = "paramspider"
    category = "active"
    description = "Parameter discovery using ParamSpider"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        tool_path = self.config.data.get("tools", {}).get("paramspider", "") or "paramspider"

        try:
            cmd = [tool_path, "-d", target, "--quiet"]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=300)
            
            output_file = f"results/{target}.txt"
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    for line in f:
                        url = line.strip()
                        if url:
                            results.append({"url": url, "source": "paramspider"})
                            self.context.setdefault("discovered_urls", []).append(url)
                os.remove(output_file)
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            pass

        return results
