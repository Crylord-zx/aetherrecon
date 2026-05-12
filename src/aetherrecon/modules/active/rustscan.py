"""
RustScan Module — Ultra-Fast Port Scanner
"""

from __future__ import annotations
import asyncio
import re
from typing import Any
from aetherrecon.modules.base import BaseModule


class RustScanModule(BaseModule):
    name = "rustscan"
    category = "active"
    description = "Ultra-fast port scanning using RustScan"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        tool_path = self.config.data.get("tools", {}).get("rustscan", "") or "rustscan"

        try:
            # -a target, -g returns pure array of open ports
            cmd = [tool_path, "-a", target, "-g"]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
            output = stdout.decode(errors="ignore").strip()
            
            # Output format: 192.168.1.1 -> [80, 443]
            ports_match = re.search(r'\[(.*?)\]', output)
            if ports_match:
                ports_str = ports_match.group(1)
                for port_str in ports_str.split(","):
                    port_str = port_str.strip()
                    if port_str.isdigit():
                        port = int(port_str)
                        results.append({"host": target, "port": port, "protocol": "tcp"})
                        self.context.setdefault("open_ports", []).append({
                            "host": target, "port": port, "service": "unknown"
                        })
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            pass

        return results
