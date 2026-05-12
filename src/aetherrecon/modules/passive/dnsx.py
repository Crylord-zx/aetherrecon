"""
DNSX Module — Fast DNS Resolution & Validation
"""

from __future__ import annotations
import asyncio
import json
from typing import Any
from aetherrecon.modules.base import BaseModule


class DnsxModule(BaseModule):
    name = "dnsx"
    category = "passive"
    description = "Fast DNS resolution and validation using dnsx"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        tool_path = self.config.data.get("tools", {}).get("dnsx", "") or "dnsx"

        # Validate subdomains discovered so far
        subs = self.context.get("subdomains", [target])
        if not subs:
            return results

        input_data = "\n".join(subs).encode()

        try:
            cmd = [tool_path, "-a", "-aaaa", "-cname", "-json", "-silent"]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(input=input_data), timeout=120)
            
            for line in stdout.decode(errors="ignore").strip().split("\n"):
                if line.strip():
                    try:
                        data = json.loads(line)
                        host = data.get("host")
                        a_records = data.get("a", [])
                        aaaa_records = data.get("aaaa", [])
                        
                        if host and (a_records or aaaa_records):
                            result = {
                                "host": host,
                                "a": a_records,
                                "aaaa": aaaa_records,
                                "cname": data.get("cname", [])
                            }
                            results.append(result)
                            
                            # Add IPs to context
                            for ip in a_records + aaaa_records:
                                self.context.setdefault("ips", []).append(ip)
                                await self.add_live_host(host=ip, port=0, scheme="network", status=0, title="")
                    except json.JSONDecodeError:
                        pass
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            pass

        return results
