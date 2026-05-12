"""
Nmap Service Enumeration Module
-------------------------------
Performs deep service and version fingerprinting using nmap -sV.
Only runs against ports discovered by the initial port scan to save time and reduce noise.
"""

import asyncio
from typing import Any
from aetherrecon.modules.base import BaseModule

class NmapEnumModule(BaseModule):
    name = "nmap_enum"
    category = "active"
    description = "Deep service version fingerprinting via Nmap"

    async def run(self, target: str) -> list[dict[str, Any]]:
        if not self.plugin_manager.is_available("nmap"):
            return []

        # Get discovered ports from context
        open_ports = self.context.get("open_ports", [])
        if not open_ports:
            return []

        # Extract port numbers for this specific target
        ports_to_scan = []
        for p in open_ports:
            if p.get("host") == target:
                ports_to_scan.append(str(p.get("port")))
        
        if not ports_to_scan:
            return []

        port_arg = ",".join(ports_to_scan)
        results = []

        try:
            # nmap -sV -Pn -p <ports> <target>
            args = ["-sV", "-Pn", "-p", port_arg, target]
            
            await self.rate_limiter.acquire()
            self.console.print(f"[dim]Running deep nmap scan on {len(ports_to_scan)} ports...[/dim]")
            
            stdout = await self.plugin_manager.run_tool("nmap", args, timeout=300)
            
            if stdout:
                await self.add_finding(
                    title=f"Nmap Service Fingerprints for {target}",
                    severity="info",
                    description="Deep version fingerprinting completed.",
                    data={"raw_output": stdout}
                )
                
                # Simple extraction of service info for the results list
                for line in stdout.splitlines():
                    if "/tcp" in line and "open" in line:
                        results.append({"service_line": line.strip()})

        except asyncio.TimeoutError:
             await self.add_finding("Timeout", "warning", "Nmap service scan timed out.")
        except Exception as e:
             await self.add_finding("Nmap Error", "error", str(e))

        return results
