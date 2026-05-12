"""
Nuclei Vulnerability Scanner Module
------------------------------------
Main vulnerability engine. Runs template-based scans for CVEs, 
misconfigurations, and exposures with high confidence.
"""

import asyncio
import json
from typing import Any
from aetherrecon.modules.base import BaseModule

class NucleiModule(BaseModule):
    name = "nuclei"
    category = "vuln"
    description = "Template-based vulnerability scanning via Nuclei"

    async def run(self, target: str) -> list[dict[str, Any]]:
        if not self.plugin_manager.is_available("nuclei"):
            await self.add_finding("Missing Tool", "error", "Nuclei not found in PATH.")
            return []

        # Get targets from context (subdomains + IPs)
        hosts = [target]
        hosts.extend(self.context.get("subdomains", [])[:20])
        hosts.extend(self.context.get("ips", [])[:10])
        
        results = []
        
        # Build command: nuclei -u host -json-export -severity critical,high,medium
        # We'll run one nuclei command with multiple targets to be efficient
        target_list = ",".join(hosts)
        
        try:
            args = ["-u", target_list, "-json-export", "-", "-silent"]
            # Add severity filter if configured
            severity = self.config.data.get("modules", {}).get("nuclei", {}).get("severity", ["critical", "high", "medium"])
            if severity:
                args.extend(["-severity", ",".join(severity)])

            await self.rate_limiter.acquire()
            self.console.print(f"[dim]Launching Nuclei on {len(hosts)} targets...[/dim]")
            
            stdout = await self.plugin_manager.run_tool("nuclei", args, timeout=600)
            
            if stdout:
                for line in stdout.splitlines():
                    try:
                        finding = json.loads(line)
                        results.append(finding)
                        
                        await self.add_vulnerability(
                            target=finding.get("matched-at", target),
                            name=finding.get("info", {}).get("name", "Unknown Nuclei Finding"),
                            severity=finding.get("info", {}).get("severity", "info"),
                            desc=finding.get("info", {}).get("description", ""),
                            cve=finding.get("info", {}).get("classification", {}).get("cve-id", "")
                        )
                    except json.JSONDecodeError:
                        continue

        except asyncio.TimeoutError:
             await self.add_finding("Timeout", "warning", "Nuclei scan exceeded timeout.")
        except Exception as e:
             await self.add_finding("Nuclei Error", "error", str(e))

        return results
