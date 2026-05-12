"""
CMSeeK Module
-------------
Automated CMS detection and scanning.
"""

import asyncio
from typing import Any
from aetherrecon.modules.base import BaseModule

class CMSeekModule(BaseModule):
    name = "cmseek"
    category = "vuln"
    description = "CMS Detection and Vulnerability Scanning"

    async def run(self, target: str) -> list[dict[str, Any]]:
        # Only run if explicitly called
        if not self.context.get("force_cmseek", False):
             return []
             
        if not self.plugin_manager.is_available("cmseek"):
             await self.add_finding("Missing Tool", "error", "cmseek not found.")
             return []

        try:
             # cmseek -u target.com --batch
             args = ["-u", f"https://{target}", "--batch"]
             
             await self.rate_limiter.acquire()
             stdout = await self.plugin_manager.run_tool("cmseek", args, timeout=300)
             
             if "CMS Detected" in stdout or "Vulnerabilities" in stdout:
                  await self.add_finding(
                       title=f"CMSeek Results for {target}",
                       severity="medium",
                       description="CMSeek identified CMS info or vulnerabilities.",
                       data={"raw": stdout[:1500]}
                  )
                  await self.add_technology(target, "CMS", "Detected")
                  if "Vulnerabilities" in stdout:
                       await self.add_vulnerability(target, "CMS Vulnerability", "medium", desc="Detected by CMSeeK")
                  return [{"target": target, "cmseek_output": stdout}]
        except asyncio.TimeoutError:
             await self.add_finding("Timeout", "warning", "CMSeek hit the 5 minute timeout limit.")
        except Exception:
             pass

        return []
