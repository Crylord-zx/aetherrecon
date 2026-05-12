"""
WPScan Module
-------------
Black box WordPress vulnerability scanner.
"""

import asyncio
from typing import Any
from aetherrecon.modules.base import BaseModule

class WPScanModule(BaseModule):
    name = "wpscan"
    category = "vuln"
    description = "WordPress vulnerability scanner"

    async def run(self, target: str) -> list[dict[str, Any]]:
        if not self.plugin_manager.is_available("wpscan"):
            return []

        # Find WordPress instances from tech_fingerprint
        wp_urls = []
        for finding in self.context.get("findings", []):
            if finding.get("module") == "tech_fingerprint":
                desc = finding.get("description", "")
                if "WordPress" in desc:
                    data = finding.get("data", {})
                    if "url" in data:
                        wp_urls.append(data["url"])
                        
        if not wp_urls:
            # Maybe the preset was forced, try primary domain
            wp_urls = [f"https://{target}"]

        mod_cfg = self.config.get_module_config("wpscan")
        api_token = mod_cfg.get("api_token", "")

        results = []
        for url in wp_urls[:3]: # Limit to 3 to prevent extreme scan times
            try:
                # wpscan --url http://target/ --no-update --disable-tls-checks
                args = ["--url", url, "--no-update", "--disable-tls-checks", "--random-user-agent"]
                
                if api_token:
                    args.extend(["--api-token", api_token])
                
                await self.rate_limiter.acquire()
                stdout = await self.plugin_manager.run_tool("wpscan", args, timeout=300)
                
                if "[!]" in stdout or "Vulnerabilities found:" in stdout:
                    severity = "high" if "Vulnerabilities found" in stdout else "medium"
                    await self.add_finding(
                        title=f"WordPress Issues on {url}",
                        severity=severity,
                        description="WPScan discovered potential issues or vulnerabilities.",
                        data={"raw": stdout}
                    )
                    await self.add_technology(url, "CMS", "WordPress")
                    if severity == "high":
                        await self.add_vulnerability(url, "WordPress Vulnerability", "high", desc="Detected by WPScan")
                    results.append({"url": url, "wpscan_output": stdout})
            except asyncio.TimeoutError:
                await self.add_finding("Timeout", "warning", f"WPScan timed out on {url}")
            except Exception:
                pass

        return results
