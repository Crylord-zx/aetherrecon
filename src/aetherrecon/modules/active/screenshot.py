"""
Screenshot Module
-----------------
Captures headless browser screenshots of live web servers using gowitness.
"""

import asyncio
import os
from pathlib import Path
from typing import Any

from aetherrecon.modules.base import BaseModule

class ScreenshotModule(BaseModule):
    name = "screenshot"
    category = "active"
    description = "Captures visual screenshots of web services"

    async def run(self, target: str) -> list[dict[str, Any]]:
        # Check if gowitness is available
        plugin_mgr = self.plugin_manager
        if not plugin_mgr.is_available("gowitness"):
            await self.add_finding("Missing Tool", "error", "gowitness not found. Cannot take screenshots.")
            return []

        # Gather live URLs from context (populated by http_probe)
        urls = []
        for asset in await self.db.get_assets(self.scan_id):
            if asset.get("asset_type") == "http_service":
                urls.append(asset.get("value"))
                    
        if not urls:
            urls = [f"http://{target}", f"https://{target}"]

        output_dir = Path(self.config.data.get("general", {}).get("output_dir", "./output"))
        screenshots_dir = output_dir / "screenshots"
        screenshots_dir.mkdir(exist_ok=True, parents=True)

        results = []
        
        # Write URLs to a temporary file for gowitness
        url_file = output_dir / "urls_to_screenshot.txt"
        url_file.write_text("\n".join(urls[:30])) # Limit to 30 to prevent exhaustion

        try:
            # gowitness file -f urls.txt -P ./output/screenshots/ --timeout 15
            args = [
                "file", "-f", str(url_file), 
                "-P", str(screenshots_dir),
                "--timeout", "15"
            ]
            
            await self.rate_limiter.acquire()
            stdout = await plugin_mgr.run_tool("gowitness", args, timeout=120)
            
            # Check what screenshots were actually saved
            for pic in screenshots_dir.glob("*.png"):
                file_path = str(pic.absolute())
                
                # Populating the specialized table
                await self.add_screenshot(target, file_path)
                
                results.append({
                    "file_path": file_path
                })
                
            if results:
                await self.add_finding(
                    title=f"Screenshots captured: {len(results)}",
                    severity="info",
                    description=f"Saved to {screenshots_dir}",
                    data={"count": len(results), "path": str(screenshots_dir)}
                )

        except asyncio.TimeoutError:
            await self.add_finding("Timeout", "warning", "gowitness took too long and was killed (Resource Exhaustion Limiter).")
        except Exception as e:
             await self.add_finding("Error", "error", str(e))
             
        # Cleanup
        if url_file.exists():
            url_file.unlink()

        return results
