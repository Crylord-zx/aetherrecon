"""
Eyewitness Module — Visual Reconnaissance
"""

from __future__ import annotations
import asyncio
from typing import Any
from aetherrecon.modules.base import BaseModule


class EyewitnessModule(BaseModule):
    name = "eyewitness"
    category = "active"
    description = "Visual reconnaissance using EyeWitness"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        tool_path = self.config.data.get("tools", {}).get("eyewitness", "") or "eyewitness"

        urls_file = f"eyewitness_urls_{target}.txt"
        urls = []
        for svc in self.context.get("http_services", []):
            if isinstance(svc, dict) and svc.get("url"):
                urls.append(svc["url"])
                
        if not urls:
            return results

        with open(urls_file, "w") as f:
            for u in urls:
                f.write(f"{u}\n")

        try:
            cmd = [tool_path, "-f", urls_file, "--web", "-d", f"eyewitness_out_{target}", "--no-prompt"]
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=300)
            
            # EyeWitness creates HTML reports and screenshots in the output dir
            out_dir = f"eyewitness_out_{target}"
            import os
            if os.path.exists(out_dir):
                # We could parse the report or just note it succeeded
                results.append({"status": "completed", "report_dir": out_dir})
                await self.add_evidence(
                    evidence_type="eyewitness_report",
                    host=target,
                    description=f"EyeWitness report generated at {out_dir}"
                )
        except (FileNotFoundError, asyncio.TimeoutError, OSError):
            pass
        finally:
            import os
            if os.path.exists(urls_file):
                os.remove(urls_file)

        return results
