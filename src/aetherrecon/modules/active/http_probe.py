"""
HTTP Probe Module
-----------------
Probes discovered hosts/subdomains for HTTP/HTTPS services.
Collects status codes, titles, Server headers, and redirect chains.
"""

import asyncio
from typing import Any

import aiohttp
from bs4 import BeautifulSoup

from aetherrecon.modules.base import BaseModule


class HTTPProbeModule(BaseModule):
    name = "http_probe"
    category = "active"
    description = "HTTP/HTTPS service probing"

    async def run(self, target: str) -> list[dict[str, Any]]:
        mod_cfg = self.config.get_module_config("http_probe")
        ports = mod_cfg.get("check_ports", [80, 443, 8080, 8443])
        user_agent = mod_cfg.get("user_agent", "AetherRecon/1.0")
        follow = mod_cfg.get("follow_redirects", True)
        
        results: list[dict[str, Any]] = []

        # Build list of URLs to probe
        targets = [target]
        targets.extend(self.context.get("subdomains", [])[:50])
        targets.extend(self.context.get("ips", [])[:20])  # Add raw IPs to the probe list

        # Use httpx if available (Recommended Flow)
        if self.plugin_manager.is_available("httpx"):
            self.console.print("[dim]Using httpx for high-performance probing...[/dim]")
            target_file = f"./output/targets_{self.scan_id}.txt"
            with open(target_file, "w") as f:
                f.write("\n".join(targets))
            
            try:
                # httpx -title -tech-detect -server -status-code -json
                args = ["-l", target_file, "-title", "-tech-detect", "-server", "-status-code", "-json", "-silent"]
                stdout = await self.plugin_manager.run_tool("httpx", args, timeout=300)
                
                for line in stdout.splitlines():
                    try:
                        data = json.loads(line)
                        res = {
                            "url": data.get("url"),
                            "host": data.get("host"),
                            "port": data.get("port"),
                            "status_code": data.get("status-code"),
                            "title": data.get("title"),
                            "server": data.get("server"),
                            "tech": data.get("tech", []),
                        }
                        results.append(res)
                        await self.add_technology(res["url"], "detect", ", ".join(res["tech"]))
                        await self.add_asset("http_service", res["url"], res)
                    except Exception: continue
                return results
            except Exception as e:
                self.console.print(f"[yellow]httpx failed, falling back: {e}[/yellow]")

        # --- Native aiohttp Fallback ---
        sem = asyncio.Semaphore(20)

        async def probe_url(host: str, port: int, scheme: str):
            url = f"{scheme}://{host}:{port}" if port not in (80, 443) else f"{scheme}://{host}"
            async with sem:
                await self.rate_limiter.acquire()
                try:
                    timeout = aiohttp.ClientTimeout(total=10)
                    async with aiohttp.ClientSession(
                        headers={"User-Agent": user_agent},
                        timeout=timeout,
                    ) as session:
                        async with session.get(
                            url,
                            allow_redirects=follow,
                            ssl=False,  # Don't verify SSL for probing
                        ) as resp:
                            body = await resp.text(errors="replace")
                            title = ""
                            try:
                                soup = BeautifulSoup(body[:10000], "html.parser")
                                title_tag = soup.find("title")
                                if title_tag:
                                    title = title_tag.get_text(strip=True)[:200]
                            except Exception:
                                pass

                            # Adaptive Throttling Integration
                            if hasattr(self.rate_limiter, "report_throttle") and resp.status in (403, 429, 503):
                                await self.rate_limiter.report_throttle(reason=str(resp.status))
                            elif hasattr(self.rate_limiter, "report_success") and resp.status < 400:
                                await self.rate_limiter.report_success()

                            result = {
                                "url": str(resp.url),
                                "host": host,
                                "port": port,
                                "scheme": scheme,
                                "status_code": resp.status,
                                "title": title,
                                "server": resp.headers.get("Server", ""),
                                "content_type": resp.headers.get("Content-Type", ""),
                                "content_length": resp.headers.get("Content-Length", ""),
                                "headers": dict(resp.headers),
                            }
                            results.append(result)
                            await self.add_finding(
                                title=f"HTTP service: {url}",
                                severity="info",
                                description=f"[{resp.status}] {title} | Server: {result['server']}",
                                data=result,
                            )
                            await self.add_asset("http_service", url, {
                                "status": resp.status, "title": title,
                            })

                except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                    pass

        tasks = []
        for host in targets:
            for port in ports:
                scheme = "https" if port in (443, 8443) else "http"
                tasks.append(probe_url(host, port, scheme))

        await asyncio.gather(*tasks)

        return results
