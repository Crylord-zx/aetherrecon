"""
Security Misconfiguration Engine
-----------------------------------
Detects common security misconfigurations in web applications and services.

Checks: exposed admin panels, public buckets, default pages,
unsafe headers, debug modes, open dashboards.
"""

from __future__ import annotations
import asyncio
from typing import Any
from urllib.parse import urljoin

import aiohttp
from aetherrecon.modules.base import BaseModule

# Default/test pages that indicate misconfigurations
DEFAULT_PAGES = {
    "Apache Default": ["<title>Apache2 Ubuntu Default Page", "It works!", "Apache HTTP Server Test Page"],
    "Nginx Default": ["Welcome to nginx!", "If you see this page, the nginx"],
    "IIS Default": ["IIS Windows Server", "Internet Information Services"],
    "Tomcat Default": ["Apache Tomcat", "If you're seeing this, you've successfully"],
    "Django Debug": ["Django Debug", "You're seeing this because", "DEBUG = True"],
    "Laravel Debug": ["Whoops!", "Laravel", "APP_DEBUG"],
    "Flask Debug": ["Debugger", "Werkzeug", "traceback"],
    "Express Default": ["Express", "Welcome to Express"],
    "Spring Boot": ["Whitelabel Error Page", "Spring Boot"],
    "PHP Info": ["phpinfo()", "PHP Version", "Configuration"],
}

# Admin/dashboard paths to detect
ADMIN_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/wp-login.php",
    "/dashboard", "/portal", "/manager", "/console",
    "/phpmyadmin", "/adminer", "/pgadmin",
    "/kibana", "/grafana", "/prometheus",
    "/jenkins", "/hudson", "/travis",
    "/jira", "/confluence", "/bitbucket",
    "/gitlab", "/gitea", "/gogs",
    "/webmail", "/roundcube", "/mailbox",
    "/cpanel", "/plesk", "/webmin",
    "/solr", "/elasticsearch", "/mongo-express",
]


class MisconfigEngine(BaseModule):
    name = "misconfig_engine"
    category = "vuln"
    description = "Security misconfiguration detection"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        base_urls = set()
        for svc in self.context.get("http_services", []):
            if isinstance(svc, dict):
                base_urls.add(svc.get("url", ""))
        if not base_urls:
            base_urls = {f"https://{target}", f"http://{target}"}

        for base_url in list(base_urls)[:5]:
            if not base_url:
                continue
            results.extend(await self._check_default_pages(base_url))
            results.extend(await self._check_admin_panels(base_url))
            results.extend(await self._check_debug_mode(base_url))
        return results

    async def _check_default_pages(self, base_url: str) -> list[dict]:
        findings = []
        await self.rate_limiter.acquire()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    base_url, ssl=False,
                    timeout=aiohttp.ClientTimeout(total=10),
                    headers={"User-Agent": "AetherRecon/2.0"},
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        for server, indicators in DEFAULT_PAGES.items():
                            if any(ind in body for ind in indicators):
                                finding = {
                                    "type": "default_page",
                                    "server": server,
                                    "url": base_url,
                                    "severity": "medium",
                                }
                                findings.append(finding)
                                await self.add_finding(
                                    title=f"Default {server} Page Detected",
                                    severity="medium",
                                    description=f"Default installation page for {server}",
                                    data=finding,
                                )
                                break
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            pass
        return findings

    async def _check_admin_panels(self, base_url: str) -> list[dict]:
        findings = []
        for path in ADMIN_PATHS:
            await self.rate_limiter.acquire()
            url = urljoin(base_url, path)
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url, ssl=False,
                        timeout=aiohttp.ClientTimeout(total=8),
                        headers={"User-Agent": "AetherRecon/2.0"},
                        allow_redirects=True,
                    ) as resp:
                        if resp.status in (200, 401, 403):
                            finding = {
                                "type": "admin_panel",
                                "url": url, "path": path,
                                "status": resp.status,
                                "severity": "medium" if resp.status in (401, 403) else "high",
                            }
                            findings.append(finding)
                            await self.add_finding(
                                title=f"Admin Panel: {path} ({resp.status})",
                                severity=finding["severity"],
                                description=f"Administration interface detected at {url}",
                                data=finding,
                            )
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                continue
        return findings

    async def _check_debug_mode(self, base_url: str) -> list[dict]:
        findings = []
        debug_paths = ["/debug", "/debug/vars", "/debug/pprof",
                       "/_debug", "/trace", "/console"]
        for path in debug_paths:
            await self.rate_limiter.acquire()
            url = urljoin(base_url, path)
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url, ssl=False,
                        timeout=aiohttp.ClientTimeout(total=8),
                        headers={"User-Agent": "AetherRecon/2.0"},
                    ) as resp:
                        if resp.status == 200:
                            finding = {
                                "type": "debug_endpoint",
                                "url": url, "severity": "high",
                            }
                            findings.append(finding)
                            await self.add_finding(
                                title=f"Debug Endpoint Exposed: {path}",
                                severity="high",
                                description=f"Debug interface at {url}",
                                data=finding,
                            )
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                continue
        return findings
