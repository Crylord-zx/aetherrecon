"""
Technology-Specific Analysis Modules
---------------------------------------
Auto-triggered modules that run specialized checks based on
detected technologies (WordPress, Nginx, GraphQL, Jira, etc.).
"""

from __future__ import annotations
import asyncio
from typing import Any
from urllib.parse import urljoin

import aiohttp
from aetherrecon.modules.base import BaseModule


class TechSpecificAnalyzer(BaseModule):
    """
    Routes analysis to technology-specific checks based on detection results.
    
    if wordpress → run_wp_modules()
    if nginx → run_nginx_checks()
    if graphql → run_graphql_checks()
    if jira → run_jira_checks()
    """
    name = "tech_specific"
    category = "vuln"
    description = "Technology-specific security analysis"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        techs = {
            t.get("name", "").lower()
            for t in self.context.get("technologies", [])
            if isinstance(t, dict)
        }

        if techs & {"wordpress", "wp"}:
            results.extend(await self._wordpress_checks(target))
        if techs & {"nginx"}:
            results.extend(await self._nginx_checks(target))
        if techs & {"apache"}:
            results.extend(await self._apache_checks(target))
        if techs & {"graphql"}:
            results.extend(await self._graphql_checks(target))
        if techs & {"jira", "atlassian"}:
            results.extend(await self._jira_checks(target))
        if techs & {"php"}:
            results.extend(await self._php_checks(target))
        if techs & {"django"}:
            results.extend(await self._django_checks(target))
        if techs & {"express.js", "node.js", "nodejs"}:
            results.extend(await self._nodejs_checks(target))

        return results

    async def _wordpress_checks(self, target: str) -> list[dict]:
        """WordPress-specific security checks."""
        findings = []
        wp_paths = [
            "/xmlrpc.php", "/wp-json/wp/v2/users",
            "/wp-content/debug.log", "/wp-config.php.bak",
            "/wp-json/", "/.wp-config.php.swp",
            "/wp-content/uploads/", "/readme.html",
        ]
        base = self._get_base_url(target)
        for path in wp_paths:
            result = await self._probe_path(base, path, "wordpress")
            if result:
                findings.append(result)
        return findings

    async def _nginx_checks(self, target: str) -> list[dict]:
        findings = []
        paths = ["/nginx_status", "/status", "/.nginx.conf"]
        base = self._get_base_url(target)
        for path in paths:
            result = await self._probe_path(base, path, "nginx")
            if result:
                findings.append(result)
        return findings

    async def _apache_checks(self, target: str) -> list[dict]:
        findings = []
        paths = ["/server-status", "/server-info", "/.htaccess"]
        base = self._get_base_url(target)
        for path in paths:
            result = await self._probe_path(base, path, "apache")
            if result:
                findings.append(result)
        return findings

    async def _graphql_checks(self, target: str) -> list[dict]:
        findings = []
        base = self._get_base_url(target)
        gql_paths = ["/graphql", "/graphiql", "/playground", "/api/graphql"]
        for path in gql_paths:
            await self.rate_limiter.acquire()
            url = urljoin(base, path)
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url, ssl=False,
                        json={"query": "{ __schema { types { name } } }"},
                        timeout=aiohttp.ClientTimeout(total=8),
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            if "__schema" in body:
                                finding = {
                                    "type": "graphql_introspection",
                                    "url": url, "severity": "high",
                                }
                                findings.append(finding)
                                await self.add_finding(
                                    title=f"GraphQL Introspection Enabled: {url}",
                                    severity="high",
                                    description="Full API schema exposed via introspection",
                                    data=finding,
                                )
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                continue
        return findings

    async def _jira_checks(self, target: str) -> list[dict]:
        findings = []
        paths = [
            "/rest/api/2/serverInfo", "/rest/api/latest/serverInfo",
            "/servicedesk/customer/user/signup",
            "/secure/QueryComponent!Default.jspa",
            "/rest/api/2/dashboard", "/rest/api/2/user/picker",
        ]
        base = self._get_base_url(target)
        for path in paths:
            result = await self._probe_path(base, path, "jira")
            if result:
                findings.append(result)
        return findings

    async def _php_checks(self, target: str) -> list[dict]:
        findings = []
        paths = ["/phpinfo.php", "/info.php", "/php_info.php", "/test.php"]
        base = self._get_base_url(target)
        for path in paths:
            result = await self._probe_path(base, path, "php")
            if result:
                findings.append(result)
        return findings

    async def _django_checks(self, target: str) -> list[dict]:
        findings = []
        paths = ["/admin/", "/__debug__/", "/debug/"]
        base = self._get_base_url(target)
        for path in paths:
            result = await self._probe_path(base, path, "django")
            if result:
                findings.append(result)
        return findings

    async def _nodejs_checks(self, target: str) -> list[dict]:
        findings = []
        paths = ["/debug", "/.env", "/package.json", "/node_modules/"]
        base = self._get_base_url(target)
        for path in paths:
            result = await self._probe_path(base, path, "nodejs")
            if result:
                findings.append(result)
        return findings

    async def _probe_path(self, base_url: str, path: str, tech: str) -> dict | None:
        await self.rate_limiter.acquire()
        url = urljoin(base_url, path)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, ssl=False,
                    timeout=aiohttp.ClientTimeout(total=8),
                    headers={"User-Agent": "AetherRecon/2.0"},
                    allow_redirects=False,
                ) as resp:
                    if resp.status in (200, 401, 403):
                        body = await resp.text()
                        if len(body) > 50 and "<title>404" not in body.lower():
                            finding = {
                                "type": f"{tech}_exposure",
                                "url": url, "path": path,
                                "status": resp.status,
                                "severity": "medium" if resp.status != 200 else "high",
                            }
                            await self.add_finding(
                                title=f"{tech.title()} Exposure: {path}",
                                severity=finding["severity"],
                                description=f"{tech.title()}-specific path accessible",
                                data=finding,
                            )
                            return finding
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            pass
        return None

    def _get_base_url(self, target: str) -> str:
        for svc in self.context.get("http_services", []):
            if isinstance(svc, dict) and svc.get("url"):
                return svc["url"]
        return f"https://{target}"
