"""
Secrets & Exposure Intelligence Engine
-----------------------------------------
Scans for exposed secrets, credentials, and sensitive configurations.
"""

from __future__ import annotations
import re
import asyncio
from typing import Any
from urllib.parse import urljoin

import aiohttp
from aetherrecon.modules.base import BaseModule

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production",
    "/.git/config", "/.git/HEAD",
    "/wp-config.php.bak", "/wp-config.php.old",
    "/web.config", "/web.config.bak",
    "/.htpasswd", "/.htaccess",
    "/phpinfo.php", "/server-status",
    "/backup.sql", "/dump.sql",
    "/docker-compose.yml", "/Dockerfile",
    "/package.json", "/composer.json",
    "/requirements.txt", "/.aws/credentials",
    "/firebase.json", "/actuator/env",
    "/debug/vars", "/config.json",
    "/appsettings.json", "/crossdomain.xml",
    "/elmah.axd", "/trace.axd",
    "/.DS_Store", "/id_rsa",
]

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
    "github_token": re.compile(r'ghp_[A-Za-z0-9]{36}'),
    "slack_token": re.compile(r'xox[bpors]-[0-9a-zA-Z-]{10,}'),
    "google_api_key": re.compile(r'AIza[0-9A-Za-z_-]{35}'),
    "jwt_token": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    "private_key": re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    "connection_string": re.compile(r'(?:mongodb|mysql|postgresql|redis)://[^\s"\'<]+', re.I),
    "stripe_key": re.compile(r'sk_(?:live|test)_[0-9a-zA-Z]{24,}'),
}


class SecretsScanner(BaseModule):
    name = "secrets_scanner"
    category = "vuln"
    description = "Secrets and exposure intelligence scanner"

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
            results.extend(await self._check_sensitive_paths(base_url))
        return results

    async def _check_sensitive_paths(self, base_url: str) -> list[dict]:
        findings = []
        for path in SENSITIVE_PATHS:
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
                        if resp.status == 200:
                            body = await resp.text()
                            if len(body) < 50 or "<title>404" in body.lower():
                                continue
                            severity = self._classify_severity(path)
                            finding = {
                                "type": "sensitive_file", "url": url,
                                "path": path, "severity": severity,
                            }
                            for stype, pattern in SECRET_PATTERNS.items():
                                if pattern.search(body):
                                    finding["secret_type"] = stype
                                    severity = "critical"
                                    break
                            findings.append(finding)
                            await self.add_finding(
                                title=f"Sensitive File Exposed: {path}",
                                severity=severity,
                                description=f"Sensitive file accessible at {url}",
                                data=finding,
                            )
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                continue
        return findings

    @staticmethod
    def _classify_severity(path: str) -> str:
        path_lower = path.lower()
        critical = [".env", ".git/config", "wp-config", ".aws", "id_rsa", "backup.sql"]
        high = [".git/HEAD", "phpinfo", "server-status", "actuator", "docker-compose"]
        if any(p in path_lower for p in critical):
            return "critical"
        elif any(p in path_lower for p in high):
            return "high"
        return "medium"
