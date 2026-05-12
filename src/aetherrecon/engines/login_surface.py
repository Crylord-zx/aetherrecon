"""
Login Surface Analysis Engine
-------------------------------
Detects and classifies authentication surfaces including admin portals,
SSO pages, OAuth flows, MFA presence, and exposed dashboards.
"""

from __future__ import annotations
import asyncio
import re
from typing import Any
from urllib.parse import urljoin

import aiohttp
from aetherrecon.modules.base import BaseModule

AUTH_PATHS = [
    ("/admin", "admin_panel"), ("/administrator", "admin_panel"),
    ("/wp-admin", "wordpress_admin"), ("/wp-login.php", "wordpress_login"),
    ("/login", "login_page"), ("/signin", "login_page"),
    ("/sign-in", "login_page"), ("/auth/login", "login_page"),
    ("/dashboard", "dashboard"), ("/portal", "portal"),
    ("/sso", "sso"), ("/oauth", "oauth"),
    ("/api/auth", "api_auth"), ("/api/login", "api_auth"),
    ("/accounts/login", "django_auth"),
    ("/user/login", "login_page"),
    ("/auth", "auth_endpoint"),
    ("/panel", "control_panel"),
    ("/console", "console"),
    ("/webmail", "webmail"),
]

MFA_INDICATORS = ["mfa", "two-factor", "2fa", "otp", "authenticator", "totp"]


class LoginSurfaceAnalyzer(BaseModule):
    name = "login_surface"
    category = "discovery"
    description = "Authentication surface detection and classification"

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
            for path, auth_type in AUTH_PATHS:
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
                                body = await resp.text()
                                if len(body) < 50:
                                    continue
                                has_mfa = any(m in body.lower() for m in MFA_INDICATORS)
                                has_form = '<form' in body.lower() and ('password' in body.lower() or 'login' in body.lower())
                                finding = {
                                    "type": auth_type, "url": url,
                                    "status": resp.status,
                                    "has_login_form": has_form,
                                    "mfa_detected": has_mfa,
                                    "severity": "medium" if resp.status == 200 else "low",
                                }
                                results.append(finding)
                                await self.add_finding(
                                    title=f"Auth Surface: {auth_type} at {path}",
                                    severity=finding["severity"],
                                    description=f"Authentication interface at {url}" +
                                                (" (MFA detected)" if has_mfa else ""),
                                    data=finding,
                                )
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                    continue

        self.context.setdefault("auth_surfaces", []).extend(results)
        return results
