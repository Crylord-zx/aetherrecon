"""
Security Headers Analysis Module
----------------------------------
Checks HTTP responses for missing or misconfigured security headers.
Evaluates against OWASP recommended headers.
"""

import asyncio
from typing import Any

import aiohttp

from aetherrecon.modules.base import BaseModule

# Security headers to check and their recommendations
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "description": "HSTS not set — vulnerable to protocol downgrade attacks",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "CSP not set — increased risk of XSS attacks",
        "recommendation": "Implement a Content-Security-Policy header",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "Missing X-Content-Type-Options — MIME sniffing possible",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "Missing X-Frame-Options — clickjacking possible",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "description": "Missing X-XSS-Protection header",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block (or rely on CSP)",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Missing Referrer-Policy — referrer info may leak",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Missing Permissions-Policy (Feature-Policy)",
        "recommendation": "Add: Permissions-Policy: geolocation=(), camera=()",
    },
    "X-Permitted-Cross-Domain-Policies": {
        "severity": "low",
        "description": "Missing cross-domain policy header",
        "recommendation": "Add: X-Permitted-Cross-Domain-Policies: none",
    },
}

# Headers that should NOT be present (information leakage)
LEAKY_HEADERS = {
    "Server": "Server header reveals software version",
    "X-Powered-By": "X-Powered-By reveals technology stack",
    "X-AspNet-Version": "ASP.NET version disclosed",
    "X-AspNetMvc-Version": "ASP.NET MVC version disclosed",
}


class HeadersAnalysisModule(BaseModule):
    name = "headers_analysis"
    category = "vuln"
    description = "Security headers analysis"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Get URLs to check from context
        urls = set()
        for svc in self.context.get("http_services", []):
            urls.add(svc.get("url", ""))
        if not urls:
            urls = {f"https://{target}", f"http://{target}"}

        for url in list(urls)[:10]:
            if not url:
                continue
            await self.rate_limiter.acquire()

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url, ssl=False,
                        timeout=aiohttp.ClientTimeout(total=10),
                        headers={"User-Agent": "AetherRecon/1.0"},
                    ) as resp:
                        headers = dict(resp.headers)

                        # Check for missing security headers
                        for header, info in SECURITY_HEADERS.items():
                            if header not in headers:
                                finding = {
                                    "url": url,
                                    "header": header,
                                    "status": "missing",
                                    "severity": info["severity"],
                                    "description": info["description"],
                                    "recommendation": info["recommendation"],
                                }
                                results.append(finding)
                                await self.add_finding(
                                    title=f"Missing {header} on {url}",
                                    severity=info["severity"],
                                    description=info["description"],
                                    data=finding,
                                )

                        # Check for information leakage headers
                        for header, desc in LEAKY_HEADERS.items():
                            if header in headers:
                                value = headers[header]
                                finding = {
                                    "url": url,
                                    "header": header,
                                    "value": value,
                                    "status": "information_disclosure",
                                    "severity": "low",
                                    "description": f"{desc}: {value}",
                                    "recommendation": f"Remove or obscure the {header} header",
                                }
                                results.append(finding)
                                await self.add_finding(
                                    title=f"Info disclosure: {header} on {url}",
                                    severity="low",
                                    description=f"{desc}: {value}",
                                    data=finding,
                                )

                        # Check for insecure cookie flags
                        for cookie_header in resp.headers.getall("Set-Cookie", []):
                            cookie_lower = cookie_header.lower()
                            issues = []
                            if "secure" not in cookie_lower:
                                issues.append("Missing Secure flag")
                            if "httponly" not in cookie_lower:
                                issues.append("Missing HttpOnly flag")
                            if "samesite" not in cookie_lower:
                                issues.append("Missing SameSite attribute")
                            if issues:
                                finding = {
                                    "url": url,
                                    "cookie": cookie_header.split("=")[0],
                                    "issues": issues,
                                    "severity": "medium",
                                }
                                results.append(finding)
                                await self.add_finding(
                                    title=f"Insecure cookie on {url}",
                                    severity="medium",
                                    description=", ".join(issues),
                                    data=finding,
                                )

            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                continue

        return results
