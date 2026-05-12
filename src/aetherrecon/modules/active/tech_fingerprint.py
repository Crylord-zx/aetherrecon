"""
Technology Fingerprinting Module
---------------------------------
Identifies web technologies by analyzing HTTP headers, HTML meta tags,
cookies, and JavaScript references. Uses a built-in signature database.
"""

import asyncio
import re
from typing import Any

import aiohttp
from bs4 import BeautifulSoup

from aetherrecon.modules.base import BaseModule

# Built-in technology signatures (inspired by Wappalyzer patterns)
TECH_SIGNATURES = {
    "nginx": {"headers": {"Server": r"nginx"}},
    "Apache": {"headers": {"Server": r"Apache"}},
    "IIS": {"headers": {"Server": r"Microsoft-IIS"}},
    "CloudFlare": {"headers": {"Server": r"cloudflare"}, "cookies": ["__cfduid", "cf_clearance"]},
    "PHP": {"headers": {"X-Powered-By": r"PHP"}, "cookies": ["PHPSESSID"]},
    "ASP.NET": {"headers": {"X-Powered-By": r"ASP\.NET"}, "cookies": ["ASP.NET_SessionId"]},
    "Express.js": {"headers": {"X-Powered-By": r"Express"}},
    "Django": {"cookies": ["csrftoken", "sessionid"], "meta": {"csrf-token": r".*"}},
    "WordPress": {"html": [r"wp-content", r"wp-includes", r"wp-json"]},
    "Drupal": {"html": [r"Drupal", r"sites/default/files"], "headers": {"X-Generator": r"Drupal"}},
    "Joomla": {"html": [r"Joomla", r"/media/jui/"], "meta": {"generator": r"Joomla"}},
    "React": {"html": [r"react\.production\.min\.js", r"__NEXT_DATA__", r"_react"]},
    "Vue.js": {"html": [r"vue\.runtime", r"v-app", r"data-v-"]},
    "Angular": {"html": [r"ng-version", r"angular\.js", r"ng-app"]},
    "jQuery": {"html": [r"jquery[\.-]", r"jquery\.min\.js"]},
    "Bootstrap": {"html": [r"bootstrap\.min\.(css|js)", r"bootstrap\.bundle"]},
    "Tailwind": {"html": [r"tailwindcss", r"tailwind\.min\.css"]},
    "Laravel": {"cookies": ["laravel_session"], "headers": {"X-Powered-By": r"Laravel"}},
    "Spring": {"headers": {"X-Application-Context": r".*"}},
    "Varnish": {"headers": {"Via": r"varnish", "X-Varnish": r".*"}},
    "Nginx-Proxy": {"headers": {"X-Nginx-Proxy": r".*"}},
    "AWS ALB": {"headers": {"Server": r"awselb"}},
    "Google Cloud": {"headers": {"Via": r"google"}},
}


class TechFingerprintModule(BaseModule):
    name = "tech_fingerprint"
    category = "active"
    description = "Web technology stack fingerprinting"

    async def run(self, target: str) -> list[dict[str, Any]]:
        http_services = self.context.get("http_services", [])

        # If no HTTP services found yet, try common URLs
        if not http_services:
            http_services = [
                {"url": f"https://{target}", "host": target},
                {"url": f"http://{target}", "host": target},
            ]

        results: list[dict[str, Any]] = []
        seen_techs: set[str] = set()

        for svc in http_services[:20]:  # Limit to avoid overload
            url = svc.get("url", f"https://{svc.get('host', target)}")
            await self.rate_limiter.acquire()

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url, ssl=False,
                        timeout=aiohttp.ClientTimeout(total=10),
                        headers={"User-Agent": "AetherRecon/1.0"},
                    ) as resp:
                        body = await resp.text(errors="replace")
                        headers = dict(resp.headers)
                        cookies = {c.key: c.value for c in resp.cookies.values()}

                        detected = self._fingerprint(headers, body, cookies)

                        for tech in detected:
                            key = f"{url}:{tech['name']}"
                            if key not in seen_techs:
                                seen_techs.add(key)
                                tech["url"] = url
                                results.append(tech)

            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                continue

        # ── Deep WordPress Verification ─────────────────────────────────────
        if any(t["name"] == "WordPress" for t in results):
            for svc in http_services[:3]:
                url = svc.get("url", "")
                if not url: continue
                
                # Probing specific WP paths for version and confirmation
                for path in ["/wp-json/wp/v2/users", "/readme.html"]:
                    await self.rate_limiter.acquire()
                    try:
                        async with aiohttp.ClientSession() as session:
                            async with session.get(f"{url.rstrip('/')}{path}", ssl=False, timeout=5) as wp_resp:
                                if wp_resp.status == 200:
                                    results.append({
                                        "name": "WordPress", 
                                        "match_type": f"deep_probe:{path}",
                                        "url": url,
                                        "confidence": "high"
                                    })
                                    # Extract version from readme if possible
                                    if "readme.html" in path:
                                        body = await wp_resp.text()
                                        ver_match = re.search(r"Version (\d+\.\d+(\.\d+)?)", body)
                                        if ver_match:
                                            results[-1]["version"] = ver_match.group(1)
                    except Exception:
                        pass

        for tech in results:
            await self.add_finding(
                title=f"Technology: {tech['name']} on {tech.get('url', target)}",
                severity="info",
                description=f"Detected via {tech['match_type']}",
                data=tech,
            )

        return results

    def _fingerprint(self, headers: dict, body: str, cookies: dict) -> list[dict]:
        """Match response against technology signatures."""
        detected = []
        body_lower = body[:50000].lower()

        for tech_name, sigs in TECH_SIGNATURES.items():
            matched = False
            match_type = ""

            # Check headers
            if "headers" in sigs:
                for h_name, pattern in sigs["headers"].items():
                    h_val = headers.get(h_name, "")
                    if re.search(pattern, h_val, re.IGNORECASE):
                        matched = True
                        match_type = f"header:{h_name}"
                        break

            # Check cookies
            if not matched and "cookies" in sigs:
                for cookie_name in sigs["cookies"]:
                    if cookie_name in cookies:
                        matched = True
                        match_type = f"cookie:{cookie_name}"
                        break

            # Check HTML content
            if not matched and "html" in sigs:
                for pattern in sigs["html"]:
                    if re.search(pattern, body_lower, re.IGNORECASE):
                        matched = True
                        match_type = f"html_pattern"
                        break

            # Check meta tags
            if not matched and "meta" in sigs:
                for meta_name, pattern in sigs["meta"].items():
                    meta_match = re.search(
                        rf'<meta[^>]*name=["\']?{meta_name}["\']?[^>]*content=["\']?([^"\']*)',
                        body_lower,
                    )
                    if meta_match:
                        matched = True
                        match_type = f"meta:{meta_name}"
                        break

            if matched:
                detected.append({"name": tech_name, "match_type": match_type})

        return detected
