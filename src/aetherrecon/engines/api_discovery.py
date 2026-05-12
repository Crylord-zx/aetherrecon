"""
API Discovery Engine
---------------------
Discovers and analyzes API surfaces including GraphQL, REST,
Swagger/OpenAPI, Postman collections, and hidden API routes.

Extracts endpoints from JavaScript files and response bodies.
"""

from __future__ import annotations
import re
import asyncio
from typing import Any
from urllib.parse import urljoin, urlparse

import aiohttp

from aetherrecon.modules.base import BaseModule


# Common API paths to check
API_DISCOVERY_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql", "/playground",
    "/swagger", "/swagger.json", "/swagger.yaml",
    "/swagger/v1/swagger.json", "/swagger-ui.html",
    "/openapi.json", "/openapi.yaml", "/api-docs",
    "/docs", "/redoc", "/_api",
    "/rest", "/rest/api", "/rest/v1",
    "/api/health", "/api/status", "/api/version",
    "/api/debug", "/api/config",
    "/.well-known/openapi.json",
    "/postman", "/collection.json",
]

# GraphQL introspection query
GRAPHQL_INTROSPECTION = '{"query":"{ __schema { types { name } } }"}'

# Patterns for extracting API endpoints from JavaScript
JS_API_PATTERNS = [
    re.compile(r'["\'](?:https?://[^"\']+/api/[^"\']*)["\']', re.I),
    re.compile(r'["\'](?:/api/[v]?\d*/?\w+)["\']', re.I),
    re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'\.get\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'\.post\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'XMLHttpRequest.*?open\s*\([^,]+,\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'url:\s*["\']([^"\']+/api/[^"\']*)["\']', re.I),
]

# Patterns for tokens/secrets in JS
JS_SECRET_PATTERNS = [
    re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']{8,})["\']', re.I),
    re.compile(r'(?:auth[_-]?token|bearer)\s*[:=]\s*["\']([^"\']{8,})["\']', re.I),
    re.compile(r'(?:secret|password|passwd)\s*[:=]\s*["\']([^"\']{4,})["\']', re.I),
    re.compile(r'(?:aws[_-]?access[_-]?key)\s*[:=]\s*["\']([A-Z0-9]{20})["\']', re.I),
    re.compile(r'(?:firebase[_-]?config|firebaseConfig).*?apiKey\s*:\s*["\']([^"\']+)["\']', re.I | re.S),
]


class APIDiscoveryModule(BaseModule):
    """
    Discovers API surfaces on the target.
    
    Checks for:
    - REST API endpoints
    - GraphQL endpoints (with introspection)
    - Swagger/OpenAPI documentation
    - Hidden API routes
    - JS-extracted endpoints
    """
    name = "api_discovery"
    category = "discovery"
    description = "API surface discovery and analysis"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        # Build base URLs from http_services or target
        base_urls = set()
        for svc in self.context.get("http_services", []):
            if isinstance(svc, dict):
                base_urls.add(svc.get("url", ""))
        if not base_urls:
            base_urls = {f"https://{target}", f"http://{target}"}

        for base_url in list(base_urls)[:5]:
            if not base_url:
                continue

            # Phase 1: Probe known API paths
            api_findings = await self._probe_api_paths(base_url)
            results.extend(api_findings)

            # Phase 2: GraphQL detection
            gql_findings = await self._detect_graphql(base_url)
            results.extend(gql_findings)

            # Phase 3: Extract endpoints from JS files
            js_findings = await self._extract_from_js(base_url)
            results.extend(js_findings)

        # Store in context for other modules
        self.context.setdefault("api_endpoints", []).extend(results)

        return results

    async def _probe_api_paths(self, base_url: str) -> list[dict]:
        """Probe common API paths."""
        findings = []
        for path in API_DISCOVERY_PATHS:
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
                        if resp.status in (200, 201, 301, 302, 401, 403):
                            content_type = resp.headers.get("Content-Type", "")
                            finding = {
                                "type": "api_endpoint",
                                "url": url,
                                "status": resp.status,
                                "content_type": content_type,
                                "path": path,
                            }

                            # Swagger/OpenAPI found
                            if "swagger" in path.lower() or "openapi" in path.lower():
                                finding["type"] = "api_documentation"
                                finding["severity"] = "medium"
                                await self.add_finding(
                                    title=f"API Documentation Exposed: {url}",
                                    severity="medium",
                                    description=f"API documentation accessible at {url}",
                                    data=finding,
                                )

                            findings.append(finding)
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                continue
        return findings

    async def _detect_graphql(self, base_url: str) -> list[dict]:
        """Detect and probe GraphQL endpoints."""
        findings = []
        gql_paths = ["/graphql", "/graphiql", "/playground", "/api/graphql", "/gql"]

        for path in gql_paths:
            await self.rate_limiter.acquire()
            url = urljoin(base_url, path)
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url, ssl=False,
                        data=GRAPHQL_INTROSPECTION,
                        headers={
                            "Content-Type": "application/json",
                            "User-Agent": "AetherRecon/2.0",
                        },
                        timeout=aiohttp.ClientTimeout(total=8),
                    ) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            if "__schema" in body or "types" in body:
                                finding = {
                                    "type": "graphql_endpoint",
                                    "url": url,
                                    "introspection_enabled": "__schema" in body,
                                    "severity": "high" if "__schema" in body else "medium",
                                }
                                findings.append(finding)
                                await self.add_finding(
                                    title=f"GraphQL Endpoint with Introspection: {url}",
                                    severity="high",
                                    description="GraphQL introspection is enabled, exposing schema",
                                    data=finding,
                                )
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                continue
        return findings

    async def _extract_from_js(self, base_url: str) -> list[dict]:
        """Extract API endpoints and secrets from JavaScript files."""
        findings = []
        js_urls = self.context.get("js_files", [])

        # Also try common JS paths
        common_js = [
            "/static/js/main.js", "/static/js/app.js",
            "/bundle.js", "/app.js", "/main.js",
            "/_next/static/chunks/main.js",
            "/assets/js/app.js",
        ]

        for js_path in common_js:
            js_urls.append(urljoin(base_url, js_path))

        for js_url in list(set(js_urls))[:20]:
            await self.rate_limiter.acquire()
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        js_url, ssl=False,
                        timeout=aiohttp.ClientTimeout(total=10),
                        headers={"User-Agent": "AetherRecon/2.0"},
                    ) as resp:
                        if resp.status == 200 and "javascript" in resp.headers.get("Content-Type", ""):
                            body = await resp.text()

                            # Extract API endpoints
                            for pattern in JS_API_PATTERNS:
                                matches = pattern.findall(body)
                                for match in matches[:10]:
                                    findings.append({
                                        "type": "js_extracted_endpoint",
                                        "endpoint": match,
                                        "source": js_url,
                                    })

                            # Extract secrets
                            for pattern in JS_SECRET_PATTERNS:
                                matches = pattern.findall(body)
                                for match in matches[:5]:
                                    masked = match[:4] + "****" + match[-4:] if len(match) > 8 else "****"
                                    findings.append({
                                        "type": "js_exposed_secret",
                                        "secret_type": "api_key",
                                        "masked_value": masked,
                                        "source": js_url,
                                        "severity": "high",
                                    })
                                    await self.add_finding(
                                        title=f"Secret Exposed in JavaScript: {js_url}",
                                        severity="high",
                                        description=f"Potential API key or secret found in JS file",
                                        data={"source": js_url, "masked": masked},
                                    )
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                continue
        return findings
