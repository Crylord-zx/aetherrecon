"""
Example Plugin — Custom Header Checker
---------------------------------------
Demonstrates the AetherRecon plugin system.

Plugins are Python files in the `plugins/` directory with a `register()` function
that returns plugin metadata and a module class inheriting from BaseModule.

Usage:
    Place this file in the `plugins/` directory.
    It will be auto-loaded by the PluginManager.
"""

from aetherrecon.modules.base import BaseModule


class CustomHeaderChecker(BaseModule):
    """Example plugin that checks for a custom security header."""

    name = "custom_header_check"
    category = "vuln"
    description = "Checks for organization-specific security headers"

    async def run(self, target: str) -> list[dict]:
        import aiohttp

        results = []
        url = f"https://{target}"

        await self.rate_limiter.acquire()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    headers = dict(resp.headers)

                    # Example: Check for custom headers your org requires
                    custom_headers = {
                        "X-Request-ID": "Request tracing header",
                        "X-Content-Type-Options": "MIME type sniffing prevention",
                    }

                    for header, desc in custom_headers.items():
                        present = header in headers
                        result = {
                            "url": url,
                            "header": header,
                            "present": present,
                            "value": headers.get(header, "N/A"),
                            "description": desc,
                        }
                        results.append(result)

                        if not present:
                            await self.add_finding(
                                title=f"Missing custom header: {header}",
                                severity="low",
                                description=f"{desc} not found on {url}",
                                data=result,
                            )

        except Exception as e:
            results.append({"error": str(e)})

        return results


def register():
    """
    Plugin registration function — required by the plugin system.

    Returns:
        dict with 'name', 'description', 'module_class', and 'version'.
    """
    return {
        "name": "custom_header_check",
        "description": "Checks for organization-specific custom security headers",
        "module_class": CustomHeaderChecker,
        "version": "1.0.0",
        "author": "AetherRecon Community",
    }
