"""
Plugin Manager
--------------
Discovers external tools on the system and manages plugin loading.
"""

import shutil
import subprocess
import asyncio
import os
import importlib.util
from pathlib import Path
from typing import Any

from aetherrecon.core.config import AetherConfig

# Tools that AetherRecon can integrate with when installed
SUPPORTED_TOOLS = [
    "subfinder", "amass", "httpx", "nuclei", "naabu",
    "katana", "dnsx", "ffuf", "assetfinder", "gau",
    "waybackurls", "nikto", "whatweb", "wpscan",
    "feroxbuster", "theharvester", "gowitness", "cmseek",
    "nmap", "rustscan", "testssl", "dalfox", "sqlmap",
    "commix", "trufflehog", "gitleaks", "eyewitness",
    "paramspider", "arjun"
]


class PluginManager:
    def __init__(self, config: AetherConfig):
        self.config = config
        self._tool_paths: dict[str, str | None] = {}
        self._plugins: dict[str, Any] = {}

    def check_tools(self) -> dict[str, str | None]:
        """Check which external tools are available on the system."""
        tool_overrides = self.config.data.get("tools", {})
        for tool in SUPPORTED_TOOLS:
            override = tool_overrides.get(tool, "")
            if override and Path(override).exists():
                self._tool_paths[tool] = override
            else:
                path = shutil.which(tool)
                if not path and tool == "httpx":
                    path = shutil.which("httpx-toolkit")
                if not path and tool == "testssl":
                    path = shutil.which("testssl.sh")
                
                # Explicit fallback for Go tools if ~/go/bin isn't in PATH
                if not path:
                    go_bin_path = os.path.expanduser(f"~/go/bin/{tool}")
                    if os.path.exists(go_bin_path) and os.access(go_bin_path, os.X_OK):
                        path = go_bin_path

                self._tool_paths[tool] = path
        return self._tool_paths

    def is_available(self, tool_name: str) -> bool:
        if not self._tool_paths:
            self.check_tools()
        return bool(self._tool_paths.get(tool_name))

    def get_tool_path(self, tool_name: str) -> str | None:
        if not self._tool_paths:
            self.check_tools()
        return self._tool_paths.get(tool_name)

    async def run_tool(self, tool_name: str, args: list[str], timeout: int = 300) -> str:
        """Run an external tool and return its stdout output."""
        path = self.get_tool_path(tool_name)
        if not path:
            raise FileNotFoundError(f"Tool '{tool_name}' not found on system.")

        proc = await asyncio.create_subprocess_exec(
            path, *args,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            return stdout.decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            raise asyncio.TimeoutError(f"Tool '{tool_name}' timed out after {timeout}s")
        except Exception as e:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            raise e

    def load_plugins(self, plugin_dir: str | Path = "plugins"):
        """Load Python plugin files from the plugins directory."""
        plugin_path = Path(plugin_dir)
        if not plugin_path.exists():
            return

        for py_file in plugin_path.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                if hasattr(module, "register"):
                    plugin_info = module.register()
                    self._plugins[py_file.stem] = plugin_info
            except Exception as e:
                pass  # Skip broken plugins silently

    def get_plugins(self) -> dict[str, Any]:
        return self._plugins
