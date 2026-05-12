"""
Tool Installer Manager
----------------------
Handles the automatic detection and installation of required external tools
for the Kali Linux environment.
"""

import asyncio
import os
import shutil
import subprocess
from typing import Callable

from rich.console import Console

KALI_APT_TOOLS = [
    "subfinder", "amass", "assetfinder", "theharvester",
    "httpx-toolkit", "nuclei", "ffuf", "nikto",
    "whatweb", "wpscan", "feroxbuster", "gowitness", "cmseek",
    "nmap", "rustscan", "testssl.sh", "sqlmap", "commix",
    "trufflehog", "gitleaks", "eyewitness", "arjun", "paramspider"
]

GO_TOOLS = {
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "dalfox": "github.com/hahwul/dalfox/v2@latest",
}

class ToolInstaller:
    def __init__(self, console: Console | None = None):
        self.console = console or Console()

    async def run_cmd(self, cmd: list[str], log_cb: Callable[[str], None] | None = None) -> bool:
        """Run a command asynchronously and log output."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            if log_cb and proc.stdout:
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    log_cb(line.decode("utf-8", errors="replace").strip())

            await proc.wait()
            return proc.returncode == 0
        except Exception as e:
            if log_cb:
                log_cb(f"Error executing {cmd[0]}: {e}")
            return False

    async def install_all(self, log_cb: Callable[[str], None] | None = None) -> dict[str, bool]:
        """Attempt to install all missing tools via APT and Go."""
        results = {}
        
        if log_cb:
            log_cb("[bold cyan]Updating APT package lists...[/]")
            
        success = await self.run_cmd(["sudo", "-n", "apt", "update"], log_cb)
        if not success and log_cb:
            log_cb("[yellow]Warning: sudo requires password or apt update failed.[/]")

        # Install APT tools
        for tool in KALI_APT_TOOLS:
            # Map package names to binary names for checking existence
            binary_name = tool
            if tool == "httpx-toolkit": binary_name = "httpx"
            if tool == "testssl.sh": binary_name = "testssl"
            if tool == "arjun": binary_name = "arjun"

            if shutil.which(binary_name):
                results[tool] = True
                if log_cb: log_cb(f"[green]✓ {binary_name} is already installed[/]")
                continue

            if log_cb: log_cb(f"Installing {tool} via apt...")
            success = await self.run_cmd(["sudo", "-n", "apt", "install", "-y", tool], log_cb)
            
            # Special fallback for rustscan if apt fails
            if tool == "rustscan" and not success:
                if log_cb: log_cb("[yellow]APT failed for rustscan. Attempting direct download from GitHub...[/]")
                deb_url = "https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb"
                deb_file = "rustscan_2.0.1_amd64.deb"
                
                await self.run_cmd(["wget", "-q", deb_url], log_cb)
                if os.path.exists(deb_file):
                    success = await self.run_cmd(["sudo", "-n", "dpkg", "-i", deb_file], log_cb)
                    if success:
                        if log_cb: log_cb("[green]✓ RustScan installed via GitHub .deb[/]")
                    os.remove(deb_file)
            
            results[tool] = success

        # Ensure Go is installed
        if not shutil.which("go"):
            if log_cb: log_cb("[bold red]✗ Go is not installed. Cannot install Go tools.[/]")
            for tool in GO_TOOLS.keys():
                if not shutil.which(tool):
                    results[tool] = False
            return results

        # Install Go tools
        for tool, repo in GO_TOOLS.items():
            # Check GOPATH/bin and standard paths
            go_bin = os.path.expanduser("~/go/bin")
            tool_path = shutil.which(tool) or (os.path.exists(f"{go_bin}/{tool}") and f"{go_bin}/{tool}")
            
            if tool_path:
                results[tool] = True
                if log_cb: log_cb(f"[green]✓ {tool} is already installed[/]")
                continue

            if log_cb: log_cb(f"Installing {tool} via go install...")
            success = await self.run_cmd(["go", "install", repo], log_cb)
            results[tool] = success

        return results
