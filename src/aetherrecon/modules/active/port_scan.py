"""
Port Scanner Module
-------------------
Async TCP connect scanner for discovering open ports.
Uses asyncio for non-blocking concurrent connections.
"""

import asyncio
from typing import Any

from aetherrecon.modules.base import BaseModule

# Top 100 most common ports (based on nmap frequency data)
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 5901, 8080, 8443, 8888, 27017,
    1433, 1521, 2049, 2082, 2083, 2086, 2087, 3000, 4443, 5000,
    5001, 5432, 5984, 6379, 6443, 7001, 7002, 8000, 8008, 8081,
    8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8181,
    8444, 8880, 8888, 9000, 9090, 9200, 9300, 9443, 10000, 10443,
    27017, 27018, 28017, 50000, 50070, 50075,
]

# Common service banners mapped to ports
PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    993: "imaps", 995: "pop3s", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 27017: "mongodb", 9200: "elasticsearch",
}


class PortScanModule(BaseModule):
    name = "port_scan"
    category = "active"
    description = "Async TCP connect port scanner"

    async def run(self, target: str) -> list[dict[str, Any]]:
        mod_cfg = self.config.get_module_config("port_scan")
        timeout = mod_cfg.get("timeout", 2)
        custom_ports = mod_cfg.get("custom_ports", [])

        # Resolve target once to avoid DNS overhead
        try:
            import socket
            target_ip = socket.gethostbyname(target)
            self.console.print(f"[dim]Resolved {target} to {target_ip}[/dim]")
        except Exception:
            target_ip = target

        # Determine ports to scan
        ports = list(set(TOP_PORTS + custom_ports))
        ports.sort()

        results: list[dict[str, Any]] = []
        sem = asyncio.Semaphore(200)  # High concurrency for port scanning

        async def scan_port(host_label: str, host_ip: str, port: int):
            async with sem:
                await self.rate_limiter.acquire()
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host_ip, port),
                        timeout=timeout,
                    )

                    # Attempt protocol-aware banner grab
                    banner = ""
                    try:
                        # Send a generic probe and an HTTP probe to coax a banner
                        writer.write(b"GET / HTTP/1.0\r\n\r\nHELP\r\n\r\n")
                        await writer.drain()
                        
                        data = await asyncio.wait_for(reader.read(1024), timeout=2)
                        banner = data.decode("utf-8", errors="replace").strip()[:200]
                    except (asyncio.TimeoutError, Exception):
                        pass

                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

                    service = PORT_SERVICES.get(port, "unknown")
                    result = {
                        "host": host_label,
                        "port": port,
                        "state": "open",
                        "service": service,
                        "banner": banner,
                    }
                    results.append(result)

                    scheme = "https" if port in (443, 8443) else "http" if port in (80, 8080) else "unknown"
                    await self.db.add_live_host(self.scan_id, host_label, port, scheme, 200, banner[:50])

                    await self.add_finding(
                        title=f"Open port {port}/{service} on {host_label}",
                        severity="medium" if port in (23, 21, 445, 3389, 5900) else "info",
                        description=f"Banner: {banner}" if banner else "",
                        data=result,
                    )

                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    pass

        # Use naabu if available (Recommended Flow)
        if self.plugin_manager.is_available("naabu"):
            self.console.print("[dim]Using naabu for fast port discovery...[/dim]")
            try:
                # naabu -host target -top-ports 1000 -silent
                args = ["-host", target, "-top-ports", "1000", "-silent"]
                stdout = await self.plugin_manager.run_tool("naabu", args, timeout=300)
                
                for line in stdout.splitlines():
                    if ":" in line:
                        p = int(line.split(":")[-1])
                        results.append({"host": target, "port": p, "state": "open"})
                        await self.add_asset("open_port", f"{target}:{p}")
                return results
            except Exception as e:
                self.console.print(f"[yellow]naabu failed, falling back: {e}[/yellow]")

        # Scan primary target
        tasks = [scan_port(target, target_ip, port) for port in ports]

        # Also scan resolved IPs from context (first 10)
        for ip in self.context.get("ips", [])[:10]:
            for port in [80, 443, 8080, 8443]:
                tasks.append(scan_port(f"ip:{ip}", ip, port))

        # Also scan resolved subdomains from context (first 10)
        for sd in self.context.get("subdomains", [])[:10]:
            for port in [80, 443, 8080, 8443]:
                tasks.append(scan_port(sd, sd, port))

        await asyncio.gather(*tasks)

        await self.add_finding(
            title=f"Port scan summary for {target}",
            severity="info",
            description=f"Found {len(results)} open ports",
            data={"total_scanned": len(ports), "open_count": len(results)},
        )

        return results
