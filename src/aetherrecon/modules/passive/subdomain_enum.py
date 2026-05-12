"""
Subdomain Enumeration Module
-----------------------------
Discovers subdomains using DNS brute-forcing with a built-in wordlist
and resolves them using configured DNS servers.
"""

import asyncio
from typing import Any

import dns.asyncresolver
import dns.resolver

from aetherrecon.modules.base import BaseModule

# Built-in compact wordlist for subdomain brute-forcing
BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "dns", "dns1", "dns2",
    "webmail", "admin", "portal", "vpn", "api", "dev", "staging", "test",
    "beta", "demo", "app", "m", "mobile", "blog", "shop", "store", "secure",
    "login", "auth", "sso", "cdn", "static", "assets", "media", "img",
    "images", "docs", "wiki", "help", "support", "status", "monitor",
    "grafana", "prometheus", "kibana", "elastic", "jenkins", "gitlab",
    "git", "ci", "cd", "deploy", "build", "stage", "prod", "production",
    "internal", "intranet", "extranet", "remote", "proxy", "gateway",
    "firewall", "backup", "db", "database", "mysql", "postgres", "redis",
    "mongo", "elastic", "search", "solr", "mq", "queue", "rabbitmq",
    "kafka", "zookeeper", "consul", "vault", "k8s", "kubernetes", "docker",
    "registry", "harbor", "nexus", "artifactory", "jira", "confluence",
    "slack", "teams", "chat", "crm", "erp", "hr", "billing", "pay",
    "payment", "checkout", "cart", "order", "track", "analytics", "stats",
    "reports", "dashboard", "panel", "cpanel", "whm", "plesk", "webmin",
    "phpmyadmin", "adminer", "mailgun", "sendgrid", "aws", "cloud",
    "s3", "storage", "files", "download", "upload", "share", "drive",
]


class SubdomainEnumModule(BaseModule):
    name = "subdomain_enum"
    category = "passive"
    description = "DNS-based subdomain enumeration"

    async def run(self, target: str) -> list[dict[str, Any]]:
        mod_cfg = self.config.get_module_config("subdomain_enum")
        resolvers = mod_cfg.get("resolvers", ["8.8.8.8", "1.1.1.1"])
        concurrent = mod_cfg.get("concurrent_resolves", 50)

        # --- Multi-Tool Passive Aggregator (Recommended Flow) ---
        found_subs = set()
        
        # 1. Subfinder
        if self.plugin_manager.is_available("subfinder"):
            try:
                self.console.print("[dim]Running subfinder...[/dim]")
                out = await self.plugin_manager.run_tool("subfinder", ["-d", target, "-silent"])
                for s in out.splitlines(): found_subs.add(s.strip())
            except Exception: pass

        # 2. Amass (Passive)
        if self.plugin_manager.is_available("amass"):
            try:
                self.console.print("[dim]Running amass (passive)...[/dim]")
                out = await self.plugin_manager.run_tool("amass", ["enum", "-passive", "-d", target])
                for s in out.splitlines(): found_subs.add(s.strip())
            except Exception: pass

        # 3. Assetfinder
        if self.plugin_manager.is_available("assetfinder"):
            try:
                self.console.print("[dim]Running assetfinder...[/dim]")
                out = await self.plugin_manager.run_tool("assetfinder", ["--subs-only", target])
                for s in out.splitlines(): found_subs.add(s.strip())
            except Exception: pass

        if found_subs:
            results = []
            for s in found_subs:
                results.append({"subdomain": s, "source": "aggregator"})
                await self.add_subdomain(s, "unknown", "passive_aggregator")
            return results

        # --- dnsx Fallback (if passive tools fail) ---
        if self.plugin_manager.is_available("dnsx"):
            self.console.print("[dim]Using dnsx for ultra-fast subdomain resolution...[/dim]")
            try:
                # dnsx -d target -silent -retry 3
                args = ["-d", target, "-silent", "-retry", "3"]
                wordlist_path = mod_cfg.get("wordlist", "")
                if wordlist_path: args.extend(["-w", wordlist_path])
                
                stdout = await self.plugin_manager.run_tool("dnsx", args, timeout=600)
                results = []
                for line in stdout.splitlines():
                    results.append({"subdomain": line.strip(), "source": "dnsx"})
                    await self.add_subdomain(line.strip(), "resolved", "dnsx")
                return results
            except Exception as e:
                self.console.print(f"[yellow]dnsx failed, falling back: {e}[/yellow]")

        # Configure resolver
        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = resolvers
        resolver.timeout = 3
        resolver.lifetime = 5

        # ── Wildcard Detection ──────────────────────────────────────────────
        # Check if a non-existent random subdomain resolves
        wildcard_ips = set()
        try:
            import random
            import string
            rand_sub = "".join(random.choices(string.ascii_lowercase, k=15))
            answers = await resolver.resolve(f"{rand_sub}.{target}", "A")
            wildcard_ips = {rdata.to_text() for rdata in answers}
            await self.add_finding("Wildcard DNS Detected", "info", 
                                  f"Wildcard resolution detected to: {list(wildcard_ips)}")
        except Exception:
            pass # No wildcard

        # Load wordlist or use built-in
        wordlist_path = mod_cfg.get("wordlist", "")
        if wordlist_path:
            try:
                with open(wordlist_path, "r") as f:
                    words = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                words = BUILTIN_WORDLIST
        else:
            words = BUILTIN_WORDLIST

        # Also include subdomains from shared context (e.g., from CT logs)
        existing = set()
        for sd in self.context.get("subdomains", []):
            if sd:
                existing.add(sd)

        results: list[dict[str, Any]] = []
        found: set[str] = set()

        # Semaphore to limit concurrency
        sem = asyncio.Semaphore(concurrent)

        async def resolve_subdomain(word: str):
            fqdn = f"{word}.{target}"
            if fqdn in found or fqdn in existing:
                return

            async with sem:
                await self.rate_limiter.acquire()
                try:
                    answers = await resolver.resolve(fqdn, "A")
                    ips = [rdata.to_text() for rdata in answers]
                    
                    # Ignore if it matches wildcard IPs
                    if wildcard_ips and any(ip in wildcard_ips for ip in ips):
                        return

                    if ips:
                        found.add(fqdn)
                        record = {"subdomain": fqdn, "ips": ips, "source": "dns_bruteforce"}
                        results.append(record)
                        await self.add_subdomain(fqdn, ips[0], "dns_bruteforce")
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                        dns.resolver.NoNameservers, asyncio.TimeoutError):
                    pass
                except Exception:
                    pass

        # Run all lookups concurrently with semaphore limiting
        tasks = [resolve_subdomain(word) for word in words]
        await asyncio.gather(*tasks)

        await self.add_finding(
            title=f"Subdomain enumeration for {target}",
            severity="info",
            description=f"Found {len(results)} subdomains via DNS brute-force",
            data={"count": len(results), "subdomains": [r["subdomain"] for r in results]},
        )

        return results
