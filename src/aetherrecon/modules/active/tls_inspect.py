"""
TLS Inspection Module
---------------------
Inspects TLS/SSL certificates for security-relevant information:
issuer, validity dates, SANs, protocol versions, weak ciphers.
"""

import asyncio
import ssl
import socket
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from aetherrecon.modules.base import BaseModule


class TLSInspectModule(BaseModule):
    name = "tls_inspect"
    category = "active"
    description = "TLS/SSL certificate and protocol inspection"

    async def run(self, target: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        hosts = [target] + self.context.get("subdomains", [])[:20]
        hosts += self.context.get("ips", [])[:10]  # Include raw IPs for TLS inspection

        sem = asyncio.Semaphore(10)

        async def inspect_host(host: str, port: int = 443):
            async with sem:
                await self.rate_limiter.acquire()
                loop = asyncio.get_event_loop()
                try:
                    result = await loop.run_in_executor(
                        None, self._inspect_tls, host, port,
                    )
                    if result:
                        results.append(result)

                        severity = "info"
                        issues = result.get("issues", [])
                        if any("expired" in i.lower() for i in issues):
                            severity = "high"
                        elif any("self-signed" in i.lower() for i in issues):
                            severity = "medium"
                        elif any("weak" in i.lower() for i in issues):
                            severity = "medium"

                        await self.add_finding(
                            title=f"TLS cert for {host}:{port}",
                            severity=severity,
                            description=f"Issuer: {result.get('issuer', 'N/A')} | "
                                        f"Issues: {len(issues)}",
                            data=result,
                        )
                except Exception:
                    pass

        tasks = [inspect_host(h) for h in hosts]
        await asyncio.gather(*tasks)
        return results

    def _inspect_tls(self, host: str, port: int = 443) -> dict[str, Any] | None:
        """Synchronous TLS inspection (run in executor)."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    protocol = ssock.version()
                    cipher = ssock.cipher()

                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())

                    # Extract Subject Alternative Names
                    sans = []
                    try:
                        ext = cert.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName
                        )
                        sans = ext.value.get_values_for_type(x509.DNSName)
                    except x509.ExtensionNotFound:
                        pass

                    # Check for issues
                    issues = []
                    now = datetime.now(timezone.utc)
                    if cert.not_valid_after_utc < now:
                        issues.append("Certificate EXPIRED")
                    if cert.not_valid_before_utc > now:
                        issues.append("Certificate not yet valid")
                    if (cert.not_valid_after_utc - now).days < 30:
                        issues.append(f"Certificate expires in {(cert.not_valid_after_utc - now).days} days")

                    issuer_cn = ""
                    for attr in cert.issuer:
                        if attr.oid == x509.oid.NameOID.COMMON_NAME:
                            issuer_cn = attr.value

                    subject_cn = ""
                    for attr in cert.subject:
                        if attr.oid == x509.oid.NameOID.COMMON_NAME:
                            subject_cn = attr.value

                    if issuer_cn == subject_cn:
                        issues.append("Self-signed certificate")

                    if protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
                        issues.append(f"Weak protocol: {protocol}")

                    if cipher and "RC4" in cipher[0]:
                        issues.append(f"Weak cipher: {cipher[0]}")

                    return {
                        "host": host,
                        "port": port,
                        "subject_cn": subject_cn,
                        "issuer": issuer_cn,
                        "protocol": protocol,
                        "cipher": cipher[0] if cipher else "",
                        "not_before": cert.not_valid_before_utc.isoformat(),
                        "not_after": cert.not_valid_after_utc.isoformat(),
                        "sans": sans,
                        "serial": str(cert.serial_number),
                        "issues": issues,
                    }

        except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError):
            return None
