"""
Remediation Intelligence Engine
----------------------------------
Provides actionable fix guidance for every finding type.
Enterprise-grade reports explain WHY it matters and HOW to fix it.
"""

from __future__ import annotations
from typing import Any


# Remediation knowledge base
REMEDIATION_DB: dict[str, dict[str, str]] = {
    "missing_hsts": {
        "title": "Missing HSTS Header",
        "impact": "Users can be downgraded to HTTP, enabling MITM attacks and credential theft.",
        "fix": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    },
    "missing_csp": {
        "title": "Missing Content-Security-Policy",
        "impact": "XSS attacks are harder to mitigate without CSP boundaries.",
        "fix": "Implement a Content-Security-Policy header. Start with: default-src 'self'",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    },
    "exposed_env": {
        "title": "Exposed .env File",
        "impact": "Environment variables often contain database credentials, API keys, and secrets.",
        "fix": "1. Block .env in web server config\n2. Rotate all exposed credentials\n3. Add .env to .gitignore",
        "reference": "https://owasp.org/www-community/Sensitive_Data_Exposure",
    },
    "exposed_git": {
        "title": "Exposed Git Repository",
        "impact": "Full source code can be downloaded, revealing business logic, secrets, and vulnerabilities.",
        "fix": "1. Block /.git/ in web server config\n2. Audit for leaked secrets\n3. Rotate any exposed credentials",
        "reference": "https://owasp.org/www-community/Sensitive_Data_Exposure",
    },
    "database_exposed": {
        "title": "Database Service Exposed to Internet",
        "impact": "Direct database access enables data theft, modification, and denial of service.",
        "fix": "1. Restrict database port to internal networks\n2. Use firewall rules\n3. Enable authentication\n4. Use TLS for connections",
        "reference": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },
    "wordpress_outdated": {
        "title": "Outdated WordPress Installation",
        "impact": "Known vulnerabilities in older WordPress versions enable site takeover.",
        "fix": "1. Update WordPress to latest version\n2. Update all plugins/themes\n3. Enable auto-updates",
        "reference": "https://wordpress.org/documentation/article/updating-wordpress/",
    },
    "graphql_introspection": {
        "title": "GraphQL Introspection Enabled",
        "impact": "Attackers can enumerate your entire API schema, discovering hidden endpoints and data types.",
        "fix": "Disable introspection in production: set introspection: false in GraphQL config",
        "reference": "https://www.apollographql.com/blog/graphql/security/why-you-should-disable-graphql-introspection-in-production/",
    },
    "expired_cert": {
        "title": "Expired TLS Certificate",
        "impact": "Users see security warnings, lose trust. Expired certs cannot verify identity.",
        "fix": "1. Renew the certificate immediately\n2. Set up auto-renewal\n3. Monitor cert expiry dates",
        "reference": "https://letsencrypt.org/",
    },
    "self_signed_cert": {
        "title": "Self-Signed TLS Certificate",
        "impact": "No trust chain — susceptible to MITM attacks. Users see browser warnings.",
        "fix": "Replace with a certificate from a trusted CA (e.g., Let's Encrypt — free)",
        "reference": "https://letsencrypt.org/",
    },
    "exposed_admin": {
        "title": "Admin Panel Publicly Accessible",
        "impact": "Brute force, credential stuffing, and targeted attacks against admin interfaces.",
        "fix": "1. Restrict admin access by IP\n2. Enable MFA\n3. Use strong passwords\n4. Consider VPN-only access",
        "reference": "https://owasp.org/www-community/Broken_Authentication",
    },
    "exposed_api_key": {
        "title": "API Key Exposed in Source",
        "impact": "API key abuse, unauthorized access, data theft, and unexpected billing charges.",
        "fix": "1. Rotate the exposed key immediately\n2. Use environment variables\n3. Implement key restrictions",
        "reference": "https://owasp.org/www-community/Sensitive_Data_Exposure",
    },
    "insecure_cookies": {
        "title": "Insecure Cookie Configuration",
        "impact": "Session hijacking via XSS (missing HttpOnly) or network interception (missing Secure).",
        "fix": "Set cookie flags: Secure; HttpOnly; SameSite=Strict",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
    },
    "server_info_disclosure": {
        "title": "Server Version Information Disclosure",
        "impact": "Reveals exact server software and version, enabling targeted exploit searches.",
        "fix": "Remove or obfuscate Server and X-Powered-By headers in web server configuration.",
        "reference": "https://owasp.org/www-community/Security_Misconfiguration",
    },
    "default_page": {
        "title": "Default Installation Page Exposed",
        "impact": "Indicates incomplete setup or oversight. May reveal server software details.",
        "fix": "Replace default pages with proper content or remove them entirely.",
        "reference": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },
    "debug_mode": {
        "title": "Debug Mode Enabled in Production",
        "impact": "Stack traces, source paths, and internal variables exposed to attackers.",
        "fix": "Disable debug mode in production. Set DEBUG=False (Django) or equivalent.",
        "reference": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    },
    "open_redirect": {
        "title": "Open Redirect Vulnerability",
        "impact": "Phishing attacks using trusted domain URL redirection.",
        "fix": "Validate and whitelist redirect destinations. Never use user input directly.",
        "reference": "https://owasp.org/www-community/attacks/Open_redirect",
    },
    "cors_misconfigured": {
        "title": "CORS Misconfiguration",
        "impact": "Cross-origin data theft if wildcard or overly permissive CORS headers used.",
        "fix": "Restrict Access-Control-Allow-Origin to specific trusted domains.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
    },
}


class RemediationEngine:
    """
    Provides detailed, actionable remediation guidance for findings.
    
    For each finding:
    - Why it matters (real-world impact)
    - Exact fix steps
    - Configuration guidance
    - Reference links
    """

    def __init__(self):
        self._custom_remediations: dict[str, dict[str, str]] = {}

    def get_remediation(self, finding_type: str) -> dict[str, str]:
        """Get remediation guidance for a finding type."""
        # Check custom remediations first
        if finding_type in self._custom_remediations:
            return self._custom_remediations[finding_type]
        return REMEDIATION_DB.get(finding_type, {
            "title": finding_type.replace("_", " ").title(),
            "impact": "Review and assess the potential impact of this finding.",
            "fix": "Investigate and apply appropriate security controls.",
            "reference": "https://owasp.org/",
        })

    def enrich_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Enrich a finding with remediation intelligence."""
        finding_type = self._classify_finding(finding)
        remediation = self.get_remediation(finding_type)
        finding["remediation"] = remediation
        return finding

    def enrich_all(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Enrich all findings with remediation guidance."""
        return [self.enrich_finding(f) for f in findings]

    def add_custom_remediation(self, finding_type: str, title: str,
                                impact: str, fix: str, reference: str = ""):
        """Register a custom remediation entry."""
        self._custom_remediations[finding_type] = {
            "title": title, "impact": impact,
            "fix": fix, "reference": reference,
        }

    @staticmethod
    def _classify_finding(finding: dict[str, Any]) -> str:
        """Map a finding to its remediation type."""
        title = finding.get("title", "").lower()
        header = finding.get("header", "").lower()
        path = finding.get("path", "").lower()

        # Header-based classification
        if "strict-transport" in header or "hsts" in title:
            return "missing_hsts"
        if "content-security" in header or "csp" in title:
            return "missing_csp"
        if "cookie" in title:
            return "insecure_cookies"
        if "server" in header and "disclosure" in title:
            return "server_info_disclosure"

        # Path-based classification
        if ".env" in path:
            return "exposed_env"
        if ".git" in path:
            return "exposed_git"
        if "admin" in path or "admin" in title:
            return "exposed_admin"

        # Content-based classification
        if "graphql" in title:
            return "graphql_introspection"
        if "database" in title and "exposed" in title:
            return "database_exposed"
        if "wordpress" in title and ("outdated" in title or "version" in title):
            return "wordpress_outdated"
        if "expired" in title and "cert" in title:
            return "expired_cert"
        if "self-signed" in title:
            return "self_signed_cert"
        if "api" in title and "key" in title:
            return "exposed_api_key"
        if "debug" in title:
            return "debug_mode"
        if "redirect" in title:
            return "open_redirect"
        if "cors" in title:
            return "cors_misconfigured"

        return "general"
