"""
Agentic Workflow Planner v2.0
-------------------------------
AI-guided scan escalation with technology-aware decision making,
progressive evidence-based escalation, and intelligent chaining.

Prioritize:
- Evidence-backed findings
- Version validation
- Technology-aware analysis
- Adaptive crawling
- Contextual risk scoring
- Low false positives

Never:
- Trust banners blindly
- Map generic CVEs without validation
- Overload fragile systems
- Classify informational findings as critical
"""

import re
from typing import Any
from datetime import datetime, timezone

from aetherrecon.core.config import AetherConfig


class ScanDecision:
    """Represents a decision the agent has made."""

    def __init__(self, action: str, reason: str, priority: int = 5, data: dict | None = None):
        self.action = action
        self.reason = reason
        self.priority = priority
        self.data = data or {}
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def __repr__(self):
        return f"Decision({self.action}, priority={self.priority})"


class AgentPlanner:
    """
    Enterprise-grade agentic planner with AI-guided escalation.

    Operates as an exposure assessment engine:
    - Verified findings only
    - Adaptive analysis
    - Technology-aware testing
    - Contextual risk scoring
    - Intelligent escalation

    Correlation targets:
    - Technologies, services, endpoints
    - APIs, secrets, cloud assets
    - Vulnerabilities, authentication surfaces
    """

    def __init__(self, config: AetherConfig):
        self.config = config
        agent_cfg = config.data.get("agent", {})
        self.enabled = agent_cfg.get("enabled", True)
        self.auto_chain = agent_cfg.get("auto_chain", True)
        self.max_depth = agent_cfg.get("max_depth", 5)
        self.rules = agent_cfg.get("priority_rules", [])
        self._decisions: list[ScanDecision] = []
        self._executed: set[str] = set()
        self._depth = 0

    def analyze(self, module_name: str, results: Any, context: dict) -> list[ScanDecision]:
        """
        Analyze results and generate AI-guided decisions.
        Uses progressive escalation — only escalate when evidence supports it.
        """
        if not self.enabled or self._depth >= self.max_depth:
            return []

        decisions: list[ScanDecision] = []

        # ── Rule-based analysis ───────────────────────────────────────
        for rule in self.rules:
            condition = rule.get("condition", "")
            action = rule.get("action", "")
            if self._evaluate_condition(condition, module_name, results, context):
                if action not in self._executed:
                    decisions.append(ScanDecision(
                        action=action,
                        reason=f"Rule matched: {condition}",
                        priority=3,
                    ))

        # ── Technology-Aware Intelligence ──────────────────────────────

        # Port scan → service-specific modules
        if module_name in ("port_scan", "naabu") and isinstance(results, list):
            ports = {r.get("port") for r in results if isinstance(r, dict)}
            web_ports = ports & {80, 443, 8080, 8443, 8000, 8888}
            if web_ports:
                for mod in ("http_probe", "tech_fingerprint", "headers_analysis"):
                    key = f"run_module:{mod}"
                    if key not in self._executed:
                        decisions.append(ScanDecision(
                            action=key,
                            reason=f"Web ports found: {web_ports}",
                            priority=2,
                        ))

            db_ports = ports & {3306, 5432, 6379, 27017, 1433, 5984, 9200}
            if db_ports:
                decisions.append(ScanDecision(
                    action="flag:database_exposed",
                    reason=f"Database ports open: {db_ports}",
                    priority=1,
                    data={"ports": list(db_ports)},
                ))

        # Tech fingerprint → technology-specific modules
        if module_name == "tech_fingerprint" and isinstance(results, list):
            tech_names = {r.get("name", "").lower() for r in results if isinstance(r, dict)}

            # WordPress → deep WP analysis
            if "wordpress" in tech_names:
                wp_items = [t for t in results if isinstance(t, dict) and t.get("name", "").lower() == "wordpress"]
                if wp_items:
                    wp = wp_items[0]
                    confidence = wp.get("confidence", "low")
                    if confidence == "high":
                        decisions.append(ScanDecision(
                            action="run_module:wpscan",
                            reason=f"WordPress verified HIGH confidence",
                            priority=1,
                        ))
                    else:
                        decisions.append(ScanDecision(
                            action="apply_preset:wordpress",
                            reason="WordPress suspected",
                            priority=3,
                        ))

            # App stack → CVE + nuclei
            app_stacks = tech_names & {"php", "asp.net", "express.js", "django", "laravel", "spring"}
            if app_stacks:
                decisions.append(ScanDecision(
                    action="run_module:nuclei,cve_correlate,tech_specific",
                    reason=f"App stack detected: {list(app_stacks)}",
                    priority=2,
                ))

            # GraphQL → introspection check
            if "graphql" in tech_names:
                decisions.append(ScanDecision(
                    action="run_module:api_discovery",
                    reason="GraphQL detected — triggering API discovery",
                    priority=2,
                ))

            # Node.js/React/Vue → JS intelligence
            js_techs = tech_names & {"node.js", "react", "vue.js", "angular", "next.js"}
            if js_techs:
                decisions.append(ScanDecision(
                    action="run_module:api_discovery,secrets_scanner",
                    reason=f"JS framework detected ({list(js_techs)}) — scanning for secrets",
                    priority=2,
                ))

        # Web discovery → XSS/SQLi testing (only with evidence)
        if module_name in ("katana", "feroxbuster", "ffuf", "paramspider", "arjun") and isinstance(results, list):
            param_urls = [r for r in results if isinstance(r, dict) and "?" in str(r.get("url", r.get("discovered", "")))]
            if param_urls:
                decisions.append(ScanDecision(
                    action="run_module:dalfox,sqlmap",
                    reason=f"Parameterized URLs found ({len(param_urls)}) — targeted injection checks",
                    priority=2,
                ))

            login_found = any("login" in str(r).lower() or "admin" in str(r).lower() for r in results)
            if login_found:
                decisions.append(ScanDecision(
                    action="run_module:login_surface,misconfig_engine",
                    reason="Login/Admin panel discovered — authentication analysis",
                    priority=1,
                ))

        # TLS → certificate issues
        if module_name == "tls_inspect" and isinstance(results, list):
            for r in results:
                if isinstance(r, dict):
                    issues = r.get("issues", [])
                    if any("expired" in i.lower() for i in issues):
                        decisions.append(ScanDecision(
                            action="flag:cert_expired",
                            reason=f"Expired certificate on {r.get('host', '?')}",
                            priority=1,
                            data=r,
                        ))
                    if any("self-signed" in i.lower() for i in issues):
                        decisions.append(ScanDecision(
                            action="flag:self_signed_cert",
                            reason=f"Self-signed cert on {r.get('host', '?')}",
                            priority=3,
                            data=r,
                        ))

        # Headers → security posture assessment
        if module_name == "headers_analysis" and isinstance(results, list):
            critical_missing = [r for r in results if isinstance(r, dict)
                                and r.get("severity") in ("high", "medium")
                                and r.get("status") == "missing"]
            if len(critical_missing) >= 3:
                decisions.append(ScanDecision(
                    action="flag:poor_security_posture",
                    reason=f"{len(critical_missing)} critical security headers missing",
                    priority=2,
                ))

        # Subdomain flood → trigger probing
        if module_name in ("subdomain_enum", "cert_transparency", "subfinder", "amass"):
            new_subs = context.get("subdomains", [])
            if len(new_subs) > 10:
                key = "run_module:http_probe"
                if key not in self._executed:
                    decisions.append(ScanDecision(
                        action=key,
                        reason=f"{len(new_subs)} subdomains — HTTP probing needed",
                        priority=3,
                    ))

        # Secrets scanner → escalate if secrets found
        if module_name == "secrets_scanner" and isinstance(results, list):
            secrets = [r for r in results if isinstance(r, dict) and r.get("severity") in ("critical", "high")]
            if secrets:
                decisions.append(ScanDecision(
                    action="flag:secrets_exposed",
                    reason=f"{len(secrets)} secrets/sensitive files exposed",
                    priority=1,
                    data={"count": len(secrets)},
                ))

        # API discovery → deep API testing
        if module_name == "api_discovery" and isinstance(results, list):
            api_docs = [r for r in results if isinstance(r, dict) and r.get("type") == "api_documentation"]
            if api_docs:
                decisions.append(ScanDecision(
                    action="flag:api_documentation_exposed",
                    reason=f"API documentation publicly accessible ({len(api_docs)} docs)",
                    priority=2,
                ))

        # Sort and track
        decisions.sort(key=lambda d: d.priority)
        for d in decisions:
            self._executed.add(d.action)
        self._decisions.extend(decisions)

        return decisions

    def _evaluate_condition(self, condition: str, module: str,
                            results: Any, context: dict) -> bool:
        """Evaluate a rule condition against current results."""
        if not condition:
            return False

        if condition.startswith("open_port:"):
            ports_str = condition.split(":")[1]
            target_ports = {int(p.strip()) for p in ports_str.split(",")}
            open_ports = {r.get("port") for r in context.get("open_ports", [])
                          if isinstance(r, dict)}
            return bool(target_ports & open_ports)

        if condition.startswith("tech:"):
            tech_names = condition.split(":")[1].split(",")
            detected = {t.get("name", "").lower() for t in context.get("technologies", [])
                        if isinstance(t, dict)}
            return any(t.strip().lower() in detected for t in tech_names)

        if condition.startswith("header:"):
            header_name = condition.split(":")[1]
            for svc in context.get("http_services", []):
                if isinstance(svc, dict) and header_name in svc.get("headers", {}):
                    return True

        if condition.startswith("cert:"):
            cert_issue = condition.split(":")[1].lower()
            for svc in context.get("tls_results", []):
                if isinstance(svc, dict):
                    issues = [i.lower() for i in svc.get("issues", [])]
                    if any(cert_issue in i for i in issues):
                        return True

        return False

    def get_decisions(self) -> list[ScanDecision]:
        return self._decisions

    def get_actions_to_run(self) -> list[str]:
        modules = []
        for d in self._decisions:
            if d.action.startswith("run_module:"):
                mods = d.action.split(":")[1].split(",")
                modules.extend(m.strip() for m in mods)
        return list(set(modules))

    def get_presets_to_apply(self) -> list[str]:
        presets = []
        for d in self._decisions:
            if d.action.startswith("apply_preset:"):
                presets.append(d.action.split(":")[1])
        return presets

    def get_flags(self) -> list[dict]:
        flags = []
        for d in self._decisions:
            if d.action.startswith("flag:"):
                flags.append({
                    "flag": d.action.split(":")[1],
                    "reason": d.reason,
                    "priority": d.priority,
                    "data": d.data,
                })
        return flags
