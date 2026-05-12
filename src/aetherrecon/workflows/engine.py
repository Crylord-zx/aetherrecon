"""
Workflow Engine
----------------
Defines and executes recon pipelines as YAML-based workflows.
Supports sequential/parallel step execution, conditions, and retries.
"""

import asyncio
from typing import Any
from pathlib import Path

import yaml

from aetherrecon.core.config import AetherConfig


class WorkflowStep:
    """Represents a single step in a workflow pipeline."""

    def __init__(self, name: str, module: str, config: dict | None = None,
                 condition: str = "", retry: int = 0, parallel: bool = False):
        self.name = name
        self.module = module
        self.config = config or {}
        self.condition = condition      # e.g., "has_subdomains", "has_open_ports"
        self.retry = retry
        self.parallel = parallel
        self.status = "pending"         # pending, running, complete, failed, skipped
        self.result: Any = None

    def to_dict(self) -> dict:
        return {
            "name": self.name, "module": self.module, "status": self.status,
            "condition": self.condition, "parallel": self.parallel,
        }


class Workflow:
    """A named sequence of WorkflowSteps."""

    def __init__(self, name: str, description: str = "", steps: list[WorkflowStep] | None = None):
        self.name = name
        self.description = description
        self.steps = steps or []

    @classmethod
    def from_dict(cls, data: dict) -> "Workflow":
        steps = []
        for s in data.get("steps", []):
            steps.append(WorkflowStep(
                name=s.get("name", s.get("module", "?")),
                module=s.get("module", ""),
                config=s.get("config"),
                condition=s.get("condition", ""),
                retry=s.get("retry", 0),
                parallel=s.get("parallel", False),
            ))
        return cls(
            name=data.get("name", "unnamed"),
            description=data.get("description", ""),
            steps=steps,
        )

    @classmethod
    def load_from_file(cls, path: str | Path) -> "Workflow":
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)


class WorkflowEngine:
    """
    Executes workflow pipelines.

    Handles step sequencing, parallelism, conditions, and retries.
    Provides status tracking for each step.
    """

    def __init__(self, config: AetherConfig):
        self.config = config
        self._workflows: dict[str, Workflow] = {}
        self._register_builtins()

    def _register_builtins(self):
        """Register built-in workflow templates."""
        self._workflows["quick_recon"] = Workflow(
            name="quick_recon",
            description="Fast passive reconnaissance pipeline",
            steps=[
                WorkflowStep("WHOIS Lookup", "whois"),
                WorkflowStep("DNS Enumeration", "dns_enum"),
                WorkflowStep("CT Log Search", "cert_transparency"),
                WorkflowStep("Subdomain Brute", "subdomain_enum", parallel=True),
                WorkflowStep("Wayback URLs", "wayback", parallel=True),
            ],
        )

        self._workflows["full_recon"] = Workflow(
            name="full_recon",
            description="Comprehensive recon + vulnerability assessment",
            steps=[
                WorkflowStep("WHOIS Lookup", "whois"),
                WorkflowStep("DNS Enumeration", "dns_enum"),
                WorkflowStep("CT Log Search", "cert_transparency"),
                WorkflowStep("Subdomain Brute", "subdomain_enum"),
                WorkflowStep("Wayback URLs", "wayback"),
                WorkflowStep("HTTP Probing", "http_probe", condition="has_subdomains"),
                WorkflowStep("Port Scanning", "port_scan"),
                WorkflowStep("Tech Fingerprint", "tech_fingerprint", condition="has_http_services"),
                WorkflowStep("TLS Inspection", "tls_inspect"),
                WorkflowStep("Headers Analysis", "headers_analysis", condition="has_http_services"),
                WorkflowStep("CVE Correlation", "cve_correlate", condition="has_technologies"),
            ],
        )

        self._workflows["web_audit"] = Workflow(
            name="web_audit",
            description="Web application security assessment",
            steps=[
                WorkflowStep("HTTP Probing", "http_probe"),
                WorkflowStep("Tech Fingerprint", "tech_fingerprint"),
                WorkflowStep("TLS Inspection", "tls_inspect"),
                WorkflowStep("Headers Analysis", "headers_analysis"),
                WorkflowStep("CVE Correlation", "cve_correlate", condition="has_technologies"),
            ],
        )

        self._workflows["ctf_blitz"] = Workflow(
            name="ctf_blitz",
            description="Aggressive CTF target enumeration",
            steps=[
                WorkflowStep("Port Scan", "port_scan"),
                WorkflowStep("HTTP Probe", "http_probe", parallel=True),
                WorkflowStep("DNS Enum", "dns_enum", parallel=True),
                WorkflowStep("Tech FP", "tech_fingerprint", condition="has_http_services"),
                WorkflowStep("Headers", "headers_analysis", parallel=True),
                WorkflowStep("TLS", "tls_inspect", parallel=True),
                WorkflowStep("CVE", "cve_correlate"),
            ],
        )

    def list_workflows(self) -> dict[str, str]:
        """Return available workflow names and descriptions."""
        return {name: wf.description for name, wf in self._workflows.items()}

    def get_workflow(self, name: str) -> Workflow | None:
        return self._workflows.get(name)

    def get_module_sequence(self, workflow_name: str) -> list[str]:
        """Extract the ordered list of module names from a workflow."""
        wf = self.get_workflow(workflow_name)
        if not wf:
            return []
        return [step.module for step in wf.steps]

    def check_condition(self, condition: str, context: dict) -> bool:
        """Evaluate a workflow step condition against scan context."""
        if not condition:
            return True

        checks = {
            "has_subdomains": lambda: len(context.get("subdomains", [])) > 0,
            "has_open_ports": lambda: len(context.get("open_ports", [])) > 0,
            "has_http_services": lambda: len(context.get("http_services", [])) > 0,
            "has_technologies": lambda: len(context.get("technologies", [])) > 0,
        }

        check_fn = checks.get(condition)
        return check_fn() if check_fn else True

    def register_workflow(self, workflow: Workflow):
        """Register a custom workflow."""
        self._workflows[workflow.name] = workflow

    def load_custom_workflows(self, directory: str | Path):
        """Load custom YAML workflow files from a directory."""
        wf_dir = Path(directory)
        if not wf_dir.exists():
            return
        for yaml_file in wf_dir.glob("*.yaml"):
            try:
                wf = Workflow.load_from_file(yaml_file)
                self._workflows[wf.name] = wf
            except Exception:
                pass
