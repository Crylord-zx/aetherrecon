"""
Agent Executor
---------------
Runs decisions from the AgentPlanner, executing follow-up modules
and applying target presets autonomously.
"""

import asyncio
from typing import Any

from rich.console import Console

from aetherrecon.core.config import AetherConfig
from aetherrecon.core.database import Database
from aetherrecon.core.rate_limiter import AdaptiveRateLimiter
from aetherrecon.agents.planner import AgentPlanner, ScanDecision


class AgentExecutor:
    """
    Executes agent decisions by running additional modules,
    applying presets, and flagging findings.
    """

    def __init__(
        self,
        config: AetherConfig,
        db: Database,
        scan_id: int,
        rate_limiter: AdaptiveRateLimiter,
        context: dict[str, Any],
        console: Console | None = None,
    ):
        self.config = config
        self.db = db
        self.scan_id = scan_id
        self.rate_limiter = rate_limiter
        self.context = context
        self.console = console or Console()
        self.planner = AgentPlanner(config)
        self._execution_log: list[dict] = []

    async def process_results(self, module_name: str, results: Any) -> list[dict]:
        """
        Feed module results to the planner and execute any decisions.

        Returns:
            List of additional results from auto-triggered modules.
        """
        decisions = self.planner.analyze(module_name, results, self.context)
        additional_results = []

        if not decisions:
            return additional_results

        self.console.print(
            f"  [magenta]🤖 Agent: {len(decisions)} decision(s) from {module_name}[/]"
        )

        for decision in decisions:
            self.console.print(
                f"    [dim]→ {decision.action} (priority:{decision.priority}) — {decision.reason}[/]"
            )

            if decision.action.startswith("run_module:"):
                mod_results = await self._run_modules(decision)
                additional_results.extend(mod_results)

            elif decision.action.startswith("apply_preset:"):
                await self._apply_preset(decision)

            elif decision.action.startswith("flag:"):
                await self._flag_finding(decision)

            self._execution_log.append({
                "decision": decision.action,
                "reason": decision.reason,
                "priority": decision.priority,
            })

        return additional_results

    async def _run_modules(self, decision: ScanDecision) -> list[dict]:
        """Execute modules specified in a run_module decision."""
        from aetherrecon.core.scanner import MODULE_REGISTRY

        mod_names = decision.action.split(":")[1].split(",")
        results = []

        for mod_name in mod_names:
            mod_name = mod_name.strip()
            if mod_name not in MODULE_REGISTRY:
                continue

            self.console.print(f"    [cyan]⚡ Auto-running: {mod_name}[/]")

            try:
                mod_class = MODULE_REGISTRY[mod_name]
                instance = mod_class(
                    config=self.config,
                    db=self.db,
                    scan_id=self.scan_id,
                    rate_limiter=self.rate_limiter,
                    context=self.context,
                )
                target = self.context.get("target", "")
                mod_results = await instance.run(target)
                results.append({"module": mod_name, "data": mod_results})

            except Exception as e:
                self.console.print(f"    [red]✗ Agent module {mod_name} failed: {e}[/]")

        return results

    async def _apply_preset(self, decision: ScanDecision):
        """Apply a target preset from configuration."""
        preset_name = decision.action.split(":")[1]
        presets = self.config.data.get("target_presets", {})

        if preset_name not in presets:
            return

        preset = presets[preset_name]
        self.console.print(f"    [green]📋 Applied preset: {preset_name}[/]")

        # Log the preset application
        await self.db.add_finding(
            scan_id=self.scan_id,
            module="agent",
            category="automation",
            severity="info",
            title=f"Applied target preset: {preset_name}",
            description=f"Paths to check: {preset.get('check_paths', [])}",
            data=preset,
        )

    async def _flag_finding(self, decision: ScanDecision):
        """Flag a high-priority finding."""
        flag_name = decision.action.split(":")[1]

        severity = "high" if decision.priority <= 2 else "medium"

        await self.db.add_finding(
            scan_id=self.scan_id,
            module="agent",
            category="flag",
            severity=severity,
            title=f"Agent flag: {flag_name.replace('_', ' ').title()}",
            description=decision.reason,
            data=decision.data,
        )

        self.console.print(
            f"    [{'red' if severity == 'high' else 'yellow'}]"
            f"🚩 Flagged: {flag_name} ({severity})[/]"
        )

    def get_execution_log(self) -> list[dict]:
        """Return the full agent execution log."""
        return self._execution_log
