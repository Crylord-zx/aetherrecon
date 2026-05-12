"""
AetherRecon CLI Entry Point
---------------------------
Provides the main CLI interface using Click + Rich for a modern terminal experience.
Handles argument parsing, profile selection, scope confirmation, and orchestration.
"""

import asyncio
import sys
import os
import signal
import json
from pathlib import Path
from datetime import datetime, timezone

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Confirm
from rich.table import Table
from rich import box

from aetherrecon.core.config import AetherConfig
from aetherrecon.core.database import Database
from aetherrecon.core.scanner import ScanOrchestrator
from aetherrecon.core.scope import ScopeValidator
from aetherrecon.core.state import StateManager
from aetherrecon.core.plugin_manager import PluginManager
from aetherrecon.reporting.json_report import JSONReporter
from aetherrecon.reporting.html_report import HTMLReporter
from aetherrecon.reporting.markdown_report import MarkdownReporter

console = Console()

# ── ASCII Banner ──────────────────────────────────────────────────────────────

BANNER = r"""
[bold cyan]
     ___       _   _               ____                      
    /   | ___ | |_| |__   ___ _ __|  _ \ ___  ___ ___  _ __  
   / /| |/ _ \| __| '_ \ / _ \ '__| |_) / _ \/ __/ _ \| '_ \ 
  / ___ |  __/| |_| | | |  __/ |  |  _ <  __/ (_| (_) | | | |
 /_/  |_|\___| \__|_| |_|\___|_|  |_| \_\___|\___\___/|_| |_|
[/bold cyan]
[dim]  ╔══════════════════════════════════════════════════════════╗
  ║  Modular Reconnaissance & Assessment Framework  v1.0   ║
  ║  ⚠  AUTHORIZED TARGETS ONLY — Know your scope.         ║
  ╚══════════════════════════════════════════════════════════╝[/dim]
"""


def display_banner():
    """Show the startup banner."""
    console.print(BANNER)


def display_target_info(target: str, profile: str, config: AetherConfig):
    """Display a summary table of the scan configuration before starting."""
    profile_cfg = config.get_profile(profile)
    table = Table(
        title="[bold]Scan Configuration[/bold]",
        box=box.ROUNDED,
        border_style="cyan",
        title_style="bold magenta",
    )
    table.add_column("Parameter", style="bold green")
    table.add_column("Value", style="white")
    table.add_row("Target", f"[yellow]{target}[/yellow]")
    table.add_row("Profile", f"[cyan]{profile}[/cyan]")
    table.add_row("Modules", ", ".join(profile_cfg.get("modules", ["all"])))
    table.add_row("Rate Limit", f"{profile_cfg.get('rate_limit', 10)} req/s")
    table.add_row("Output Dir", config.data.get("general", {}).get("output_dir", "./output"))
    table.add_row("Timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    console.print(table)


# ── Click CLI ─────────────────────────────────────────────────────────────────

@click.group(invoke_without_command=True)
@click.version_option(version="2.0.0", prog_name="AetherRecon")
@click.pass_context
def cli(ctx):
    """AetherRecon — Modular Reconnaissance Framework for authorized targets."""
    if ctx.invoked_subcommand is None:
        display_banner()
        click.echo(ctx.get_help())


@cli.command()
@click.option("-t", "--target", required=True, help="Target domain or IP (must be authorized)")
@click.option("-p", "--profile", default="standard",
              type=click.Choice(["safe", "standard", "moderate", "high", "advanced", "full_audit", "aggressive", "extreme"]),
              help="Scanning profile to use")
@click.option("-c", "--config", "config_path", default="config.yaml",
              help="Path to YAML configuration file")
@click.option("-o", "--output", "output_dir", default=None,
              help="Override output directory")
@click.option("--resume", is_flag=True, help="Resume a previously interrupted scan")
@click.option("--no-confirm", is_flag=True, help="Skip scope confirmation prompt")
@click.option("-m", "--modules", default=None,
              help="Comma-separated list of modules to run (overrides profile)")
def scan(target, profile, config_path, output_dir, resume, no_confirm, modules):
    """Run a reconnaissance scan against an authorized target."""
    display_banner()

    # ── Load configuration ────────────────────────────────────────────────
    config = AetherConfig(config_path)
    if output_dir:
        config.data.setdefault("general", {})["output_dir"] = output_dir

    out_dir = Path(config.data.get("general", {}).get("output_dir", "./output"))
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Scope validation ──────────────────────────────────────────────────
    scope_validator = ScopeValidator(config)
    is_allowed, reason = scope_validator.validate(target)

    if not is_allowed:
        console.print(Panel(
            f"[bold red]✗ TARGET BLOCKED[/bold red]\n\n"
            f"Target: [yellow]{target}[/yellow]\n"
            f"Reason: {reason}\n\n"
            f"[dim]Edit config.yaml to update scope rules.[/dim]",
            border_style="red",
            title="Scope Violation",
        ))
        sys.exit(1)

    # ── Display scan info and confirm ─────────────────────────────────────
    display_target_info(target, profile, config)

    if not no_confirm and config.data.get("scope", {}).get("require_confirmation", True):
        console.print()
        console.print(Panel(
            "[bold yellow]⚠  AUTHORIZATION CHECK[/bold yellow]\n\n"
            "You must have [bold]explicit written authorization[/bold] to scan this target.\n"
            "Unauthorized scanning is [bold red]illegal[/bold red] in most jurisdictions.",
            border_style="yellow",
        ))
        if not Confirm.ask(
            f"[bold]Do you have authorization to scan [cyan]{target}[/cyan]?[/bold]"
        ):
            console.print("[red]Scan aborted. No authorization confirmed.[/red]")
            sys.exit(0)

    # ── Determine modules to run ──────────────────────────────────────────
    if modules:
        module_list = [m.strip() for m in modules.split(",")]
    else:
        profile_cfg = config.get_profile(profile)
        module_list = profile_cfg.get("modules", ["all"])

    # ── Run the async scan ────────────────────────────────────────────────
    console.print()
    console.print("[bold green]▶ Starting scan...[/bold green]\n")

    try:
        asyncio.run(_run_scan(target, profile, module_list, config, resume, out_dir))
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Scan interrupted. State saved for resume.[/yellow]")
        sys.exit(130)


async def _run_scan(
    target: str,
    profile: str,
    module_list: list[str],
    config: AetherConfig,
    resume: bool,
    output_dir: Path,
):
    """Async entry point for the scan orchestration pipeline."""
    db = Database(output_dir / "aetherrecon.db")
    await db.initialize()

    state_mgr = StateManager(output_dir / ".aetherrecon_state.json")
    plugin_mgr = PluginManager(config)

    # If resuming, load previous state
    if resume:
        previous = state_mgr.load()
        if previous:
            console.print(f"[cyan]↻ Resuming scan from {previous.get('timestamp', 'unknown')}[/cyan]")
        else:
            console.print("[yellow]No previous state found. Starting fresh.[/yellow]")

    orchestrator = ScanOrchestrator(
        target=target,
        profile=profile,
        modules=module_list,
        config=config,
        db=db,
        state_manager=state_mgr,
        plugin_manager=plugin_mgr,
        console=console,
    )

    # Run all scan phases
    results = await orchestrator.run()

    # ── Generate reports ──────────────────────────────────────────────────
    console.print("\n[bold blue]📄 Generating reports...[/bold blue]")

    report_formats = config.data.get("reporting", {}).get("formats", ["json"])

    scan_meta = {
        "target": target,
        "profile": profile,
        "modules": module_list,
        "timestamp_start": results.get("timestamp_start", ""),
        "timestamp_end": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",
    }

    if "json" in report_formats:
        json_reporter = JSONReporter(output_dir)
        json_path = await json_reporter.generate(scan_meta, results)
        console.print(f"  [green]✓[/green] JSON report: [link={json_path}]{json_path}[/link]")

    if "html" in report_formats:
        html_reporter = HTMLReporter(output_dir, config)
        html_path = await html_reporter.generate(scan_meta, results)
        console.print(f"  [green]✓[/green] HTML report: [link={html_path}]{html_path}[/link]")

    if "markdown" in report_formats:
        md_reporter = MarkdownReporter(output_dir)
        md_path = await md_reporter.generate(scan_meta, results)
        console.print(f"  [green]✓[/green] Markdown report: [link={md_path}]{md_path}[/link]")

    # ── Summary ───────────────────────────────────────────────────────────
    total_findings = sum(
        len(v) if isinstance(v, list) else 1
        for k, v in results.items()
        if k not in ("timestamp_start", "errors")
    )
    errors = results.get("errors", [])

    console.print()
    console.print(Panel(
        f"[bold green]✓ Scan Complete[/bold green]\n\n"
        f"  Target: [cyan]{target}[/cyan]\n"
        f"  Findings: [yellow]{total_findings}[/yellow]\n"
        f"  Errors: [red]{len(errors)}[/red]\n"
        f"  Output: [blue]{output_dir}[/blue]",
        border_style="green",
        title="Summary",
    ))

    await db.close()


@cli.command()
@click.option("-c", "--config", "config_path", default="config.yaml")
def check_tools(config_path):
    """Check which external tools are available on this system."""
    display_banner()
    config = AetherConfig(config_path)
    plugin_mgr = PluginManager(config)

    table = Table(title="[bold]External Tool Status[/bold]", box=box.ROUNDED, border_style="cyan")
    table.add_column("Tool", style="bold")
    table.add_column("Status")
    table.add_column("Path", style="dim")

    for tool_name, tool_path in plugin_mgr.check_tools().items():
        if tool_path:
            table.add_row(tool_name, "[green]✓ Found[/green]", tool_path)
        else:
            table.add_row(tool_name, "[red]✗ Not found[/red]", "-")

    console.print(table)


@cli.command()
def install_tools():
    """Install missing external tools (requires sudo)."""
    console.print("[bold cyan]▶ Starting Tool Auto-Installer[/]")
    
    from aetherrecon.core.installer import ToolInstaller
    import asyncio
    
    installer = ToolInstaller()
    
    def log_cb(msg: str):
        console.print(msg)
        
    # We remove the '-n' from sudo temporarily so the terminal can prompt for password if needed.
    original_run_cmd = installer.run_cmd
    
    async def patched_run_cmd(cmd: list[str], log_cb=None):
        if cmd[0] == "sudo" and "-n" in cmd:
            cmd.remove("-n")
        return await original_run_cmd(cmd, log_cb)
        
    installer.run_cmd = patched_run_cmd
    
    asyncio.run(installer.install_all(log_cb=log_cb))
    console.print("[bold green]✓ Tool installation complete![/]")


@cli.command()
def profiles():
    """List available scanning profiles."""
    display_banner()
    config = AetherConfig("config.yaml")

    table = Table(title="[bold]Scanning Profiles[/bold]", box=box.ROUNDED, border_style="cyan")
    table.add_column("Profile", style="bold cyan")
    table.add_column("Description")
    table.add_column("Modules", style="dim")
    table.add_column("Rate", justify="right")

    for name, prof in config.data.get("profiles", {}).items():
        mods = ", ".join(prof.get("modules", [])[:5])
        if len(prof.get("modules", [])) > 5:
            mods += "..."
        table.add_row(
            name,
            prof.get("description", ""),
            mods,
            str(prof.get("rate_limit", "-")),
        )

    console.print(table)


@cli.command()
@click.option("-c", "--config", "config_path", default="config.yaml")
def tui(config_path):
    """Launch the Cyberpunk TUI Dashboard."""
    from aetherrecon.tui.dashboard import run_dashboard
    run_dashboard(config_path)


@cli.command()
@click.option("-c", "--config", "config_path", default="config.yaml")
@click.option("--host", default="127.0.0.1", help="API host to bind to")
@click.option("--port", default=8337, help="API port to bind to")
def api(config_path, host, port):
    """Start the local FastAPI server."""
    display_banner()
    console.print(f"[bold green]Starting API server on {host}:{port}...[/bold green]")
    from aetherrecon.api.server import run_api
    run_api(config_path, host, port)


# ── Main Entry ────────────────────────────────────────────────────────────────

def main():
    """Package entry point."""
    cli()


if __name__ == "__main__":
    main()
