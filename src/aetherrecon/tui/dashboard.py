"""
AetherRecon TUI Dashboard
---------------------------
Full-featured terminal UI built with Textual.
Features: live scan progress, log panel, stats, keyboard shortcuts,
interactive target/profile selection, and cyberpunk theme.
"""

import asyncio
from datetime import datetime, timezone
from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, Container
from textual.widgets import (
    Header, Footer, Static, Button, Input, Select,
    DataTable, RichLog, ProgressBar, LoadingIndicator,
    Label, TabbedContent, TabPane, Markdown,
)
from textual.screen import Screen, ModalScreen
from rich.text import Text
from rich.panel import Panel
from rich.table import Table

from aetherrecon.tui.theme import APP_CSS
from aetherrecon.core.config import AetherConfig
from aetherrecon.core.database import Database
from aetherrecon.core.scope import ScopeValidator
from aetherrecon.core.scanner import ScanOrchestrator
from aetherrecon.core.state import StateManager
from aetherrecon.core.plugin_manager import PluginManager
from aetherrecon.core.rate_limiter import AdaptiveRateLimiter


# ── Banner Widget ─────────────────────────────────────────────────────────────

BANNER_ART = r"""
 ▄▄▄      ▓█████▄▄▄█████▓ ██░ ██ ▓█████  ██▀███
▒████▄    ▓█   ▀▓  ██▒ ▓▒▓██░ ██▒▓█   ▀ ▓██ ▒ ██▒
▒██  ▀█▄  ▒███  ▒ ▓██░ ▒░▒██▀▀██░▒███   ▓██ ░▄█ ▒
░██▄▄▄▄██ ▒▓█  ▄░ ▓██▓ ░ ░▓█ ░██ ▒▓█  ▄ ▒██▀▀█▄
 ▓█   ▓██▒░▒████▒ ▒██▒ ░ ░▓█▒░██▓░▒████▒░██▓ ▒██▒
 ▒▒   ▓▒█░░░ ▒░ ░ ▒ ░░    ▒ ░░▒░▒░░ ▒░ ░░ ▒▓ ░▒▓░
  R  E  C  O  N     v2.0  ⚡  Authorized Only
"""


# ── Confirmation Modal ────────────────────────────────────────────────────────

class AuthConfirmScreen(ModalScreen[bool]):
    """Modal screen for authorization confirmation before scanning."""

    BINDINGS = [
        Binding("y", "confirm", "Yes, I'm authorized"),
        Binding("n", "deny", "No, abort"),
    ]

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static(
                Panel(
                    "[bold yellow]⚠  AUTHORIZATION CHECK[/]\n\n"
                    "You must have [bold]explicit written authorization[/bold]\n"
                    "to scan this target.\n\n"
                    "Unauthorized scanning is [bold red]ILLEGAL[/bold red]\n"
                    "in most jurisdictions.\n\n"
                    "[dim]Press [bold]Y[/bold] to confirm or [bold]N[/bold] to abort[/dim]",
                    border_style="yellow",
                    title="⚡ Scope Confirmation",
                ),
                id="auth-modal",
            ),
            id="modal-container",
        )

    def action_confirm(self):
        self.dismiss(True)

    def action_deny(self):
        self.dismiss(False)


# ── Main Dashboard App ────────────────────────────────────────────────────────

class AetherReconDashboard(App):
    """AetherRecon TUI Dashboard — Cyberpunk-themed scanning interface."""

    CSS = APP_CSS
    TITLE = "⚡ AetherRecon v2.0"
    SUB_TITLE = "Authorized Targets Only"

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("ctrl+s", "start_scan", "Start Scan", show=True),
        Binding("ctrl+x", "stop_scan", "Stop Scan", show=True),
        Binding("ctrl+l", "clear_logs", "Clear Logs", show=True),
        Binding("ctrl+t", "cycle_theme", "Theme", show=True),
        Binding("ctrl+p", "show_profiles", "Profiles", show=True),
        Binding("ctrl+w", "show_workspace", "Workspace", show=True),
        Binding("f1", "show_help", "Help", show=True),
    ]

    def __init__(self, config_path: str = "config.yaml"):
        super().__init__()
        self.config = AetherConfig(config_path)
        self._scanning = False
        self._scan_task = None
        self._theme_index = 0
        self._themes = ["cyberpunk", "matrix", "arctic"]
        self._findings_count = 0
        self._modules_done = 0
        self._total_modules = 0
        self._scan_start_time = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with TabbedContent(initial="dashboard"):
            # ── Dashboard Tab ─────────────────────────────────────────
            with TabPane("Dashboard", id="dashboard"):
                yield Static(
                    Text.from_ansi(BANNER_ART),
                    id="banner",
                )

                with Horizontal(id="input-row"):
                    yield Input(
                        placeholder="Enter target (domain or IP)...",
                        id="target-input",
                    )
                    yield Select(
                        [(p, p) for p in ["safe", "standard", "high", "aggressive", "extreme"]],
                        value="standard",
                        id="profile-select",
                        prompt="Profile",
                    )
                    yield Button("⚡ Scan", variant="primary", id="btn-scan")
                    yield Button("■ Stop", variant="error", id="btn-stop", disabled=True)

                with Horizontal(id="stats-row"):
                    yield Static("", id="stat-target", classes="stat-box")
                    yield Static("", id="stat-profile", classes="stat-box")
                    yield Static("", id="stat-findings", classes="stat-box")
                    yield Static("", id="stat-modules", classes="stat-box")
                    yield Static("", id="stat-elapsed", classes="stat-box")

                yield ProgressBar(total=100, show_eta=True, id="scan-progress")

                with Horizontal(id="panels-row"):
                    with Vertical(id="findings-panel"):
                        yield Static("[bold cyan]━━ Findings ━━[/]", classes="panel-title")
                        yield DataTable(id="findings-table")

                    with Vertical(id="log-panel"):
                        yield Static("[bold cyan]━━ Live Logs ━━[/]", classes="panel-title")
                        yield RichLog(
                            highlight=True,
                            markup=True,
                            wrap=True,
                            max_lines=500,
                            id="log-output",
                        )

            # ── Tools Tab ─────────────────────────────────────────────
            with TabPane("Tools", id="tools-tab"):
                yield Static("[bold cyan]External Tool Status[/]", classes="panel-title")
                yield DataTable(id="tools-table")
                with Horizontal():
                    yield Button("🔍 Check Tools", id="btn-check-tools")
                    yield Button("📦 Install Missing", id="btn-install-tools")

            # ── Workspace Tab ─────────────────────────────────────────
            with TabPane("Workspace", id="workspace-tab"):
                yield Static("[bold cyan]Projects[/]", classes="panel-title")
                yield DataTable(id="projects-table")

            # ── Help Tab ──────────────────────────────────────────────
            with TabPane("Help", id="help-tab"):
                yield Markdown(HELP_MD, id="help-content")

        yield Footer()

    def on_mount(self) -> None:
        """Initialize widgets after mount."""
        # Setup findings table
        ft = self.query_one("#findings-table", DataTable)
        ft.add_columns("Severity", "Module", "Title", "Description")

        # Setup tools table
        tt = self.query_one("#tools-table", DataTable)
        tt.add_columns("Tool", "Status", "Path")

        # Setup projects table
        pt = self.query_one("#projects-table", DataTable)
        pt.add_columns("Project", "Target", "Last Scan", "Findings")

        # Initial log
        log = self.query_one("#log-output", RichLog)
        log.write("[bold cyan]⚡ AetherRecon v2.0 Dashboard[/]")
        log.write("[dim]Ready. Enter a target and press Ctrl+S or click ⚡ Scan.[/]")
        log.write("")

        self._update_stats()

    # ── Scan Control ──────────────────────────────────────────────────────

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-scan":
            await self.action_start_scan()
        elif event.button.id == "btn-stop":
            await self.action_stop_scan()
        elif event.button.id == "btn-check-tools":
            self._check_tools()
        elif event.button.id == "btn-install-tools":
            self.run_worker(self.action_install_tools(), exclusive=True)

    async def action_install_tools(self) -> None:
        log = self.query_one("#log-output", RichLog)
        log.write("\n[bold cyan]▶ Starting Tool Auto-Installer[/]")
        
        from aetherrecon.core.installer import ToolInstaller
        installer = ToolInstaller()
        
        def log_callback(msg: str):
            # Safe to call from worker thread via Textual's call_from_thread
            self.call_from_thread(log.write, msg)
            
        await installer.install_all(log_cb=log_callback)
        self.call_from_thread(log.write, "[bold green]✓ Tool installation complete. Re-check tools![/]")

    @work
    async def action_start_scan(self) -> None:
        target_input = self.query_one("#target-input", Input)
        target = target_input.value.strip()

        if not target:
            log = self.query_one("#log-output", RichLog)
            log.write("[red]✗ No target specified. Enter a domain or IP.[/]")
            return

        if self._scanning:
            log = self.query_one("#log-output", RichLog)
            log.write("[yellow]⚠ Scan already in progress.[/]")
            return

        # Scope validation
        scope = ScopeValidator(self.config)
        allowed, reason = scope.validate(target)
        if not allowed:
            log = self.query_one("#log-output", RichLog)
            log.write(f"[red]✗ TARGET BLOCKED: {reason}[/]")
            return

        # Authorization confirmation
        if self.config.data.get("scope", {}).get("require_confirmation", True):
            confirmed = await self.push_screen_wait(AuthConfirmScreen())
            if not confirmed:
                log = self.query_one("#log-output", RichLog)
                log.write("[red]Scan aborted — no authorization confirmed.[/]")
                return

        # Start scan
        self._scanning = True
        self.query_one("#btn-scan", Button).disabled = True
        self.query_one("#btn-stop", Button).disabled = False
        self._scan_start_time = datetime.now(timezone.utc)

        profile_select = self.query_one("#profile-select", Select)
        profile = str(profile_select.value)

        self._scan_task = asyncio.create_task(self._run_scan(target, profile))

    async def action_stop_scan(self) -> None:
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
            log = self.query_one("#log-output", RichLog)
            log.write("[yellow]⚠ Scan cancelled by user.[/]")

        self._scanning = False
        self.query_one("#btn-scan", Button).disabled = False
        self.query_one("#btn-stop", Button).disabled = True

    async def _run_scan(self, target: str, profile: str):
        """Execute the scan and update the TUI in real-time."""
        log = self.query_one("#log-output", RichLog)
        ft = self.query_one("#findings-table", DataTable)
        progress = self.query_one("#scan-progress", ProgressBar)

        log.write(f"\n[bold green]▶ Starting scan: {target} ({profile})[/]")
        log.write(f"[dim]  Time: {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}[/]")

        output_dir = Path(self.config.data.get("general", {}).get("output_dir", "./output"))
        output_dir.mkdir(parents=True, exist_ok=True)

        db = Database(output_dir / "aetherrecon.db")
        await db.initialize()

        state_mgr = StateManager(output_dir / ".aetherrecon_state.json")
        plugin_mgr = PluginManager(self.config)

        profile_cfg = self.config.get_profile(profile)
        module_list = profile_cfg.get("modules", ["all"])

        # Create orchestrator with TUI callback
        orchestrator = ScanOrchestrator(
            target=target, profile=profile, modules=module_list,
            config=self.config, db=db, state_manager=state_mgr,
            plugin_manager=plugin_mgr, console=None,
        )

        modules_to_run = orchestrator._resolve_modules()
        self._total_modules = len(modules_to_run)
        self._modules_done = 0
        self._findings_count = 0
        progress.update(total=self._total_modules, progress=0)

        self._update_stats(target=target, profile=profile)

        try:
            results = await orchestrator.run()

            # Populate findings table from results
            for mod_name, mod_data in results.items():
                if mod_name in ("timestamp_start", "errors"):
                    continue

                self._modules_done += 1
                progress.update(progress=self._modules_done)
                log.write(f"  [green]✓[/] [cyan]{mod_name}[/] complete")

                if isinstance(mod_data, list):
                    for item in mod_data[:50]:
                        if isinstance(item, dict):
                            sev = item.get("severity", "info")
                            sev_style = f"severity-{sev}"
                            title = str(item.get("title", item.get("url", item.get("domain", ""))))[:60]
                            desc = str(item.get("description", ""))[:80]
                            ft.add_row(
                                Text(sev.upper(), style=sev_style),
                                mod_name, title, desc,
                            )
                            self._findings_count += 1

                self._update_stats(target=target, profile=profile)

            # Generate reports
            log.write("\n[bold blue]📄 Generating reports...[/]")
            from aetherrecon.reporting.json_report import JSONReporter
            from aetherrecon.reporting.html_report import HTMLReporter
            from aetherrecon.reporting.markdown_report import MarkdownReporter

            meta = {
                "target": target, "profile": profile, "modules": module_list,
                "timestamp_start": results.get("timestamp_start", ""),
                "timestamp_end": datetime.now(timezone.utc).isoformat(),
            }

            json_r = JSONReporter(output_dir)
            await json_r.generate(meta, results)
            html_r = HTMLReporter(output_dir, self.config)
            await html_r.generate(meta, results)
            md_r = MarkdownReporter(output_dir)
            await md_r.generate(meta, results)

            log.write(f"  [green]✓[/] Reports saved to {output_dir}/")

            errors = results.get("errors", [])
            log.write(f"\n[bold green]✓ Scan complete — "
                      f"{self._findings_count} findings, {len(errors)} errors[/]")

        except asyncio.CancelledError:
            log.write("[yellow]Scan was cancelled.[/]")
        except Exception as e:
            log.write(f"[red]✗ Scan error: {e}[/]")
        finally:
            await db.close()
            self._scanning = False
            self.query_one("#btn-scan", Button).disabled = False
            self.query_one("#btn-stop", Button).disabled = True

    # ── Stats Update ──────────────────────────────────────────────────────

    def _update_stats(self, target: str = "—", profile: str = "—"):
        try:
            self.query_one("#stat-target", Static).update(
                f"[bold cyan]Target:[/] {target}"
            )
            self.query_one("#stat-profile", Static).update(
                f"[bold cyan]Profile:[/] {profile}"
            )
            self.query_one("#stat-findings", Static).update(
                f"[bold cyan]Findings:[/] [green]{self._findings_count}[/]"
            )
            self.query_one("#stat-modules", Static).update(
                f"[bold cyan]Modules:[/] {self._modules_done}/{self._total_modules}"
            )

            elapsed = ""
            if self._scan_start_time:
                delta = datetime.now(timezone.utc) - self._scan_start_time
                elapsed = str(delta).split(".")[0]
            self.query_one("#stat-elapsed", Static).update(
                f"[bold cyan]Elapsed:[/] {elapsed or '—'}"
            )
        except Exception:
            pass

    # ── Tools Check ───────────────────────────────────────────────────────

    def _check_tools(self):
        log = self.query_one("#log-output", RichLog)
        tt = self.query_one("#tools-table", DataTable)
        tt.clear()

        plugin_mgr = PluginManager(self.config)
        tools = plugin_mgr.check_tools()

        for name, path in tools.items():
            if path:
                tt.add_row(name, Text("✓ Found", style="green"), path)
            else:
                tt.add_row(name, Text("✗ Missing", style="red"), "—")

        found = sum(1 for v in tools.values() if v)
        log.write(f"[cyan]Tool check: {found}/{len(tools)} tools available[/]")

    # ── Actions ───────────────────────────────────────────────────────────

    def action_clear_logs(self) -> None:
        self.query_one("#log-output", RichLog).clear()

    def action_cycle_theme(self) -> None:
        self._theme_index = (self._theme_index + 1) % len(self._themes)
        theme = self._themes[self._theme_index]
        log = self.query_one("#log-output", RichLog)
        log.write(f"[cyan]Theme: {theme}[/]")

    def action_show_profiles(self) -> None:
        log = self.query_one("#log-output", RichLog)
        log.write("\n[bold cyan]━━ Scanning Profiles ━━[/]")
        for name, prof in self.config.data.get("profiles", {}).items():
            desc = prof.get("description", "")
            rate = prof.get("rate_limit", "?")
            threads = prof.get("threads", "?")
            log.write(f"  [green]{name:12s}[/] {desc} [dim](rate:{rate}, threads:{threads})[/]")

    def action_show_workspace(self) -> None:
        log = self.query_one("#log-output", RichLog)
        log.write("[cyan]Workspace manager — projects dir: ./projects[/]")

    def action_show_help(self) -> None:
        """Switch to help tab."""
        tabs = self.query_one(TabbedContent)
        tabs.active = "help-tab"


# ── Help Content ──────────────────────────────────────────────────────────────

HELP_MD = """
# ⚡ AetherRecon v2.0 — Keyboard Shortcuts

| Key | Action |
|---|---|
| `Ctrl+S` | Start scan |
| `Ctrl+X` | Stop scan |
| `Ctrl+L` | Clear logs |
| `Ctrl+T` | Cycle theme |
| `Ctrl+P` | Show profiles |
| `Ctrl+W` | Workspace info |
| `Ctrl+Q` | Quit |
| `F1` | Show this help |
| `Tab` | Switch panels |

## Profiles

| Profile | Description |
|---|---|
| `safe` | Passive-only, no connections |
| `standard` | Balanced passive + light active |
| `high` | Thorough active scanning |
| `aggressive` | Fast CTF/lab scanning |
| `extreme` | Maximum speed, lab only |

## Usage

1. Enter target in the input field
2. Select a profile from the dropdown
3. Press `Ctrl+S` or click ⚡ Scan
4. Monitor progress in the logs panel
5. View findings in the table
6. Reports saved to `./output/`

## Safety

- Blocked: `.gov`, `.mil`, `.edu`, `localhost`
- Authorization prompt before every scan
- Private IPs auto-approved for labs
"""


def run_dashboard(config_path: str = "config.yaml"):
    """Launch the TUI dashboard."""
    app = AetherReconDashboard(config_path)
    app.run()
