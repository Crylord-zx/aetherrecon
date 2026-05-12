"""
TUI Theme System
-----------------
Provides theme definitions for the Textual-based dashboard.
Supports cyberpunk, matrix, and arctic themes.
"""

from textual.app import ComposeResult
from textual.design import ColorSystem

# ── Cyberpunk Theme ───────────────────────────────────────────────────────────
CYBERPUNK = ColorSystem(
    primary="#00f0ff",
    secondary="#ff00aa",
    accent="#00ff88",
    warning="#ffd700",
    error="#ff3366",
    success="#00ff88",
    background="#0a0e17",
    surface="#1a1f35",
    panel="#111827",
    dark=True,
)

MATRIX = ColorSystem(
    primary="#00ff00",
    secondary="#00cc00",
    accent="#00ff88",
    warning="#ffff00",
    error="#ff0000",
    success="#00ff00",
    background="#000000",
    surface="#0a0a0a",
    panel="#050505",
    dark=True,
)

ARCTIC = ColorSystem(
    primary="#88ccff",
    secondary="#4488cc",
    accent="#aaddff",
    warning="#ffcc00",
    error="#ff4444",
    success="#44ffaa",
    background="#0a1628",
    surface="#152238",
    panel="#0f1a2e",
    dark=True,
)

THEMES = {
    "cyberpunk": CYBERPUNK,
    "matrix": MATRIX,
    "arctic": ARCTIC,
}

# ── CSS for the TUI app ──────────────────────────────────────────────────────
APP_CSS = """
Screen {
    background: #0a0e17;
}

#header-bar {
    dock: top;
    height: 3;
    background: #111827;
    border-bottom: solid #00f0ff;
    content-align: center middle;
    text-style: bold;
    color: #00f0ff;
}

#footer-bar {
    dock: bottom;
    height: 1;
    background: #111827;
    border-top: solid #2d3555;
    color: #94a3b8;
}

#main-container {
    layout: grid;
    grid-size: 2 2;
    grid-gutter: 1;
    padding: 1;
}

#scan-panel {
    row-span: 2;
    border: solid #2d3555;
    background: #1a1f35;
    padding: 1;
}

#stats-panel {
    border: solid #2d3555;
    background: #1a1f35;
    padding: 1;
}

#log-panel {
    border: solid #2d3555;
    background: #1a1f35;
    padding: 1;
}

.panel-title {
    text-style: bold;
    color: #00f0ff;
    text-align: center;
    margin-bottom: 1;
}

.stat-value {
    text-style: bold;
    color: #00ff88;
}

.severity-critical {
    color: #ff3366;
    text-style: bold;
}

.severity-high {
    color: #ff6432;
    text-style: bold;
}

.severity-medium {
    color: #ffd700;
}

.severity-low {
    color: #00ff88;
}

.severity-info {
    color: #00f0ff;
}

#target-input {
    margin: 1 0;
}

#profile-select {
    margin: 1 0;
}

Button {
    margin: 0 1;
}

Button.primary {
    background: #00f0ff;
    color: #0a0e17;
}

Button.danger {
    background: #ff3366;
    color: #ffffff;
}

DataTable {
    height: 100%;
}

RichLog {
    height: 100%;
    border: solid #2d3555;
    background: #0a0e17;
    scrollbar-color: #2d3555;
    scrollbar-color-hover: #00f0ff;
}

.hidden {
    display: none;
}

#menu-bar {
    dock: top;
    height: 1;
    background: #111827;
    color: #94a3b8;
}

LoadingIndicator {
    color: #00f0ff;
}

ProgressBar Bar {
    color: #00f0ff;
}

ProgressBar PercentageStatus {
    color: #00ff88;
}

#workspace-info {
    color: #94a3b8;
    text-align: right;
    margin-right: 2;
}
"""
