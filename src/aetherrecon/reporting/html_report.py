"""
HTML Reporter
--------------
Generates an interactive HTML report with search, filter, and
a cyberpunk-inspired dark theme.
"""

import json
from pathlib import Path
from typing import Any

from aetherrecon.core.config import AetherConfig

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AetherRecon Report — {target}</title>
<style>
  :root {{
    --bg-primary: #0a0e17;
    --bg-secondary: #111827;
    --bg-card: #1a1f35;
    --border: #2d3555;
    --text-primary: #e2e8f0;
    --text-secondary: #94a3b8;
    --accent-cyan: #00f0ff;
    --accent-magenta: #ff00aa;
    --accent-green: #00ff88;
    --accent-yellow: #ffd700;
    --accent-red: #ff3366;
    --glow-cyan: 0 0 20px rgba(0, 240, 255, 0.3);
    --glow-magenta: 0 0 20px rgba(255, 0, 170, 0.3);
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  body {{
    font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    min-height: 100vh;
  }}

  .scanlines {{
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    background: repeating-linear-gradient(0deg, transparent, transparent 2px,
                rgba(0, 240, 255, 0.015) 2px, rgba(0, 240, 255, 0.015) 4px);
    pointer-events: none; z-index: 999;
  }}

  header {{
    background: linear-gradient(135deg, var(--bg-secondary), #0d1525);
    border-bottom: 1px solid var(--accent-cyan);
    padding: 2rem; text-align: center;
    box-shadow: var(--glow-cyan);
  }}

  header h1 {{
    font-size: 2rem;
    background: linear-gradient(90deg, var(--accent-cyan), var(--accent-magenta));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    text-transform: uppercase; letter-spacing: 4px;
  }}

  .meta {{ color: var(--text-secondary); margin-top: 0.5rem; font-size: 0.85rem; }}

  .controls {{
    display: flex; gap: 1rem; padding: 1rem 2rem;
    background: var(--bg-secondary); border-bottom: 1px solid var(--border);
    flex-wrap: wrap; align-items: center;
  }}

  .controls input, .controls select {{
    background: var(--bg-card); border: 1px solid var(--border);
    color: var(--text-primary); padding: 0.5rem 1rem;
    border-radius: 6px; font-family: inherit; font-size: 0.85rem;
  }}

  .controls input:focus, .controls select:focus {{
    outline: none; border-color: var(--accent-cyan);
    box-shadow: var(--glow-cyan);
  }}

  .controls input {{ flex: 1; min-width: 200px; }}

  main {{ padding: 2rem; max-width: 1400px; margin: 0 auto; }}

  .stats {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem; margin-bottom: 2rem;
  }}

  .stat-card {{
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: 12px; padding: 1.5rem; text-align: center;
    transition: all 0.3s;
  }}

  .stat-card:hover {{
    border-color: var(--accent-cyan); box-shadow: var(--glow-cyan);
    transform: translateY(-2px);
  }}

  .stat-card .value {{
    font-size: 2.5rem; font-weight: bold;
    background: linear-gradient(90deg, var(--accent-cyan), var(--accent-green));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  }}

  .stat-card .label {{ color: var(--text-secondary); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 2px; }}

  .module-section {{
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: 12px; margin-bottom: 1.5rem; overflow: hidden;
  }}

  .module-header {{
    padding: 1rem 1.5rem; cursor: pointer;
    display: flex; justify-content: space-between; align-items: center;
    background: linear-gradient(90deg, rgba(0,240,255,0.05), transparent);
    border-bottom: 1px solid var(--border);
  }}

  .module-header:hover {{ background: linear-gradient(90deg, rgba(0,240,255,0.1), transparent); }}
  .module-header h2 {{ font-size: 1.1rem; color: var(--accent-cyan); }}
  .module-header .count {{ color: var(--accent-green); font-size: 0.9rem; }}

  .module-body {{ padding: 1rem 1.5rem; }}

  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ text-align: left; padding: 0.75rem; border-bottom: 2px solid var(--border); color: var(--accent-cyan); text-transform: uppercase; font-size: 0.75rem; letter-spacing: 1px; }}
  td {{ padding: 0.75rem; border-bottom: 1px solid rgba(45, 53, 85, 0.5); word-break: break-all; }}
  tr:hover td {{ background: rgba(0, 240, 255, 0.03); }}

  .severity {{
    display: inline-block; padding: 0.15rem 0.6rem;
    border-radius: 4px; font-size: 0.75rem; font-weight: bold;
    text-transform: uppercase;
  }}

  .severity.critical {{ background: rgba(255,51,102,0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }}
  .severity.high {{ background: rgba(255,100,50,0.2); color: #ff6432; border: 1px solid #ff6432; }}
  .severity.medium {{ background: rgba(255,215,0,0.2); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }}
  .severity.low {{ background: rgba(0,255,136,0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }}
  .severity.info {{ background: rgba(0,240,255,0.2); color: var(--accent-cyan); border: 1px solid var(--accent-cyan); }}

  .hidden {{ display: none; }}

  footer {{
    text-align: center; padding: 2rem;
    color: var(--text-secondary); font-size: 0.8rem;
    border-top: 1px solid var(--border);
  }}

  @keyframes glow {{ 0%, 100% {{ opacity: 0.5; }} 50% {{ opacity: 1; }} }}
</style>
</head>
<body>
<div class="scanlines"></div>

<header>
  <h1>⚡ AetherRecon Report</h1>
  <div class="meta">
    Target: <strong>{target}</strong> &nbsp;|&nbsp;
    Profile: <strong>{profile}</strong> &nbsp;|&nbsp;
    {timestamp}
  </div>
</header>

<div class="controls">
  <input type="text" id="searchInput" placeholder="🔍 Search findings..." oninput="filterResults()">
  <select id="severityFilter" onchange="filterResults()">
    <option value="">All Severities</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
    <option value="info">Info</option>
  </select>
  <select id="moduleFilter" onchange="filterResults()">
    <option value="">All Modules</option>
    {module_options}
  </select>
</div>

<main>
  <div class="stats">
    {stat_cards}
  </div>

  {module_sections}
</main>

<footer>
  Generated by AetherRecon v1.0 — Authorized scanning only.
</footer>

<script>
function filterResults() {{
  const search = document.getElementById('searchInput').value.toLowerCase();
  const severity = document.getElementById('severityFilter').value;
  const module = document.getElementById('moduleFilter').value;

  document.querySelectorAll('.finding-row').forEach(row => {{
    const text = row.textContent.toLowerCase();
    const rowSev = row.dataset.severity || '';
    const rowMod = row.dataset.module || '';
    const matchText = !search || text.includes(search);
    const matchSev = !severity || rowSev === severity;
    const matchMod = !module || rowMod === module;
    row.classList.toggle('hidden', !(matchText && matchSev && matchMod));
  }});
}}

document.querySelectorAll('.module-header').forEach(header => {{
  header.addEventListener('click', () => {{
    const body = header.nextElementSibling;
    body.classList.toggle('hidden');
    header.querySelector('.toggle').textContent = body.classList.contains('hidden') ? '▶' : '▼';
  }});
}});
</script>
</body>
</html>"""


class HTMLReporter:
    def __init__(self, output_dir: Path, config: AetherConfig):
        self.output_dir = output_dir
        self.config = config

    async def generate(self, metadata: dict, results: dict[str, Any]) -> Path:
        target = metadata.get("target", "unknown")
        profile = metadata.get("profile", "N/A")
        timestamp = metadata.get("timestamp_end", "N/A")

        # Count stats
        total_findings = 0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        module_names = []

        for mod_name, mod_data in results.items():
            if mod_name in ("timestamp_start", "errors"):
                continue
            module_names.append(mod_name)
            if isinstance(mod_data, list):
                total_findings += len(mod_data)
                for item in mod_data:
                    if isinstance(item, dict):
                        sev = item.get("severity", "info")
                        if sev in severity_counts:
                            severity_counts[sev] += 1

        # Build stat cards
        stat_cards = []
        stat_cards.append(self._stat_card(str(total_findings), "Total Findings"))
        for sev, count in severity_counts.items():
            if count > 0:
                stat_cards.append(self._stat_card(str(count), sev.title()))

        stat_cards.append(self._stat_card(str(len(module_names)), "Modules Run"))
        stat_cards_html = "\n".join(stat_cards)

        # Build module options
        module_options = "\n".join(
            f'<option value="{m}">{m.replace("_", " ").title()}</option>'
            for m in module_names
        )

        # Build module sections
        sections = []
        for mod_name, mod_data in results.items():
            if mod_name in ("timestamp_start", "errors"):
                continue
            sections.append(self._build_module_section(mod_name, mod_data))

        # Build error section if any
        errors = results.get("errors", [])
        if errors:
            err_html = '<div class="module-section" style="border-color: var(--accent-red)">'
            err_html += '<div class="module-header"><h2>⚠️ Module Errors</h2><span class="count" style="color:var(--accent-red)">'
            err_html += f'{len(errors)} errors</span></div><div class="module-body"><table>'
            err_html += '<thead><tr><th>Module</th><th>Error</th></tr></thead><tbody>'
            for err in errors:
                m = err.get("module", "unknown")
                e = err.get("error", "unknown")
                err_html += f'<tr><td>{m}</td><td style="color:var(--accent-red)">{e}</td></tr>'
            err_html += '</tbody></table></div></div>'
            sections.append(err_html)

        module_sections = "\n".join(sections)

        html = HTML_TEMPLATE.format(
            target=target,
            profile=profile,
            timestamp=timestamp,
            stat_cards=stat_cards_html,
            module_options=module_options,
            module_sections=module_sections,
        )

        filename = f"aetherrecon_report_{target}.html"
        filepath = self.output_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        return filepath

    def _stat_card(self, value: str, label: str) -> str:
        return f'<div class="stat-card"><div class="value">{value}</div><div class="label">{label}</div></div>'

    def _build_module_section(self, name: str, data: Any) -> str:
        title = name.replace("_", " ").title()

        if isinstance(data, list):
            count = len(data)
            rows = self._build_table_rows(name, data)
            keys = []
            if data and isinstance(data[0], dict):
                keys = list(data[0].keys())[:6]

            headers = "".join(f"<th>{k}</th>" for k in keys) if keys else "<th>Value</th>"
            table = f"<table><thead><tr>{headers}</tr></thead><tbody>{rows}</tbody></table>"

        elif isinstance(data, dict):
            count = len(data)
            rows_html = ""
            for k, v in data.items():
                val = str(v)[:200] if not isinstance(v, (list, dict)) else f"{len(v)} items" if isinstance(v, list) else json.dumps(v)[:200]
                rows_html += f'<tr class="finding-row" data-module="{name}" data-severity="info"><td>{k}</td><td>{val}</td></tr>'
            table = f"<table><thead><tr><th>Key</th><th>Value</th></tr></thead><tbody>{rows_html}</tbody></table>"
        else:
            count = 0
            table = f"<p>{data}</p>"

        return f"""
        <div class="module-section">
          <div class="module-header">
            <h2>{title}</h2>
            <span><span class="count">{count} results</span> <span class="toggle">▼</span></span>
          </div>
          <div class="module-body">{table}</div>
        </div>"""

    def _build_table_rows(self, mod_name: str, data: list) -> str:
        rows = []
        for item in data[:100]:
            if isinstance(item, dict):
                sev = item.get("severity", "info")
                keys = list(item.keys())[:6]
                cells = ""
                for k in keys:
                    val = item.get(k, "")
                    # Visual Rendering for Screenshots
                    if isinstance(val, str) and (val.lower().endswith('.png') or val.lower().endswith('.jpg')):
                        cells += f'<td><a href="{val}" target="_blank"><img src="{val}" style="width:150px; border:1px solid var(--accent-cyan); border-radius:4px; box-shadow: var(--glow-cyan);"></a></td>'
                    elif k == "severity":
                        cells += f'<td><span class="severity {sev}">{sev}</span></td>'
                    else:
                        cells += f"<td>{str(val)[:150]}</td>"
                rows.append(f'<tr class="finding-row" data-module="{mod_name}" data-severity="{sev}">{cells}</tr>')
            else:
                rows.append(f'<tr class="finding-row" data-module="{mod_name}" data-severity="info"><td>{item}</td></tr>')
        return "\n".join(rows)
