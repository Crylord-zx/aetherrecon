# ⚡ AetherRecon

**Modular Cybersecurity Reconnaissance & Assessment Framework**

> ⚠️ **AUTHORIZED TARGETS ONLY** — This tool is designed for use against targets you have **explicit written authorization** to test. Unauthorized scanning is **illegal**.

---

## Features

| Category | Capabilities |
|---|---|
| **Passive Recon** | WHOIS, DNS enumeration, Certificate Transparency, Subdomain discovery, Wayback URLs |
| **Active Recon** | HTTP probing, TCP port scanning, Technology fingerprinting, TLS/SSL inspection |
| **Vuln Assessment** | Security headers analysis, CVE correlation via NIST NVD |
| **Integrations** | subfinder, amass, httpx, nuclei, naabu, katana, dnsx, ffuf, gau, nikto |
| **Reporting** | JSON, interactive HTML (cyberpunk theme), Markdown |
| **Safety** | Scope validation, blocklists, authorization prompts, audit logging |

## Quick Start

### Option 1: Kali Linux (Recommended)

```bash
git clone <repo> && cd aetherrecon
chmod +x install.sh
./install.sh
source .venv/bin/activate
```

### Option 2: pip

```bash
pip install -r requirements.txt
pip install -e .
```

### Option 3: Docker

```bash
docker compose build
docker compose run aetherrecon scan -t example.com -p safe --no-confirm
```

## Usage

```bash
# View help
aetherrecon --help

# Safe passive-only scan
aetherrecon scan -t example.com -p safe

# Standard scan (passive + light active)
aetherrecon scan -t example.com -p standard

# Full comprehensive scan
aetherrecon scan -t 192.168.1.0/24 -p full

# CTF/lab aggressive scan
aetherrecon scan -t 10.10.10.1 -p ctf --no-confirm

# Run specific modules only
aetherrecon scan -t example.com -m whois,dns_enum,cert_transparency

# Resume an interrupted scan
aetherrecon scan -t example.com -p standard --resume

# Custom config file
aetherrecon scan -t example.com -c my_config.yaml

# Check available external tools
aetherrecon check-tools

# List scanning profiles
aetherrecon profiles
```

## Scanning Profiles

| Profile | Type | Modules | Rate Limit |
|---|---|---|---|
| `safe` | Passive only | WHOIS, DNS, CT logs, subdomains | 5 req/s |
| `standard` | Passive + light active | + HTTP probe, TLS, headers | 10 req/s |
| `full` | Comprehensive | All modules | 15 req/s |
| `ctf` | Aggressive (labs only) | All modules, high concurrency | 50 req/s |

## Project Structure

```
aetherrecon/
├── config.yaml              # Configuration
├── pyproject.toml            # Project metadata
├── requirements.txt          # Dependencies
├── install.sh                # Kali installer
├── Dockerfile                # Container image
├── docker-compose.yml        # Docker Compose
├── src/aetherrecon/
│   ├── cli.py                # CLI entry point
│   ├── core/
│   │   ├── config.py         # Config loader
│   │   ├── database.py       # SQLite storage
│   │   ├── scanner.py        # Scan orchestrator
│   │   ├── scope.py          # Scope validator
│   │   ├── state.py          # Resume state manager
│   │   ├── rate_limiter.py   # Token-bucket rate limiter
│   │   └── plugin_manager.py # Plugin system
│   ├── modules/
│   │   ├── base.py           # Base module class
│   │   ├── passive/          # Passive recon modules
│   │   ├── active/           # Active recon modules
│   │   └── vuln/             # Vuln assessment modules
│   └── reporting/
│       ├── json_report.py    # JSON export
│       ├── html_report.py    # Interactive HTML report
│       └── markdown_report.py # Markdown export
├── plugins/                  # Custom plugins
│   └── example_plugin.py     # Plugin template
└── tests/                    # Unit tests
```

## Writing Plugins

Create a `.py` file in `plugins/` with a `register()` function:

```python
from aetherrecon.modules.base import BaseModule

class MyPlugin(BaseModule):
    name = "my_plugin"
    category = "vuln"

    async def run(self, target: str) -> list[dict]:
        # Your logic here
        return [{"finding": "example"}]

def register():
    return {
        "name": "my_plugin",
        "module_class": MyPlugin,
        "version": "1.0.0",
    }
```

## Configuration

Edit `config.yaml` to customize:

- **Scope rules** — blocklists, allowlists
- **Rate limits** — per-profile request throttling
- **Module settings** — ports, wordlists, resolvers
- **External tool paths** — override auto-detection
- **Report formats** — JSON, HTML, Markdown

## Safety Features

- 🛡️ **Blocklist** — `.gov`, `.mil`, `.edu`, localhost blocked by default
- ✅ **Authorization prompt** — requires explicit confirmation before scanning
- 📋 **Allowlist** — optionally restrict to pre-approved targets
- 🏠 **Private IPs** — lab/CTF ranges auto-approved
- 📝 **Audit trail** — all actions logged to SQLite database
- ⏱️ **Rate limiting** — adaptive token-bucket prevents target overload

## License

MIT — Use responsibly and only on authorized targets.
