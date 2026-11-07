<div align="center">

```
=====================================================================
  =====     ===    ====  ======   ======   ====    ======  ==   ==
 ==        == ==    ==   ==   ==  ==      ==  ==  ==    == ===  ==
  ====    ==   ==   ==   ======   =====   ==      ==    == == = ==
     ==   =======   ==   ==  ==   ==      ==  ==  ==    == ==  ===
 =====    ==   ==  ====  ==   ==  ======   ====    ======  ==   ==
=====================================================================
```

**One CLI. 21 recon modules. Zero attack code.**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)]()

</div>

---

SaiRecon aggregates the best open-source recon tools (subfinder, httpx, naabu, katana…) into a single, authorised pipeline. One command → 21 modules → clean JSON + HTML + Markdown reports.

---

## Table of Contents

1. [Installation](#installation)
2. [Quick start](#quick-start)
3. [Usage reference](#usage-reference)
4. [21 Modules](#21-modules)
5. [Architecture](#architecture)
6. [Output & reports](#output--reports)
7. [API keys](#api-keys)
8. [Troubleshooting](#troubleshooting)
9. [Contributing](#contributing)
10. [Legal & ethical use](#legal--ethical-use)

---

## Installation

### Option A — pip from GitHub (recommended, no git clone needed)

```bash
pip install git+https://github.com/saivishwaa/sairecon.git
```

That's it. The `sairecon` command is now available anywhere.

---

### Option B — Clone + pip install (for development / modifying code)

```bash
git clone https://github.com/saivishwaa/sairecon.git
cd sairecon
pip install -e .          # -e = editable, changes to source take effect immediately
sairecon doctor           # verify setup
```

---

### Option C — Full installer (Linux/Kali — installs Go tools too)

```bash
git clone https://github.com/saivishwaa/sairecon.git
cd sairecon
chmod +x install_tools.sh
./install_tools.sh
```

The script installs: system packages → Go 1.22 → all 18 Go tools → Python venv → pip deps → gf patterns → API key prompts → `/usr/local/bin/sairecon` wrapper.

---

### Option D — Windows PowerShell

```powershell
git clone https://github.com/saivishwaa/sairecon.git
cd sairecon
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
.\install_tools_windows.ps1
```

---

### Option E — Docker

```bash
docker build -t sairecon .
docker run --rm -v "$(pwd)/reports:/app/sairecon_output" sairecon scan example.com --yes
```

---

### Option F — Python-only (no Go tools, works everywhere)

```bash
pip install git+https://github.com/saivishwaa/sairecon.git
sairecon doctor             # shows which Go tools are missing (optional)
sairecon scan example.com   # works with Python-native fallbacks
```

> Python-only mode runs: whois, dns, email_security, security_posture, wayback_robots, sensitive_files, breach_check, ssl_cert (stdlib), and passive URL archive. Go tools unlock the full pipeline speed.

---

## Quick start

```bash
# After any install method above:
sairecon doctor                # check tools + API keys

sairecon scan example.com      # single domain (most common)
sairecon scan "*.example.com"  # wildcard — full scope
sairecon scan admin.example.com # single subdomain

# Fast scan (skip heavy modules)
sairecon scan example.com \
  --skip-modules screenshot,content_discovery,param_discovery

# Specific modules only
sairecon scan example.com \
  --modules whois_recon,dns_recon,subdomain_enum,live_recon,port_scan

# CI / automation (no interactive prompt)
sairecon scan example.com --yes --format json

# Custom output directory
sairecon scan example.com -o /tmp/my-recon
```

---

## Usage reference

```
sairecon scan <target> [OPTIONS]

ARGUMENTS
  target        *.example.com  |  example.com  |  sub.example.com

OPTIONS
  --modules       Comma-separated modules to run  (default: all 21)
  --skip-modules  Comma-separated modules to skip
  --format        json | html | markdown | md | all  (default: all)
  -o, --output    Base output directory  (default: ./sairecon_output)
  -y, --yes       Skip authorisation prompt  (CI mode)
  --concurrency   Thread pool size  (default: 8)
  -h, --help      Show help

sairecon doctor   Check all external tools and API keys
```

### All 21 module keys (for --modules / --skip-modules)

```
whois_recon         dns_recon           subdomain_enum
asn_cloud_recon     passive_exposure    live_recon
subdomain_takeover  port_scan           ssl_cert
techstack           waf_detect          security_posture
email_security      url_discovery       content_discovery
param_discovery     js_secrets          wayback_robots
sensitive_files     screenshot          breach_check
```

---

## 21 Modules

| # | Module key | What it does | Go tools | Python fallback |
|---|---|---|---|---|
| 1 | `whois_recon` | WHOIS registration data | `whois` binary | python-whois ✓ |
| 2 | `dns_recon` | Full DNS record enumeration | `dig` | dnspython ✓ |
| 3 | `subdomain_enum` | Multi-source subdomain discovery + DNS resolution | subfinder, assetfinder, findomain, github-subdomains, dnsx | archive only |
| 4 | `asn_cloud_recon` | ASN → CIDR mapping, cloud provider detection | asnmap, mapcidr | ipwhois ✓ |
| 5 | `passive_exposure` | Internet-wide asset discovery | uncover (Shodan/Censys) | needs API keys |
| 6 | `live_recon` | HTTP/S probe — status, title, tech, redirects | httpx | requests ✓ |
| 7 | `subdomain_takeover` | Unclaimed CNAME detection | Python logic | — |
| 8 | `port_scan` | Top-1000 ports + service banners | naabu + nmap | nmap only |
| 9 | `ssl_cert` | TLS cert details, expiry, SANs | tlsx | ssl stdlib ✓ |
| 10 | `techstack` | Web framework / CMS fingerprinting | whatweb | header parse ✓ |
| 11 | `waf_detect` | WAF / CDN identification | wafw00f | header heuristics ✓ |
| 12 | `security_posture` | Security headers audit (CSP, HSTS…) | — | requests ✓ |
| 13 | `email_security` | SPF, DMARC, DKIM, MTA-STS | — | dnspython ✓ |
| 14 | `url_discovery` | Crawl + archive URL collection | katana, gau, waybackurls | archive ✓ |
| 15 | `content_discovery` | Directory/file brute-force | ffuf | skipped |
| 16 | `param_discovery` | Query parameter enumeration | arjun | skipped |
| 17 | `js_secrets` | API keys/tokens in JS files | gf patterns | regex ✓ |
| 18 | `wayback_robots` | Historical robots.txt from Wayback | — | requests ✓ |
| 19 | `sensitive_files` | Sensitive path probe (.env, .git…) | — | requests ✓ |
| 20 | `screenshot` | Full-page screenshots | gowitness | skipped |
| 21 | `breach_check` | HaveIBeenPwned domain breach lookup | — | requests ✓ |

---

## Architecture

```
sairecon scan *.example.com
        │
        ▼
  ┌─────────────────────────────────┐
  │         cli.py                  │
  │   Theme: Stealth Dark + Amber   │
  │   ▓▓▒▒░░  PHASE  ░░▒▒▓▓         │  ← amber gradient separators
  │   ✦ running  ✔ ok  ✘ failed      │  ← status icons (ASCII on Windows)
  └────────────┬────────────────────┘
               │
               ▼
  ┌────────────────────────────────────────────────────────────┐
  │                 ReconOrchestrator.run()                    │
  │                                                            │
  │  ┌── DOMAIN LEVEL ──────────────────────────────────────┐  │
  │  │  whois_recon, dns_recon, subdomain_enum,             │  │
  │  │  asn_cloud_recon, passive_exposure, email_security   │  │
  │  └──────────────────────────────────────────────────────┘  │
  │                           │                                │
  │               resolved_hosts (from subdomain_enum)         │
  │                           │                                │
  │  ┌── HOST LEVEL ───────────▼────────────────────────────┐  │
  │  │  live_recon → live_hosts                             │  │
  │  │  subdomain_takeover, port_scan, ssl_cert, waf_detect │  │
  │  └──────────────────────────────────────────────────────┘  │
  │                           │                                │
  │               live_hosts (from live_recon)                 │
  │                           │                                │
  │  ┌── HTTP LEVEL ───────────▼────────────────────────────┐  │
  │  │  techstack, security_posture, url_discovery,         │  │
  │  │  content_discovery, js_secrets, wayback_robots,      │  │
  │  │  sensitive_files, screenshot                         │  │
  │  └──────────────────────────────────────────────────────┘  │
  │                                                            │
  │  Every module wrapped in try/except — one crash ≠ stop    │
  └──────────────┬─────────────────────────────────────────────┘
                 ▼
  modules_status: {whois_recon: "ok", screenshot: "skipped", ...}
  modules_timing: {whois_recon: 2.1, subdomain_enum: 45.3, ...}
                 │
       ┌──────────┴──────────┐
       ▼          ▼          ▼
   report.json  report.html  report.md
```

---

## Output & reports

```
./sairecon_output/example.com_20261101_120000/
├── example.com.json       ← machine-readable, all findings + metadata
├── example.com.html       ← interactive HTML with severity colours
└── example.com.md         ← Markdown for GitHub issues / notes
```

Wildcard scans:

```
./sairecon_output/wildcard_example.com_20261101_120000/
```

### JSON structure

```json
{
  "sairecon_version": "1.0.0",
  "target_raw": "*.example.com",
  "apex_domain": "example.com",
  "started_at": "2026-11-01T12:00:00+00:00",
  "duration_sec": 182.4,
  "resolved_hosts": ["sub1.example.com", "sub2.example.com"],
  "live_hosts":     ["https://sub1.example.com"],
  "modules_run":    ["whois_recon", "dns_recon"],
  "modules_status": {"whois_recon": "ok", "screenshot": "skipped"},
  "modules_timing": {"whois_recon": 2.1, "subdomain_enum": 45.3},
  "findings": [
    {
      "title": "WHOIS Record for example.com",
      "command": "whois example.com",
      "source_module": "whois_recon",
      "severity": null,
      "result": { ... }
    }
  ]
}
```

---

## API keys

Set in `.env` (the installer prompts for them), or export as environment variables:

| Variable | Where to get | Unlocks |
|---|---|---|
| `GITHUB_TOKEN` | github.com → Settings → Developer → Personal access tokens → Tokens (classic) | `github-subdomains` (many more subdomains) |
| `PDCP_API_KEY` | app.projectdiscovery.io → API keys (free tier) | `asnmap` (ASN/CIDR mapping) |
| `SHODAN_API_KEY` | account.shodan.io → My Account | `uncover` Shodan passive search |
| `CENSYS_API_ID` + `CENSYS_API_SECRET` | search.censys.io → Account → API | `uncover` Censys passive search |

**Without any API keys**, SaiRecon still runs 18/21 modules using public APIs and Python-native fallbacks.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `sairecon: command not found` | Run `source ~/.bashrc` or `export PATH="$PATH:$HOME/.local/bin"` |
| Go tools missing after install | Ensure `export PATH="$PATH:$HOME/go/bin"` is in `~/.bashrc` |
| `subdomain_enum` returns 0 results | Install at least one of: subfinder, assetfinder, findomain |
| Module shows `skipped` | Expected: HTTP modules skip when no live hosts found. Tool modules skip when binary missing. |
| `content_discovery` very slow | Use `--skip-modules content_discovery` for quick scans |
| Windows: garbled output | Run `chcp 65001` first, or use Windows Terminal |
| ImportError | `pip install -r requirements.txt` inside the virtualenv |
| SSL/TLS errors | `pip install --upgrade certifi` |

---

## Contributing

Contributions from the community are welcome! SaiRecon is an open-source tool, and we appreciate bug reports, feature requests, and pull requests.

### Development Setup

1. **Fork the repository** on GitHub.
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/sairecon.git
   cd sairecon
   ```
3. **Create a new branch** for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. **Install in editable mode**:
   ```bash
   pip install -e .
   ```
5. **Make your changes** and test your module or improvement.
6. **Commit your changes**:
   ```bash
   git commit -m "feat: add your feature description"
   ```
7. **Push to your branch**:
   ```bash
   git push origin feature/your-feature-name
   ```
8. **Open a Pull Request** on GitHub.

### Adding a new module

```python
# sairecon/modules/my_mod.py
from sairecon.core.base import BaseModule

class MyModule(BaseModule):
    name = "my_check"
    description = "Does something useful"
    required_tools = ["mytool"]   # or [] for pure Python

    def execute(self):
        if not self.guard_required_tools():
            return self.findings

        # Use specific exception types, not bare except:
        try:
            result = self.run(["mytool", "--target", self.target])
        except FileNotFoundError:
            self.log("mytool binary not found")
            return self.findings

        self.add_finding(
            title="My finding",
            command=f"mytool --target {self.target}",
            result={"status": "ok", "data": {}},
            severity="low",   # critical | high | medium | low | None
        )
        return self.findings
```

Then register the module in `orchestrator.py` → `MODULE_REGISTRY` and `config.py` → `MODULE_ORDER`.

---

## Legal & ethical use

> ⚠️ **You must have explicit written authorisation to scan any target that is not your own.**

SaiRecon performs real network requests and DNS lookups. It contains no exploit code, no attack payloads, and no vulnerability confirmation.

Acceptable targets:
- Your own domains and infrastructure
- Bug bounty programme in-scope targets (check scope carefully)
- Signed pentest agreement targets

Unauthorised scanning may violate the CFAA (USA), CMA (UK), and similar laws worldwide.
**The author accepts no liability for misuse.**

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

Made by [Sai Vishwaa](https://github.com/saivishwaa) · Built on tools by [ProjectDiscovery](https://github.com/projectdiscovery), [tomnomnom](https://github.com/tomnomnom) and many others.

*SaiRecon — recon only, no attack code.*

</div>
