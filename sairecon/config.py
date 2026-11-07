"""
Central configuration for SaiRecon.
Pure data — no network or subprocess work performed here.

CLI Theme: Stealth Dark + Amber
  ▓▓▒▒░░  PHASE SEPARATOR  ░░▒▒▓▓   (ASCII on Windows: ======  LABEL  ======)
  ✦ running   ✔ ok   ✘ failed   ⊘ skipped   (ASCII fallbacks on Windows)
"""
import os
import sys

VERSION = "1.0.0"

PACKAGE_DIR = os.path.dirname(__file__)
COMMON_WORDLIST = os.path.join(PACKAGE_DIR, "data", "wordlists", "common.txt")

# ---------------------------------------------------------------------------
# Platform detection  (defined early — theme constants depend on it)
# ---------------------------------------------------------------------------
IS_WINDOWS = sys.platform.startswith("win")

# ---------------------------------------------------------------------------
# CLI Theme — Stealth Dark + Amber
# Rich markup colour tokens used throughout cli.py and orchestrator logging.
# ---------------------------------------------------------------------------
CLR_BANNER = "bold orange1"       # amber/gold  — banner + headings
CLR_TARGET = "bold bright_white"  # target domain
CLR_MODULE = "bold white"         # module names
CLR_OK     = "bold green"         # success
CLR_FAIL   = "bold red"           # failure
CLR_SKIP   = "dim"                # skipped / secondary text
CLR_WARN   = "bold yellow"        # warnings
CLR_INFO   = "cyan"               # informational
CLR_DIM    = "grey50"             # secondary / timestamps
CLR_PHASE  = "bold orange1"       # phase separators

# Status symbols — Windows falls back to pure ASCII so spacing is preserved.
SYM_RUNNING = "*"  if IS_WINDOWS else "✦"
SYM_OK      = "+"  if IS_WINDOWS else "✔"
SYM_FAIL    = "!"  if IS_WINDOWS else "✘"
SYM_SKIP    = "-"  if IS_WINDOWS else "⊘"
SYM_ARROW   = "->" if IS_WINDOWS else "→"
_ICON       = "#"  if IS_WINDOWS else "⬡"  # title icon


def phase_sep(label: str, width: int = 60) -> str:
    """Return a ▓▒░ gradient-block separator (Rich markup).

    On Windows, returns a pure-ASCII ``======  LABEL  ======`` line so that
    terminal spacing and column widths are never affected by multi-byte chars.
    """
    if IS_WINDOWS:
        pad = "=" * 6
        return f"\n{pad}  {label}  {pad}\n"
    inner = f"  {label}  "
    fill = max(0, (width - len(inner)) // 2)
    block = ("▓▓▒▒░░" * 10)[:fill] if fill >= 6 else "░" * fill
    return f"\n[bold orange1]{block}{inner}{block[::-1]}[/bold orange1]\n"


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
BANNER = r"""
 ____        _ ____
/ ___|  __ _(_) |  _ \ ___  ___ ___  _ __
\___ \ / _` | | |_) / _ \/ __/ _ \| '_ \
 ___) | (_| | | |  _ <  __/ (_| (_) | | | |
|____/ \__,_|_|_| \_\___|\___\___/|_| |_|

      One CLI. Every recon source. No attack code.
"""

DEFAULT_OUTPUT_DIR = os.path.join(os.getcwd(), "sairecon_output")
DEFAULT_CONCURRENCY = 8
DEFAULT_HTTP_TIMEOUT = 10

# ---------------------------------------------------------------------------
# Required external tools.
# All tools are optional at import time — modules degrade gracefully when a
# binary is absent (Python-native fallback or SKIPPED finding).
# ---------------------------------------------------------------------------
REQUIRED_TOOLS = {
    "subfinder":         {"used_by": "subdomain_enum",
                          "install_linux":   "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                          "install_windows": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    "assetfinder":       {"used_by": "subdomain_enum",
                          "install_linux":   "go install github.com/tomnomnom/assetfinder@latest",
                          "install_windows": "go install github.com/tomnomnom/assetfinder@latest"},
    "findomain":         {"used_by": "subdomain_enum",
                          "install_linux":   "see install_tools.sh (downloads prebuilt binary)",
                          "install_windows": "download from github.com/Findomain/Findomain/releases"},
    "github-subdomains": {"used_by": "subdomain_enum",
                          "install_linux":   "go install github.com/gwen001/github-subdomains@latest",
                          "install_windows": "go install github.com/gwen001/github-subdomains@latest"},
    "dnsx":              {"used_by": "subdomain_enum / live_recon",
                          "install_linux":   "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
                          "install_windows": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
    "alterx":            {"used_by": "subdomain_enum (--deep)",
                          "install_linux":   "go install github.com/projectdiscovery/alterx/cmd/alterx@latest",
                          "install_windows": "go install github.com/projectdiscovery/alterx/cmd/alterx@latest"},
    "puredns":           {"used_by": "subdomain_enum (--deep)",
                          "install_linux":   "go install github.com/d3mondev/puredns/v2@latest",
                          "install_windows": "not officially supported on Windows"},
    "httpx":             {"used_by": "live_recon",
                          "install_linux":   "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
                          "install_windows": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    "naabu":             {"used_by": "port_scan",
                          "install_linux":   "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
                          "install_windows": "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
    "nmap":              {"used_by": "port_scan",
                          "install_linux":   "apt install nmap",
                          "install_windows": "https://nmap.org/download.html"},
    "tlsx":              {"used_by": "ssl_cert",
                          "install_linux":   "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
                          "install_windows": "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest"},
    "whatweb":           {"used_by": "techstack",
                          "install_linux":   "apt install whatweb (or gem install whatweb)",
                          "install_windows": "gem install whatweb  (requires Ruby)"},
    "katana":            {"used_by": "url_discovery",
                          "install_linux":   "go install github.com/projectdiscovery/katana/cmd/katana@latest",
                          "install_windows": "go install github.com/projectdiscovery/katana/cmd/katana@latest"},
    "gau":               {"used_by": "url_discovery",
                          "install_linux":   "go install github.com/lc/gau/v2/cmd/gau@latest",
                          "install_windows": "go install github.com/lc/gau/v2/cmd/gau@latest"},
    "waybackurls":       {"used_by": "url_discovery",
                          "install_linux":   "go install github.com/tomnomnom/waybackurls@latest",
                          "install_windows": "go install github.com/tomnomnom/waybackurls@latest"},
    "gf":                {"used_by": "url_discovery / js_secrets",
                          "install_linux":   "go install github.com/tomnomnom/gf@latest  (+ clone Gf-Patterns)",
                          "install_windows": "go install github.com/tomnomnom/gf@latest  (+ clone Gf-Patterns)"},
    "anew":              {"used_by": "subdomain_enum / url_discovery",
                          "install_linux":   "go install github.com/tomnomnom/anew@latest",
                          "install_windows": "go install github.com/tomnomnom/anew@latest"},
    "unfurl":            {"used_by": "url_discovery",
                          "install_linux":   "go install github.com/tomnomnom/unfurl@latest",
                          "install_windows": "go install github.com/tomnomnom/unfurl@latest"},
    "gowitness":         {"used_by": "screenshot",
                          "install_linux":   "go install github.com/sensepost/gowitness@latest",
                          "install_windows": "go install github.com/sensepost/gowitness@latest"},
    "asnmap":            {"used_by": "asn_cloud_recon",
                          "install_linux":   "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest  (needs PDCP_API_KEY)",
                          "install_windows": "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest  (needs PDCP_API_KEY)"},
    "mapcidr":           {"used_by": "asn_cloud_recon",
                          "install_linux":   "go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest",
                          "install_windows": "go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"},
    "wafw00f":           {"used_by": "waf_detect",
                          "install_linux":   "pip install wafw00f",
                          "install_windows": "pip install wafw00f"},
    "ffuf":              {"used_by": "content_discovery",
                          "install_linux":   "go install github.com/ffuf/ffuf/v2@latest",
                          "install_windows": "go install github.com/ffuf/ffuf/v2@latest"},
    "arjun":             {"used_by": "param_discovery",
                          "install_linux":   "pip install arjun",
                          "install_windows": "pip install arjun"},
    "uncover":           {"used_by": "passive_exposure",
                          "install_linux":   "go install github.com/projectdiscovery/uncover/cmd/uncover@latest",
                          "install_windows": "go install github.com/projectdiscovery/uncover/cmd/uncover@latest"},
    # System tools with Python fallbacks on Windows
    "whois":             {"used_by": "whois_recon",
                          "install_linux":   "apt install whois",
                          "install_windows": "python-whois pip dep used as fallback (no binary needed)"},
    "dig":               {"used_by": "dns_recon / email_security",
                          "install_linux":   "apt install dnsutils",
                          "install_windows": "dnspython pip dep used as fallback (no binary needed)"},
}

# Nice-to-have: module partially degrades without these but still runs.
OPTIONAL_TOOLS = [
    "findomain", "github-subdomains", "alterx", "puredns",
    "whatweb", "gf", "anew", "unfurl",
]

# Run once against the apex domain, never per-subdomain.
DOMAIN_LEVEL_MODULES = {
    "whois_recon", "dns_recon", "email_security", "subdomain_enum",
    "asn_cloud_recon", "passive_exposure", "param_discovery", "breach_check",
}

MODULE_ORDER = [
    "whois_recon",
    "dns_recon",
    "subdomain_enum",
    "asn_cloud_recon",
    "passive_exposure",
    "live_recon",
    "subdomain_takeover",
    "port_scan",
    "ssl_cert",
    "techstack",
    "waf_detect",
    "security_posture",
    "email_security",
    "url_discovery",
    "content_discovery",
    "param_discovery",
    "js_secrets",
    "wayback_robots",
    "sensitive_files",
    "screenshot",
    "breach_check",
]
