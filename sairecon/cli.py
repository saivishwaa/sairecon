"""
SaiRecon CLI — `sairecon scan <target>` and `sairecon doctor`.
Works on Linux (Kali/Ubuntu/Debian), macOS, and Windows (Python 3.9+).

Theme: Stealth Dark + Amber
  ▓▓▒▒░░  PHASE SEPARATOR  ░░▒▒▓▓
  ✦ running   ✔ ok   ✘ failed   ⊘ skipped   (ASCII fallbacks on Windows)
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Callable

from rich.console import Console
from rich.table import Table

from sairecon.config import (
    BANNER, MODULE_ORDER, REQUIRED_TOOLS, OPTIONAL_TOOLS, VERSION,
    DEFAULT_OUTPUT_DIR, DEFAULT_CONCURRENCY, IS_WINDOWS, _ICON,
    CLR_MODULE, CLR_OK, CLR_FAIL, CLR_SKIP, CLR_WARN, CLR_INFO, CLR_DIM,
    CLR_PHASE, CLR_TARGET, CLR_BANNER,
    SYM_RUNNING, SYM_OK, SYM_FAIL, SYM_SKIP,
    phase_sep,
)
from sairecon.utils import parse_target, make_scan_output_dir, tool_exists

console = Console()


# ---------------------------------------------------------------------------
# Shared log callback — passed to ReconOrchestrator for per-module messages
# ---------------------------------------------------------------------------

def _make_log_cb() -> Callable:
    def log_cb(module: str, message: str) -> None:
        msg_lower = message.lower()
        if "skipped" in msg_lower or "skip" in msg_lower:
            sym = f"[{CLR_SKIP}]{SYM_SKIP}[/{CLR_SKIP}]"
        elif any(x in msg_lower for x in ("error", "failed", "fail", "exception")):
            sym = f"[{CLR_FAIL}]{SYM_FAIL}[/{CLR_FAIL}]"
        elif any(x in msg_lower for x in ("done", "found", "complete", "ok", "completed")):
            sym = f"[{CLR_OK}]{SYM_OK}[/{CLR_OK}]"
        else:
            sym = f"[{CLR_INFO}]{SYM_RUNNING}[/{CLR_INFO}]"
        console.print(f"  {sym} [[{CLR_MODULE}]{module}[/{CLR_MODULE}]] {message}")
    return log_cb


# ---------------------------------------------------------------------------
def cmd_scan(args: argparse.Namespace) -> None:
    try:
        target = parse_target(args.target)
    except ValueError as e:
        console.print(f"[{CLR_FAIL}]Invalid target:[/{CLR_FAIL}] {e}")
        sys.exit(1)

    # Authorisation gate
    if not args.yes:
        console.print(f"\n[{CLR_TARGET}]Target:[/{CLR_TARGET}]   {target.raw}")
        console.print(
            f"[{CLR_TARGET}]Scope:[/{CLR_TARGET}]    "
            f"{'Full wildcard recon' if target.is_wildcard else 'Single host'}"
        )
        console.print(
            f"\n[{CLR_WARN}]IMPORTANT:[/{CLR_WARN}] Only scan domains you are "
            "explicitly authorised to test (active bug-bounty scope, your own "
            "assets, or a written pentest contract).\n"
        )
        try:
            confirm = input("Type 'yes' to confirm authorisation and proceed: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            confirm = ""
        if confirm != "yes":
            console.print(f"[{CLR_WARN}]Scan aborted.[/{CLR_WARN}]")
            sys.exit(0)

    # Module list
    modules_to_run = None
    if args.modules:
        modules_to_run = [m.strip() for m in args.modules.split(",") if m.strip()]
    if args.skip_modules:
        skip = {m.strip() for m in args.skip_modules.split(",") if m.strip()}
        base = modules_to_run or MODULE_ORDER
        modules_to_run = [m for m in base if m not in skip]

    base_output = args.output or DEFAULT_OUTPUT_DIR
    output_dir = make_scan_output_dir(base_output, target.raw)

    # --- Banner + scan header ---
    console.print(f"[{CLR_BANNER}]{BANNER}[/{CLR_BANNER}]")
    console.print(f"[{CLR_BANNER}]{_ICON} SaiRecon v{VERSION}[/{CLR_BANNER}]\n")
    console.print(phase_sep("SCAN CONFIGURATION"))
    console.print(f"  [{CLR_INFO}]Target:[/{CLR_INFO}]     [{CLR_TARGET}]{target.raw}[/{CLR_TARGET}]")
    console.print(f"  [{CLR_INFO}]Output:[/{CLR_INFO}]     [{CLR_DIM}]{output_dir}[/{CLR_DIM}]")
    console.print(f"  [{CLR_INFO}]Threads:[/{CLR_INFO}]    [{CLR_DIM}]{args.concurrency}[/{CLR_DIM}]")

    from sairecon.core.orchestrator import ReconOrchestrator

    result = ReconOrchestrator(
        target=target,
        modules_to_run=modules_to_run,
        output_dir=output_dir,
        concurrency=args.concurrency,
        log_callback=_make_log_cb(),
    ).run()

    # --- Reports ---
    clean_target = target.raw.lstrip("*").lstrip(".")
    prefix = "wildcard_" if target.raw.startswith("*") else ""
    file_stem = f"{prefix}{clean_target}"

    from sairecon.report.exporter import export_json, export_markdown
    from sairecon.report.renderer import render_html

    fmt = (args.format or "all").lower()

    json_path = os.path.join(output_dir, f"{file_stem}.json")
    html_path = os.path.join(output_dir, f"{file_stem}.html")
    md_path   = os.path.join(output_dir, f"{file_stem}.md")

    console.print(phase_sep("REPORTS"))
    if fmt in ("json", "all"):
        p = export_json(result, json_path)
        if p:
            console.print(f"  [{CLR_OK}]{SYM_OK}[/{CLR_OK}] JSON      [{CLR_DIM}]{p}[/{CLR_DIM}]")
        else:
            console.print(f"  [{CLR_FAIL}]{SYM_FAIL}[/{CLR_FAIL}] JSON export failed")
    if fmt in ("html", "all"):
        p = render_html(result, html_path)
        if p:
            console.print(f"  [{CLR_OK}]{SYM_OK}[/{CLR_OK}] HTML      [{CLR_DIM}]{p}[/{CLR_DIM}]")
        else:
            console.print(f"  [{CLR_FAIL}]{SYM_FAIL}[/{CLR_FAIL}] HTML export failed")
    if fmt in ("markdown", "md", "all"):
        p = export_markdown(result, md_path)
        if p:
            console.print(f"  [{CLR_OK}]{SYM_OK}[/{CLR_OK}] Markdown  [{CLR_DIM}]{p}[/{CLR_DIM}]")
        else:
            console.print(f"  [{CLR_FAIL}]{SYM_FAIL}[/{CLR_FAIL}] Markdown export failed")

    # --- Summary table ---
    findings = result.get("findings", [])
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        s = f.get("severity")
        if s in sev:
            sev[s] += 1

    modules_status = result.get("modules_status", {})
    ok_count   = sum(1 for s in modules_status.values() if s == "ok")
    fail_count = sum(1 for s in modules_status.values() if s == "failed")
    skip_count = sum(1 for s in modules_status.values() if s == "skipped")

    console.print(phase_sep("SCAN COMPLETE"))

    table = Table(
        show_header=True,
        header_style="bold orange1",
        border_style="grey50",
        show_lines=False,
    )
    table.add_column("Metric",  style="dim",     min_width=22)
    table.add_column("Value",   justify="right", min_width=14)

    table.add_row("Target",         f"[{CLR_TARGET}]{target.raw}[/{CLR_TARGET}]")
    table.add_row("Duration",       f"[{CLR_DIM}]{result.get('duration_sec')}s[/{CLR_DIM}]")
    table.add_row("Resolved hosts", str(len(result.get("resolved_hosts", []))))
    table.add_row("Live hosts",     str(len(result.get("live_hosts", []))))
    table.add_row("Total findings", f"[bold]{len(findings)}[/bold]")
    table.add_row("[red]Critical[/red]",                          str(sev["critical"]))
    table.add_row("[orange3]High[/orange3]",                      str(sev["high"]))
    table.add_row("[yellow]Medium[/yellow]",                      str(sev["medium"]))
    table.add_row("[blue]Low[/blue]",                             str(sev["low"]))
    table.add_row(f"[{CLR_OK}]Modules OK[/{CLR_OK}]",            str(ok_count))
    table.add_row(f"[{CLR_FAIL}]Modules Failed[/{CLR_FAIL}]",    str(fail_count))
    table.add_row(f"[{CLR_SKIP}]Modules Skipped[/{CLR_SKIP}]",   str(skip_count))
    table.add_row("Output folder",  f"[{CLR_DIM}]{output_dir}[/{CLR_DIM}]")
    console.print(table)

    if fail_count:
        console.print(
            f"\n[{CLR_WARN}]  {SYM_RUNNING} {fail_count} module(s) reported errors "
            f"— check findings for details.[/{CLR_WARN}]"
        )
    console.print(f"\n[{CLR_OK}]  {SYM_OK} Scan finished.[/{CLR_OK}]\n")


# ---------------------------------------------------------------------------
def cmd_doctor(_args: argparse.Namespace) -> None:
    console.print(f"[{CLR_BANNER}]{BANNER}[/{CLR_BANNER}]")
    console.print(f"[{CLR_BANNER}]{_ICON} SaiRecon v{VERSION}[/{CLR_BANNER}]  —  doctor\n")

    platform_key = "install_windows" if IS_WINDOWS else "install_linux"

    console.print(phase_sep("EXTERNAL TOOL STATUS"))

    table = Table(
        show_header=True,
        header_style="bold orange1",
        border_style="grey50",
        show_lines=False,
    )
    table.add_column("Tool",         style="bold", min_width=20)
    table.add_column("Status",       justify="center", min_width=12)
    table.add_column("Used by",      style="dim",  min_width=20)
    table.add_column("Install hint", style="dim",  overflow="fold")

    missing_required = []
    for tool, info in REQUIRED_TOOLS.items():
        present  = tool_exists(tool)
        optional = tool in OPTIONAL_TOOLS
        if present:
            status = f"[{CLR_OK}]{SYM_OK} found[/{CLR_OK}]"
        elif optional:
            status = f"[{CLR_SKIP}]{SYM_SKIP} optional[/{CLR_SKIP}]"
        else:
            status = f"[{CLR_FAIL}]{SYM_FAIL} missing[/{CLR_FAIL}]"
            missing_required.append(tool)
        table.add_row(tool, status, info.get("used_by", ""), info.get(platform_key, ""))

    console.print(table)

    if missing_required:
        console.print(f"\n[{CLR_FAIL}]Missing required tools:[/{CLR_FAIL}] {', '.join(missing_required)}")
        script = "install_tools_windows.ps1" if IS_WINDOWS else "install_tools.sh"
        console.print(f"Run [bold]./{script}[/bold] to install everything automatically.")
    else:
        console.print(f"\n[{CLR_OK}]{SYM_OK} All required tools present![/{CLR_OK}]")

    # Python deps
    console.print(phase_sep("PYTHON DEPENDENCIES"))
    py_deps = {
        "requests":     "requests",
        "dnspython":    "dns",
        "python-whois": "whois",
        "jinja2":       "jinja2",
        "rich":         "rich",
        "mmh3":         "mmh3",
    }
    for pkg, imp in py_deps.items():
        try:
            __import__(imp)
            console.print(f"  [{CLR_OK}]{SYM_OK}[/{CLR_OK}] {pkg}")
        except ImportError:
            console.print(f"  [{CLR_FAIL}]{SYM_FAIL}[/{CLR_FAIL}] {pkg}  "
                          f"[{CLR_DIM}]{SYM_ARROW}  pip install {pkg}[/{CLR_DIM}]")

    # API keys
    console.print(phase_sep("API KEY STATUS"))
    keys = {
        "GITHUB_TOKEN":      "github-subdomains (more subdomain sources)",
        "PDCP_API_KEY":      "asnmap (ASN/CIDR mapping)",
        "SHODAN_API_KEY":    "uncover (passive asset search)",
        "CENSYS_API_ID":     "uncover (Censys passive search)",
        "CENSYS_API_SECRET": "uncover (Censys passive search)",
    }
    for var, desc in keys.items():
        val = os.environ.get(var, "")
        if val:
            console.print(f"  [{CLR_OK}]{SYM_OK}[/{CLR_OK}] [{CLR_INFO}]{var}[/{CLR_INFO}] set  "
                          f"[{CLR_DIM}]({desc})[/{CLR_DIM}]")
        else:
            console.print(f"  [{CLR_SKIP}]{SYM_SKIP}[/{CLR_SKIP}] [{CLR_DIM}]{var} not set  "
                          f"({desc})[/{CLR_DIM}]")
    console.print()


# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sairecon",
        description=f"SaiRecon v{VERSION} — full recon pipeline, no attack code.",
    )
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="Run a full recon scan.")
    p_scan.add_argument("target",
                        help="Target: *.example.com  or  example.com  or  sub.example.com")
    p_scan.add_argument("--modules",
                        help="Comma-separated modules to run (default: all 21).")
    p_scan.add_argument("--skip-modules",
                        help="Comma-separated modules to skip.")
    p_scan.add_argument("--format",
                        choices=["json", "html", "markdown", "md", "all"],
                        default="all",
                        help="Report format (default: all — html + json + markdown).")
    p_scan.add_argument("-o", "--output",
                        help="Base output directory (default: ./sairecon_output).")
    p_scan.add_argument("-y", "--yes", action="store_true",
                        help="Skip authorisation prompt (CI mode).")
    p_scan.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                        help=f"Thread pool size (default: {DEFAULT_CONCURRENCY}).")

    sub.add_parser("doctor", help="Check tool + API key status.")

    args = parser.parse_args()
    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "doctor":
        cmd_doctor(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
