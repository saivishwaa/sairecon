"""
Shared helpers: subprocess execution, tool detection, target parsing,
unique output-path generation.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional


IS_WINDOWS = sys.platform.startswith("win")


def tool_exists(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None


@dataclass
class CommandResult:
    cmd: str
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration_sec: float = 0.0


def run_command(
    cmd_args: List[str],
    timeout_sec: int = 120,
    input_text: Optional[str] = None,
) -> CommandResult:
    cmd_str = " ".join(cmd_args)
    start = time.time()
    try:
        proc = subprocess.run(
            cmd_args,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
        return CommandResult(
            cmd=cmd_str,
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            duration_sec=round(time.time() - start, 2),
        )
    except subprocess.TimeoutExpired as e:
        partial_stdout = ""
        if e.stdout:
            partial_stdout = e.stdout.decode("utf-8", errors="ignore") if isinstance(e.stdout, bytes) else e.stdout
        return CommandResult(
            cmd=cmd_str,
            returncode=-1,
            stdout=partial_stdout,
            stderr=f"Command timed out after {timeout_sec}s",
            timed_out=True,
            duration_sec=round(time.time() - start, 2),
        )
    except FileNotFoundError:
        return CommandResult(cmd=cmd_str, returncode=127,
                             stderr=f"Executable not found: {cmd_args[0]}")
    except Exception as e:
        return CommandResult(cmd=cmd_str, returncode=-1, stderr=str(e))


# ---------------------------------------------------------------------------
# Target normalisation
# ---------------------------------------------------------------------------

_WILDCARD_RE = re.compile(r"^\*\.")
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)
_MULTI_TLDS = {
    # India (.in)
    "ac.in", "edu.in", "res.in", "gov.in", "mil.in", "net.in", "org.in", "co.in",
    "gen.in", "firm.in", "ind.in",
    # United Kingdom (.uk)
    "co.uk", "ac.uk", "gov.uk", "org.uk", "net.uk", "me.uk", "ltd.uk", "plc.uk", "sch.uk",
    # Australia (.au)
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    # New Zealand (.nz)
    "co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz", "edu.nz",
    # Japan (.jp)
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ed.jp", "ad.jp", "gr.jp", "lg.jp",
    # Brazil (.br)
    "com.br", "net.br", "org.br", "gov.br", "edu.br", "mil.br",
    # South Africa (.za)
    "co.za", "net.za", "org.za", "ac.za", "gov.za", "edu.za", "web.za",
    # Singapore (.sg)
    "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg", "per.sg",
    # Malaysia (.my)
    "com.my", "edu.my", "gov.my", "net.my", "org.my", "mil.my",
    # Indonesia (.id)
    "co.id", "ac.id", "go.id", "or.id", "net.id", "web.id", "sch.id",
    # South Korea (.kr)
    "co.kr", "ne.kr", "or.kr", "re.kr", "pe.kr", "go.kr", "ac.kr",
    # Philippines (.ph)
    "com.ph", "net.ph", "org.ph", "edu.ph", "gov.ph",
    # Pakistan (.pk)
    "com.pk", "net.pk", "org.pk", "edu.pk", "gov.pk",
    # Canada (.ca)
    "gc.ca",
}


@dataclass
class Target:
    raw: str
    is_wildcard: bool
    apex_domain: str
    single_host: Optional[str]


def parse_target(raw: str) -> Target:
    clean = raw.strip().strip("'\"").lower()
    # Strip URL protocol scheme if provided (e.g. https://, http://, wss://)
    clean = re.sub(r"^[a-zA-Z0-9+.-]+://", "", clean)
    # Strip trailing slashes, paths, query parameters, and fragments
    clean = clean.split("/")[0].split("?")[0].split("#")[0].strip()
    # Strip port if present (e.g. example.com:8080)
    if ":" in clean:
        clean = clean.split(":")[0]

    is_wildcard = bool(_WILDCARD_RE.match(clean))
    stripped = _WILDCARD_RE.sub("", clean)

    if not _HOST_RE.match(stripped):
        raise ValueError(
            f"'{raw}' is not a valid domain, URL, or wildcard (e.g. example.com, www.example.com/, or *.example.com)"
        )

    labels = stripped.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_TLDS:
        apex = ".".join(labels[-3:])
    else:
        apex = ".".join(labels[-2:]) if len(labels) >= 2 else stripped

    if is_wildcard:
        return Target(raw=clean, is_wildcard=True, apex_domain=apex, single_host=None)
    if stripped == apex:
        return Target(raw=clean, is_wildcard=True, apex_domain=apex, single_host=None)
    return Target(raw=clean, is_wildcard=False, apex_domain=apex, single_host=stripped)


def safe_filename(value: str) -> str:
    """Convert any string to a safe filename component."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")


def make_scan_output_dir(base_dir: str, target_raw: str) -> str:
    """
    Returns a unique directory path for a scan:
        <base_dir>/<target_safe>_<YYYYMMDD_HHMMSS>/

    Examples:
        nasa.gov        → sairecon_output/nasa.gov_20261023_141502/
        sub.nasa.gov    → sairecon_output/sub.nasa.gov_20261023_142001/
        *.zomato.com    → sairecon_output/wildcard_zomato.com_20261023_143000/

    Every scan gets its own folder — re-scanning the same target never
    overwrites a previous run.
    """
    import os
    # Replace leading *. with "wildcard_" so the folder name is valid
    clean = target_raw.lstrip("*").lstrip(".")
    prefix = "wildcard_" if target_raw.startswith("*") else ""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder_name = f"{prefix}{clean}_{timestamp}"
    path = os.path.join(base_dir, folder_name)
    os.makedirs(path, exist_ok=True)
    return path


def dedupe_keep_order(items: List[str]) -> List[str]:
    seen: set = set()
    out = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out
