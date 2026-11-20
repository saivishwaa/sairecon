"""
SaiRecon HTML renderer.
Returns output path on success, None on failure — never raises.
"""
from __future__ import annotations

import json
import os
from typing import Any, Optional

from sairecon.config import VERSION

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, None: 5}


def _safe_json_dumps(obj: Any, indent: int = 2) -> str:
    """Safely serialize any object to a formatted JSON string."""
    try:
        return json.dumps(obj, indent=indent, default=str)
    except Exception:
        return str(obj)


def render_html(scan_result: dict, output_path: str) -> Optional[str]:
    """Render an HTML report. Returns path on success, None on failure."""
    try:
        from jinja2 import (
            Environment, FileSystemLoader, TemplateNotFound,
            TemplateSyntaxError, select_autoescape,
        )
    except ImportError as exc:
        print(f"[render_html] jinja2 not installed — HTML report skipped: {exc}", flush=True)
        return None

    try:
        env = Environment(
            loader=FileSystemLoader(TEMPLATE_DIR),
            autoescape=select_autoescape(["html", "j2"]),
        )
        # Register custom safe json filter
        env.filters["safe_json"] = _safe_json_dumps
        template = env.get_template("report.html.j2")
    except TemplateNotFound:
        print(f"[render_html] Template 'report.html.j2' not found in {TEMPLATE_DIR}", flush=True)
        return None
    except TemplateSyntaxError as exc:
        print(f"[render_html] Template syntax error: {exc}", flush=True)
        return None
    except Exception as exc:
        print(f"[render_html] Could not load template: {type(exc).__name__}: {exc}", flush=True)
        return None

    try:
        raw_findings = (scan_result or {}).get("findings") or []
        findings = sorted(
            raw_findings,
            key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 5),
        )
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            s = f.get("severity")
            if s in sev_counts:
                sev_counts[s] += 1

        scan_meta = dict(scan_result or {})
        scan_meta.setdefault("sairecon_version", VERSION)
        scan_meta["resolved_hosts"] = scan_meta.get("resolved_hosts") or []
        scan_meta["live_hosts"] = scan_meta.get("live_hosts") or []
        scan_meta["modules_run"] = scan_meta.get("modules_run") or []
        scan_meta["modules_status"] = scan_meta.get("modules_status") or {}
        scan_meta["modules_timing"] = scan_meta.get("modules_timing") or {}
        scan_meta.setdefault("target_raw", scan_meta.get("apex_domain", "target"))
        scan_meta.setdefault("apex_domain", "target")
        scan_meta.setdefault("is_wildcard", False)
        scan_meta.setdefault("started_at", "N/A")
        scan_meta.setdefault("finished_at", "N/A")
        scan_meta.setdefault("duration_sec", 0.0)

        html = template.render(
            scan=scan_meta,
            findings=findings,
            severity_counts=sev_counts,
        )
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return output_path

    except (OSError, PermissionError, IOError) as exc:
        print(f"[render_html] ERROR writing {output_path}: {exc}", flush=True)
        return None
    except Exception as exc:
        print(f"[render_html] Unexpected error: {type(exc).__name__}: {exc}", flush=True)
        return None
