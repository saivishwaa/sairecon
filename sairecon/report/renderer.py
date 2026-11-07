"""
SaiRecon HTML renderer.
Returns output path on success, None on failure — never raises.
"""
from __future__ import annotations

import json
import os
from typing import Optional

from sairecon.config import VERSION

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, None: 5}


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
        findings = sorted(
            scan_result.get("findings", []),
            key=lambda f: SEVERITY_ORDER.get(f.get("severity"), 5),
        )
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            s = f.get("severity")
            if s in sev_counts:
                sev_counts[s] += 1

        scan_meta = dict(scan_result)
        scan_meta.setdefault("sairecon_version", VERSION)

        html = template.render(scan=scan_meta, findings=findings, severity_counts=sev_counts)
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
