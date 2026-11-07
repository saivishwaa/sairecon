"""
ReconOrchestrator: drives the full pipeline.

Flow:
  1. Domain-level modules (whois, dns, subdomain_enum, asn, passive_exposure,
     email_security) run once against the apex domain.
  2. subdomain_enum resolves candidates → resolved_hosts list.
  3. live_recon probes resolved_hosts → live_hosts list.
  4. Remaining modules run against appropriate host lists.
  5. url_discovery output is passed to js_secrets + param_discovery via shared_context.

Module isolation:
  Every module's execute() is wrapped in an independent try/except.
  An unhandled exception records an error finding and the pipeline continues.
  modules_status and modules_timing track per-module outcomes.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sairecon.utils import Target


def _load_dotenv() -> None:
    """Load .env from the project root (two levels up from this file) if present."""
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    env_path = os.path.join(here, ".env")
    if not os.path.exists(env_path):
        return
    try:
        with open(env_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip()
                if key and key not in os.environ:
                    os.environ[key] = val
    except (OSError, PermissionError, IOError):
        pass  # .env unreadable — proceed without it


_load_dotenv()

MODULE_REGISTRY: Dict[str, Any] = {}


def _lazy_import_modules() -> None:
    if MODULE_REGISTRY:
        return
    from sairecon.modules.whois_mod import WhoisModule
    from sairecon.modules.dns_mod import DNSModule
    from sairecon.modules.subdomain_enum_mod import SubdomainEnumModule
    from sairecon.modules.asn_cloud_recon_mod import ASNCloudReconModule
    from sairecon.modules.passive_exposure_mod import PassiveExposureModule
    from sairecon.modules.live_recon_mod import LiveReconModule
    from sairecon.modules.subdomain_takeover_mod import SubdomainTakeoverModule
    from sairecon.modules.port_scan_mod import PortScanModule
    from sairecon.modules.ssl_cert_mod import SSLCertModule
    from sairecon.modules.techstack_mod import TechStackModule
    from sairecon.modules.waf_detect_mod import WAFDetectModule
    from sairecon.modules.security_posture_mod import SecurityPostureModule
    from sairecon.modules.email_security_mod import EmailSecurityModule
    from sairecon.modules.url_discovery_mod import URLDiscoveryModule
    from sairecon.modules.content_discovery_mod import ContentDiscoveryModule
    from sairecon.modules.param_discovery_mod import ParamDiscoveryModule
    from sairecon.modules.js_secrets_mod import JSSecretsModule
    from sairecon.modules.wayback_robots_mod import WaybackRobotsModule
    from sairecon.modules.sensitive_files_mod import SensitiveFilesModule
    from sairecon.modules.screenshot_mod import ScreenshotModule
    from sairecon.modules.breach_mod import BreachModule

    MODULE_REGISTRY.update({
        "whois_recon":        WhoisModule,
        "dns_recon":          DNSModule,
        "subdomain_enum":     SubdomainEnumModule,
        "asn_cloud_recon":    ASNCloudReconModule,
        "passive_exposure":   PassiveExposureModule,
        "live_recon":         LiveReconModule,
        "subdomain_takeover": SubdomainTakeoverModule,
        "port_scan":          PortScanModule,
        "ssl_cert":           SSLCertModule,
        "techstack":          TechStackModule,
        "waf_detect":         WAFDetectModule,
        "security_posture":   SecurityPostureModule,
        "email_security":     EmailSecurityModule,
        "url_discovery":      URLDiscoveryModule,
        "content_discovery":  ContentDiscoveryModule,
        "param_discovery":    ParamDiscoveryModule,
        "js_secrets":         JSSecretsModule,
        "wayback_robots":     WaybackRobotsModule,
        "sensitive_files":    SensitiveFilesModule,
        "screenshot":         ScreenshotModule,
        "breach_check":       BreachModule,
    })


class ReconOrchestrator:
    def __init__(
        self,
        target: Target,
        modules_to_run: Optional[List[str]] = None,
        output_dir: str = ".",
        concurrency: int = 8,
        log_callback=None,
    ):
        self.target = target
        self.modules_to_run = modules_to_run
        self.output_dir = output_dir
        self.concurrency = concurrency
        self.log_callback = log_callback

    def _log(self, module: str, message: str) -> None:
        if self.log_callback:
            self.log_callback(module, message)
        else:
            print(f"[{module}] {message}", flush=True)

    def run(self) -> Dict[str, Any]:
        from sairecon.config import MODULE_ORDER, DOMAIN_LEVEL_MODULES, VERSION

        _lazy_import_modules()

        order = self.modules_to_run if self.modules_to_run else MODULE_ORDER
        order = [m for m in order if m in MODULE_REGISTRY]

        started_at = datetime.now(timezone.utc).isoformat()
        t_start = time.time()

        shared: Dict[str, Any] = {"concurrency": self.concurrency}
        all_findings: List[Dict[str, Any]] = []
        modules_run: List[str] = []
        modules_status: Dict[str, str] = {}
        modules_timing: Dict[str, float] = {}

        resolved_hosts: List[str] = []
        live_hosts: List[str] = []
        apex = self.target.apex_domain

        for mod_name in order:
            cls = MODULE_REGISTRY.get(mod_name)
            if not cls:
                continue

            # --- choose hosts ---
            if mod_name in DOMAIN_LEVEL_MODULES:
                hosts = [apex]
            elif mod_name in ("live_recon", "subdomain_takeover", "port_scan",
                              "ssl_cert", "waf_detect"):
                hosts = resolved_hosts if resolved_hosts else [apex]
            elif mod_name in ("techstack", "security_posture", "url_discovery",
                              "content_discovery", "wayback_robots",
                              "sensitive_files", "screenshot"):
                hosts = live_hosts if live_hosts else []
                if not hosts:
                    self._log(mod_name, "No live hosts — skipping HTTP-dependent module.")
                    modules_status[mod_name] = "skipped"
                    modules_timing[mod_name] = 0.0
                    continue
            else:
                hosts = live_hosts if live_hosts else [apex]

            self._log(mod_name, f"Starting ...")

            # --- instantiate module ---
            try:
                if mod_name == "screenshot":
                    mod = cls(
                        target=apex,
                        log_callback=lambda n, m: self._log(n, m),
                        hosts=hosts,
                        shared_context=shared,
                        output_dir=os.path.join(self.output_dir, "screenshots"),
                    )
                else:
                    mod = cls(
                        target=apex,
                        log_callback=lambda n, m: self._log(n, m),
                        hosts=hosts,
                        shared_context=shared,
                    )
            except Exception as inst_exc:
                self._log(mod_name, f"ERROR instantiating module — {type(inst_exc).__name__}: {inst_exc}")
                modules_status[mod_name] = "failed"
                modules_timing[mod_name] = 0.0
                all_findings.append({
                    "title": f"{mod_name} — instantiation error",
                    "command": "",
                    "source_module": mod_name,
                    "result": {"status": "error", "error": str(inst_exc),
                               "type": type(inst_exc).__name__},
                    "severity": None,
                })
                continue

            # --- execute with full isolation ---
            mod_start = time.time()
            try:
                findings = mod.execute()
                mod_dur = round(time.time() - mod_start, 2)

                # Determine status from finding content
                if findings and findings[0].get("result", {}).get("status") == "skipped":
                    mod_status = "skipped"
                elif findings and findings[0].get("result", {}).get("status") == "error":
                    mod_status = "failed"
                else:
                    mod_status = "ok"

                self._log(mod_name, f"Completed in {mod_dur}s — {len(findings)} finding(s)")

            except Exception as exc:
                mod_dur = round(time.time() - mod_start, 2)
                mod_status = "failed"
                findings = [{
                    "title": f"{mod_name} — unexpected error",
                    "command": "",
                    "source_module": mod_name,
                    "result": {
                        "status": "error",
                        "error": str(exc),
                        "type": type(exc).__name__,
                        "duration_sec": mod_dur,
                    },
                    "severity": None,
                }]
                self._log(mod_name, f"ERROR — {type(exc).__name__}: {exc}")

            all_findings.extend(findings)
            modules_run.append(mod_name)
            modules_status[mod_name] = mod_status
            modules_timing[mod_name] = mod_dur if 'mod_dur' in dir() else 0.0

            # --- pipeline wiring ---
            if mod_name == "subdomain_enum":
                resolved_hosts = getattr(mod, "resolved_hosts", [])
                if not resolved_hosts:
                    for f in findings:
                        if "candidates" in f.get("result", {}):
                            resolved_hosts = f["result"]["candidates"][:500]
                            self._log(
                                mod_name,
                                f"dnsx unavailable — using {len(resolved_hosts)} unresolved "
                                f"candidates (capped at 500) for downstream."
                            )
                            break
                self._log(mod_name, f"Resolved hosts: {len(resolved_hosts)}")

            if mod_name == "live_recon":
                live_hosts = getattr(mod, "live_hosts", [])
                self._log(mod_name, f"Live hosts: {len(live_hosts)}")

            if mod_name == "url_discovery":
                shared["discovered_urls"] = getattr(mod, "discovered_urls", [])

        finished_at = datetime.now(timezone.utc).isoformat()
        duration = round(time.time() - t_start, 2)

        return {
            "sairecon_version": VERSION,
            "target_raw": self.target.raw,
            "apex_domain": apex,
            "is_wildcard": self.target.is_wildcard,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_sec": duration,
            "resolved_hosts": resolved_hosts,
            "live_hosts": live_hosts,
            "modules_run": modules_run,
            "modules_status": modules_status,
            "modules_timing": modules_timing,
            "findings": all_findings,
        }
