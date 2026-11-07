"""
whois_recon — WHOIS registration lookup.
  - Linux/Mac: prefers system `whois` binary for richest raw output.
  - Windows + any OS without binary: falls back to python-whois (pip dep).
  - Both unavailable: records a SKIPPED finding with install hints.
"""
import re

from sairecon.core.base import BaseModule
from sairecon.utils import tool_exists


class WhoisModule(BaseModule):
    name = "whois_recon"
    description = "WHOIS registration lookup"
    required_tools = []  # python-whois is always available as pip dep

    FIELDS = {
        "registrar":         r"Registrar:\s*(.+)",
        "creation_date":     r"Creation Date:\s*(.+)",
        "expiration_date":   r"Registry Expiry Date:\s*(.+)",
        "updated_date":      r"Updated Date:\s*(.+)",
        "name_servers":      r"Name Server:\s*(.+)",
        "domain_status":     r"Domain Status:\s*(.+)",
        "registrant_org":    r"Registrant Organization:\s*(.+)",
        "registrant_country":r"Registrant Country:\s*(.+)",
        "dnssec":            r"DNSSEC:\s*(.+)",
    }

    def execute(self):
        if tool_exists("whois"):
            return self._run_binary()
        return self._run_python_whois()

    # ------------------------------------------------------------------
    def _run_binary(self):
        self.log(f"Running whois binary for {self.target}...")
        result = self.run(["whois", self.target], timeout_sec=30)
        if result.returncode not in (0,) or not result.stdout.strip():
            self.add_finding(
                title="WHOIS Lookup Failed / No Data",
                command=result.cmd,
                result={"error": result.stderr or "empty response"},
                severity=None,
            )
            return self.findings
        parsed = self._parse_raw(result.stdout)
        self.add_finding(
            title=f"WHOIS Record for {self.target}",
            command=result.cmd,
            result={"parsed": parsed, "raw_excerpt": result.stdout[:4000]},
            severity=None,
        )
        return self.findings

    # ------------------------------------------------------------------
    def _run_python_whois(self):
        self.log(f"whois binary not found — using python-whois for {self.target}...")
        try:
            import whois as pw
            w = pw.whois(self.target)
            def _clean(v):
                if isinstance(v, list):
                    return [str(x) for x in v]
                return str(v) if v is not None else None
            parsed = {k: _clean(getattr(w, k, None)) for k in (
                "registrar", "creation_date", "expiration_date", "updated_date",
                "name_servers", "emails", "org", "country", "status",
            )}
            parsed = {k: v for k, v in parsed.items() if v and v != "None"}
            self.add_finding(
                title=f"WHOIS Record for {self.target} (python-whois)",
                command=f"python-whois: whois.whois('{self.target}')",
                result={"parsed": parsed},
                severity=None,
            )
        except ImportError:
            self.add_finding(
                title="WHOIS Lookup Skipped — whois binary and python-whois both unavailable",
                command="n/a",
                result={"status": "skipped",
                        "reason": "apt install whois  OR  pip install python-whois"},
                severity=None,
            )
        except Exception as e:
            self.add_finding(
                title="WHOIS Lookup Failed (python-whois)",
                command=f"python-whois: whois.whois('{self.target}')",
                result={"error": str(e)},
                severity=None,
            )
        return self.findings

    def _parse_raw(self, raw: str) -> dict:
        parsed = {}
        for field, pattern in self.FIELDS.items():
            matches = re.findall(pattern, raw, re.IGNORECASE)
            if not matches:
                continue
            cleaned = [m.strip() for m in matches]
            parsed[field] = cleaned if field in ("name_servers", "domain_status") else cleaned[0]
        return parsed
