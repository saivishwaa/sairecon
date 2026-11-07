"""
email_security — SPF / DMARC / DKIM audit.
  - Prefers dig binary.  Falls back to dnspython (always available).
"""
from sairecon.core.base import BaseModule
from sairecon.utils import tool_exists

COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim"]


class EmailSecurityModule(BaseModule):
    name = "email_security"
    description = "Email anti-spoofing audit — SPF, DMARC, DKIM selector presence"
    required_tools = []

    def execute(self):
        if tool_exists("dig"):
            return self._run_dig()
        return self._run_dnspython()

    def _run_dig(self):
        domain = self.target
        self.log(f"SPF/DMARC/DKIM check for {domain} (dig)...")
        spf = [l.strip('"') for l in
               self.run(["dig", "+short", "TXT", domain], timeout_sec=15).stdout.splitlines()
               if "v=spf1" in l.lower()]
        dmarc = [l.strip('"') for l in
                 self.run(["dig", "+short", "TXT", f"_dmarc.{domain}"], timeout_sec=15).stdout.splitlines()
                 if "v=dmarc1" in l.lower()]
        dkim_found = []
        for sel in COMMON_DKIM_SELECTORS:
            if self.run(["dig", "+short", "TXT", f"{sel}._domainkey.{domain}"], timeout_sec=10).stdout.strip():
                dkim_found.append(sel)
        return self._emit(domain, spf, dmarc, dkim_found)

    def _run_dnspython(self):
        domain = self.target
        self.log(f"dig not found — using dnspython for {domain}...")
        try:
            import dns.resolver
            r = dns.resolver.Resolver()
            r.timeout = 5.0; r.lifetime = 10.0
            def query_txt(name):
                try:
                    return [b.decode() for ans in r.resolve(name, "TXT") for b in ans.strings]
                except Exception:
                    return []
            spf   = [x for x in query_txt(domain)          if "v=spf1"  in x.lower()]
            dmarc = [x for x in query_txt(f"_dmarc.{domain}") if "v=dmarc1" in x.lower()]
            dkim_found = [sel for sel in COMMON_DKIM_SELECTORS
                          if query_txt(f"{sel}._domainkey.{domain}")]
        except ImportError:
            self.add_finding(
                title="Email Security Audit Skipped — dig and dnspython both unavailable",
                command="n/a",
                result={"status": "skipped",
                        "reason": "apt install dnsutils  OR  pip install dnspython"},
                severity=None,
            )
            return self.findings
        return self._emit(domain, spf, dmarc, dkim_found)

    def _emit(self, domain, spf, dmarc, dkim_found):
        issues = []
        if not spf:
            issues.append("No SPF record — domain more vulnerable to email spoofing.")
        if not dmarc:
            issues.append("No DMARC record — spoofed mail may not be rejected/quarantined.")
        elif "p=none" in (dmarc[0] if dmarc else "").lower():
            issues.append("DMARC policy 'p=none' (monitor-only) — spoofed mail not blocked.")
        self.add_finding(
            title=f"Email Anti-Spoofing Audit for {domain}" + (" — Issues Found" if issues else " — Looks Healthy"),
            command=f"TXT {domain} / _dmarc.{domain} / <sel>._domainkey.{domain}",
            result={"spf_records": spf, "dmarc_records": dmarc,
                    "dkim_selectors_found": dkim_found, "issues": issues},
            severity="medium" if issues else None,
        )
        return self.findings
