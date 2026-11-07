"""
dns_recon — DNS record enumeration + zone-transfer exposure check.
  - Prefers system `dig` binary (richest output, all record types).
  - Falls back to dnspython when dig is missing (Windows / minimal Linux).
"""
from sairecon.core.base import BaseModule
from sairecon.utils import tool_exists

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


class DNSModule(BaseModule):
    name = "dns_recon"
    description = "DNS record enumeration & zone transfer (AXFR) exposure check"
    required_tools = []  # dnspython is always available as pip dep

    def execute(self):
        if tool_exists("dig"):
            return self._run_dig()
        return self._run_dnspython()

    # ------------------------------------------------------------------
    def _run_dig(self):
        self.log(f"Querying DNS records for {self.target} (dig)...")
        records = {}
        for rtype in RECORD_TYPES:
            result = self.run(["dig", "+short", self.target, rtype], timeout_sec=15)
            lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
            if lines:
                records[rtype] = lines
        self.add_finding(
            title=f"DNS Records for {self.target}",
            command=f"dig +short {self.target} <{'|'.join(RECORD_TYPES)}>",
            result={"records": records},
            severity=None,
        )
        self._axfr_check_dig(records.get("NS", []))
        return self.findings

    def _axfr_check_dig(self, ns_list):
        axfr_exposed = []
        for ns in ns_list:
            ns_host = ns.rstrip(".")
            result = self.run(["dig", f"@{ns_host}", self.target, "AXFR"], timeout_sec=15)
            out = result.stdout
            if out and "Transfer failed" not in out and "timed out" not in result.stderr.lower():
                if out.count("SOA") >= 2:
                    axfr_exposed.append({"nameserver": ns_host, "sample": out[:1500]})
                    self.log(f"ZONE TRANSFER SUCCEEDED against {ns_host}!")
        severity = "critical" if axfr_exposed else None
        self.add_finding(
            title=(f"VULNERABLE: DNS Zone Transfer Exposed on {len(axfr_exposed)} nameserver(s)"
                   if axfr_exposed else "Zone Transfer (AXFR) Audit — Not Exposed"),
            command=f"dig @<ns> {self.target} AXFR  ({len(ns_list)} NS tested)",
            result={"nameservers_tested": ns_list, "axfr_exposed": axfr_exposed},
            severity=severity,
        )

    # ------------------------------------------------------------------
    def _run_dnspython(self):
        self.log(f"dig not found — falling back to dnspython for {self.target}...")
        try:
            import dns.resolver
            import dns.zone
            import dns.query
        except ImportError:
            self.add_finding(
                title="DNS Recon Skipped — dig and dnspython both unavailable",
                command="n/a",
                result={"status": "skipped",
                        "reason": "apt install dnsutils  OR  pip install dnspython"},
                severity=None,
            )
            return self.findings

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 10.0

        records = {}
        for rtype in RECORD_TYPES:
            try:
                answers = resolver.resolve(self.target, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                pass

        self.add_finding(
            title=f"DNS Records for {self.target} (dnspython fallback)",
            command=f"dns.resolver.resolve('{self.target}', <type>)",
            result={"records": records},
            severity=None,
        )

        # AXFR via dnspython
        ns_list = records.get("NS", [])
        axfr_exposed = []
        for ns_raw in ns_list:
            ns_host = ns_raw.rstrip(".")
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ns_host, self.target, timeout=10))
                names = [str(n) for n in z.nodes.keys()]
                axfr_exposed.append({"nameserver": ns_host, "record_count": len(names), "sample_names": names[:20]})
                self.log(f"ZONE TRANSFER SUCCEEDED against {ns_host}!")
            except Exception:
                pass

        severity = "critical" if axfr_exposed else None
        self.add_finding(
            title=(f"VULNERABLE: DNS Zone Transfer Exposed on {len(axfr_exposed)} nameserver(s)"
                   if axfr_exposed else "Zone Transfer (AXFR) Audit — Not Exposed"),
            command=f"dns.query.xfr(<ns>, '{self.target}')  ({len(ns_list)} NS tested)",
            result={"nameservers_tested": ns_list, "axfr_exposed": axfr_exposed},
            severity=severity,
        )
        return self.findings
