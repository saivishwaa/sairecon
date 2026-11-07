"""
ssl_cert — TLS/SSL certificate inspection.
  - Prefers tlsx (richest output: SANs, self-signed, expiry).
  - Falls back to Python ssl module (zero deps, works on Windows too).
"""
import json
import socket
import ssl as _ssl
from datetime import datetime, timezone

from sairecon.core.base import BaseModule
from sairecon.utils import tool_exists


class SSLCertModule(BaseModule):
    name = "ssl_cert"
    description = "TLS/SSL certificate inspection — expiry, issuer, SANs, weak/self-signed detection"
    required_tools = []  # Python ssl fallback always available

    def execute(self):
        if tool_exists("tlsx"):
            return self._run_tlsx()
        return self._run_python_ssl()

    # ------------------------------------------------------------------
    def _run_tlsx(self):
        self.log(f"Inspecting TLS certificates with tlsx ({len(self.hosts)} host(s))...")
        result = self.run(
            ["tlsx", "-silent", "-json", "-san", "-cn", "-so", "-expired", "-self-signed"],
            timeout_sec=180,
            input_text="\n".join(self.hosts),
        )
        certs, expiring_soon = [], []
        for line in result.stdout.splitlines():
            try:
                rec = json.loads(line.strip())
            except Exception:
                continue
            cert_info = {
                "host":        rec.get("host"),
                "subject_cn":  rec.get("subject_cn"),
                "subject_an":  rec.get("subject_an", []),
                "issuer_cn":   rec.get("issuer_cn"),
                "not_before":  rec.get("not_before"),
                "not_after":   rec.get("not_after"),
                "self_signed": rec.get("self_signed", False),
                "expired":     rec.get("expired", False),
            }
            certs.append(cert_info)
            not_after = rec.get("not_after")
            if not_after:
                try:
                    exp_dt = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                    days_left = (exp_dt - datetime.now(timezone.utc)).days
                    if 0 <= days_left <= 30:
                        expiring_soon.append({"host": rec.get("host"), "days_left": days_left})
                except Exception:
                    pass

        severity = ("high" if any(c["expired"] or c["self_signed"] for c in certs)
                    else ("medium" if expiring_soon else None))
        self.add_finding(
            title=f"TLS Certificate Audit — {len(certs)} certificate(s)",
            command="tlsx -silent -json -san -cn -so -expired -self-signed < host_list.txt",
            result={
                "certificates": certs,
                "expiring_within_30_days": expiring_soon,
                "expired_count": sum(1 for c in certs if c["expired"]),
                "self_signed_count": sum(1 for c in certs if c["self_signed"]),
            },
            severity=severity,
        )
        return self.findings

    # ------------------------------------------------------------------
    def _run_python_ssl(self):
        self.log(f"tlsx not found — Python ssl inspection ({len(self.hosts)} host(s))...")
        results = []
        for host in self.hosts:
            result = self._check_host_ssl(host)
            results.append(result)

        expired   = [r for r in results if r.get("is_expired")]
        self_sig  = [r for r in results if r.get("self_signed")]
        exp_soon  = [r for r in results if not r.get("is_expired") and isinstance(r.get("days_remaining"), int) and r["days_remaining"] <= 30]

        severity = ("high"   if expired or self_sig
                    else "medium" if exp_soon else None)
        self.add_finding(
            title=f"TLS Certificate Audit (Python ssl fallback) — {len(results)} host(s)",
            command="python ssl.get_server_certificate + ssl.SSLContext",
            result={
                "certificates": results,
                "expired_count": len(expired),
                "self_signed_count": len(self_sig),
                "expiring_within_30_days": [{"host": r["host"], "days_left": r["days_remaining"]} for r in exp_soon],
            },
            severity=severity,
        )
        return self.findings

    def _check_host_ssl(self, host: str) -> dict:
        base = {"host": host, "error": None}
        try:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            with ctx.wrap_socket(socket.create_connection((host, 443), timeout=8), server_hostname=host) as conn:
                cert  = conn.getpeercert(binary_form=False)
                cipher = conn.cipher()
                ver    = conn.version()
            issuer  = dict(x[0] for x in cert.get("issuer", []))
            subject = dict(x[0] for x in cert.get("subject", []))
            sans    = [e[1] for e in cert.get("subjectAltName", []) if e[0] == "DNS"]
            not_after = cert.get("notAfter", "")
            days_left = None
            expired   = False
            self_signed = issuer == subject
            if not_after:
                try:
                    exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (exp_dt - datetime.utcnow()).days
                    expired = days_left < 0
                except Exception:
                    pass
            return {
                "host": host, "subject_cn": subject.get("commonName"),
                "issuer_cn": issuer.get("commonName"), "expires_on": not_after,
                "days_remaining": days_left, "is_expired": expired,
                "self_signed": self_signed, "sans_count": len(sans),
                "sans_sample": sans[:20], "tls_version": ver, "cipher": cipher,
            }
        except Exception as e:
            return {**base, "error": str(e)}
