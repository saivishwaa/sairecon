"""
subdomain_enum — multi-source subdomain discovery.

Sources: subfinder, assetfinder, findomain,
         github-subdomains (needs GITHUB_TOKEN), crt.sh (pure HTTP).
Resolution: dnsx with scaled timeout + -t 100 threads.

KEY FIX: dnsx timeout = min(900, max(180, candidates // 50))
so large wildcard targets (30k+ subs) don't silently time out.
"""
import os
import urllib.request

from sairecon.core.base import BaseModule
from sairecon.utils import dedupe_keep_order, tool_exists


class SubdomainEnumModule(BaseModule):
    name = "subdomain_enum"
    description = (
        "Subdomain enumeration — subfinder / assetfinder / findomain / "
        "github-subdomains / crt.sh, resolved with dnsx"
    )
    required_tools = ["subfinder"]

    def execute(self):
        if not self.guard_required_tools():
            return self.findings

        apex = self.target
        all_candidates: list = []
        sources_used: list = []
        sources_skipped: list = []

        # 1. subfinder
        self.log(f"subfinder passive enum for {apex}...")
        r = self.run(["subfinder", "-d", apex, "-silent", "-all"], timeout_sec=300)
        found = [l.strip() for l in r.stdout.splitlines() if l.strip()]
        all_candidates += found
        sources_used.append({"tool": "subfinder", "count": len(found)})

        # 2. assetfinder
        if tool_exists("assetfinder"):
            self.log(f"assetfinder for {apex}...")
            r = self.run(["assetfinder", "--subs-only", apex], timeout_sec=120)
            found = [l.strip() for l in r.stdout.splitlines() if l.strip()]
            all_candidates += found
            sources_used.append({"tool": "assetfinder", "count": len(found)})
        else:
            sources_skipped.append("assetfinder")

        # 4. findomain
        if tool_exists("findomain"):
            self.log(f"findomain for {apex}...")
            r = self.run(["findomain", "--target", apex, "--quiet"], timeout_sec=120)
            found = [l.strip() for l in r.stdout.splitlines() if l.strip()]
            all_candidates += found
            sources_used.append({"tool": "findomain", "count": len(found)})
        else:
            sources_skipped.append("findomain")

        # 5. github-subdomains (needs GITHUB_TOKEN)
        if tool_exists("github-subdomains"):
            token = os.environ.get("GITHUB_TOKEN", "")
            if token:
                self.log(f"github-subdomains for {apex}...")
                r = self.run(["github-subdomains", "-d", apex, "-t", token, "-q"], timeout_sec=120)
                found = [l.strip() for l in r.stdout.splitlines() if l.strip()]
                all_candidates += found
                sources_used.append({"tool": "github-subdomains", "count": len(found)})
            else:
                sources_skipped.append("github-subdomains (no GITHUB_TOKEN env var set)")
        else:
            sources_skipped.append("github-subdomains (not installed)")

        # 6. crt.sh certificate transparency (pure HTTP — works on all platforms)
        crt_found = self._crt_sh(apex)
        all_candidates += crt_found
        sources_used.append({"tool": "crt.sh", "count": len(crt_found)})

        # Dedupe & filter to target domain only
        merged = dedupe_keep_order([
            s for s in all_candidates
            if s.endswith(f".{apex}") or s == apex
        ])

        self.add_finding(
            title=f"Subdomain Enumeration for {apex} ({len(merged)} unique candidates)",
            command="subfinder + assetfinder + findomain + github-subdomains + crt.sh",
            result={
                "total_unique_candidates": len(merged),
                "sources_used": sources_used,
                "sources_skipped": sources_skipped,
                "candidates": merged,
            },
            severity=None,
        )

        # 7. Resolve with dnsx — scaled timeout
        resolved: list = []
        if tool_exists("dnsx"):
            # ~50 resolutions/sec at -t 100; floor 180s, cap 900s
            dnsx_timeout = min(900, max(180, len(merged) // 50))
            self.log(f"Resolving {len(merged)} candidates with dnsx (timeout={dnsx_timeout}s, -t 100)...")
            r = self.run(
                ["dnsx", "-silent", "-a", "-resp", "-t", "100"],
                timeout_sec=dnsx_timeout,
                input_text="\n".join(merged),
            )
            if r.timed_out:
                self.log(
                    f"dnsx timed out after {dnsx_timeout}s — "
                    f"{len(resolved)} hosts resolved before cutoff; passing partial results downstream."
                )
            for line in r.stdout.splitlines():
                line = line.strip()
                if line:
                    resolved.append(line.split(" ")[0])
            resolved = dedupe_keep_order(resolved)
            self.add_finding(
                title=f"DNS-Resolved Subdomains ({len(resolved)} / {len(merged)})",
                command=f"dnsx -silent -a -resp -t 100  [timeout={dnsx_timeout}s]",
                result={"resolved_count": len(resolved), "resolved_hosts": resolved},
                severity=None,
            )
        else:
            self.log("dnsx not found — passing all candidates downstream unresolved (capped 500).")
            resolved = merged[:500]

        self.resolved_hosts = resolved
        return self.findings

    def _crt_sh(self, domain: str) -> list:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            import json, ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.urlopen(url, timeout=20, context=ctx)
            data = json.loads(req.read())
            found = set()
            for entry in data:
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        found.add(name)
            return list(found)
        except Exception:
            return []
