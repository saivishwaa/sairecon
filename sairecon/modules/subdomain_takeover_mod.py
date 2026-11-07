import dns.resolver
import requests

from sairecon.core.base import BaseModule

TAKEOVER_SIGNATURES = {
    "github.io":         {"service": "GitHub Pages",       "fingerprint": "There isn't a GitHub Pages site here"},
    "s3.amazonaws.com":  {"service": "AWS S3 Bucket",      "fingerprint": "The specified bucket does not exist"},
    "herokuapp.com":     {"service": "Heroku App",          "fingerprint": "No such app"},
    "azurewebsites.net": {"service": "Azure Web App",       "fingerprint": "404 Web Site not found"},
    "myshopify.com":     {"service": "Shopify Store",       "fingerprint": "Sorry, this shop is currently unavailable"},
    "fastly.net":        {"service": "Fastly CDN",          "fingerprint": "Fastly error: unknown domain"},
    "pantheonsite.io":   {"service": "Pantheon Hosting",    "fingerprint": "404 error unknown site"},
    "tumblr.com":        {"service": "Tumblr Blog",         "fingerprint": "there's nothing here"},
    "wordpress.com":     {"service": "WordPress.com",       "fingerprint": "Do you want to register"},
    "surge.sh":          {"service": "Surge.sh",            "fingerprint": "project not found"},
    "ghost.io":          {"service": "Ghost Blog",          "fingerprint": "The thing you were looking for is no longer here"},
    "readme.io":         {"service": "ReadMe.io",           "fingerprint": "Project doesnt exist"},
    "webflow.io":        {"service": "Webflow",             "fingerprint": "The page you are looking for doesn't exist"},
    "zendesk.com":       {"service": "Zendesk",             "fingerprint": "Help Center Closed"},
}


class SubdomainTakeoverModule(BaseModule):
    name = "subdomain_takeover"
    description = "Dangling CNAME subdomain takeover detection (passive DNS + response fingerprint)"
    required_tools = []

    def execute(self):
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 5.0

        cname_records = {}
        takeover_candidates = []

        self.log(f"Checking CNAME pointers on {len(self.hosts)} host(s)...")
        for host in self.hosts:
            try:
                answers = resolver.resolve(host, "CNAME")
            except Exception:
                continue
            for rdata in answers:
                cname_target = str(rdata.target).rstrip(".").lower()
                cname_records[host] = cname_target
                for sig_domain, sig in TAKEOVER_SIGNATURES.items():
                    if sig_domain in cname_target:
                        self.log(f"{host} → CNAME {cname_target} ({sig['service']}); fingerprinting...")
                        if self._fingerprint_matches(host, sig["fingerprint"]):
                            takeover_candidates.append({
                                "subdomain": host,
                                "cname_target": cname_target,
                                "service": sig["service"],
                                "fingerprint_matched": sig["fingerprint"],
                            })
                            self.log(f"POSSIBLE TAKEOVER: {host} → unclaimed {sig['service']}")

        severity = "critical" if takeover_candidates else None
        self.add_finding(
            title=(f"POSSIBLE SUBDOMAIN TAKEOVER on {len(takeover_candidates)} host(s)"
                   if takeover_candidates else "Subdomain Takeover Audit — No Dangling CNAMEs"),
            command=f"dnspython CNAME + HTTP fingerprint  ({len(self.hosts)} hosts)",
            result={
                "hosts_checked": len(self.hosts),
                "cname_records": cname_records,
                "takeover_candidates": takeover_candidates,
                "note": "Fingerprint match only — nothing was claimed. Verify manually before reporting.",
            },
            severity=severity,
        )
        return self.findings

    @staticmethod
    def _fingerprint_matches(host: str, fingerprint: str) -> bool:
        for scheme in ("https", "http"):
            try:
                resp = requests.get(f"{scheme}://{host}", timeout=5, verify=False, allow_redirects=True)
                if fingerprint.lower() in resp.text.lower():
                    return True
            except Exception:
                pass
        return False
