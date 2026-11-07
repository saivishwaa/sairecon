import re
import requests
from sairecon.core.base import BaseModule
from sairecon.utils import dedupe_keep_order

SECRET_PATTERNS = {
    "AWS Access Key":    r"AKIA[0-9A-Z]{16}",
    "Generic API Key":   r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,64})["\']',
    "Bearer Token":      r"bearer\s+[a-zA-Z0-9\-._~+/]+=*",
    "Private Key Header":r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "Google API Key":    r"AIza[0-9A-Za-z_\-]{35}",
    "Slack Token":       r"xox[baprs]-[0-9A-Za-z-]{10,48}",
}
ENDPOINT_PATTERN = re.compile(r"""["'](/[a-zA-Z0-9_\-/.]{2,80}?)[\"']""")


class JSSecretsModule(BaseModule):
    name = "js_secrets"
    description = "Passive JS endpoint & secret OSINT scan (public JS files only)"
    required_tools = []

    def execute(self):
        discovered = self.shared_context.get("discovered_urls", [])
        js_urls = dedupe_keep_order([u for u in discovered if u.split("?")[0].endswith(".js")])[:40]
        if not js_urls:
            self.add_finding(title="JS Secret/Endpoint Scan — Skipped (no JS URLs from url_discovery)",
                             command="n/a",
                             result={"status": "skipped"},
                             severity=None)
            return self.findings
        self.log(f"Scanning {len(js_urls)} JS file(s)...")
        endpoints_found, secrets_found = set(), []
        for js_url in js_urls:
            try:
                resp = requests.get(js_url, timeout=8, verify=False)
                body = resp.text
                for path in ENDPOINT_PATTERN.findall(body):
                    endpoints_found.add(path)
                for label, pattern in SECRET_PATTERNS.items():
                    for match in re.findall(pattern, body):
                        secrets_found.append({
                            "type": label, "js_url": js_url,
                            "match_preview": (match if isinstance(match, str) else str(match))[:12] + "...(redacted)",
                        })
            except Exception:
                pass
        self.add_finding(
            title=f"JS OSINT — {len(endpoints_found)} endpoint(s), {len(secrets_found)} possible secret(s)",
            command=f"GET <js_url> regex scan  ({len(js_urls)} files)",
            result={"js_files_scanned": len(js_urls),
                    "endpoints_found": sorted(endpoints_found)[:300],
                    "possible_secrets": secrets_found,
                    "note": "Pattern-based matches may include false positives. Values truncated."},
            severity="high" if secrets_found else None,
        )
        return self.findings
