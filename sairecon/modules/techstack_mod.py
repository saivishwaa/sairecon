"""
techstack — technology fingerprinting.
  - whatweb CLI (richest output) preferred.
  - Falls back to Python httpx-based header+HTML signature matching (v1 logic,
    works on Windows and any box without whatweb).
  - Shodan-compatible favicon hash via mmh3 (optional dep).
"""
import base64
import json
import re

import requests

from sairecon.core.base import BaseModule
from sairecon.utils import tool_exists

try:
    import mmh3
except ImportError:
    mmh3 = None

_TECH_SIGNATURES = {
    "WordPress":  ["wp-content", "wp-includes", "wordpress"],
    "Joomla":     ["/components/com_", "joomla!"],
    "Drupal":     ["drupal.js", "sites/all/themes"],
    "React":      ["react.production.min.js", "data-reactroot"],
    "Vue.js":     ["vue.min.js", "data-v-"],
    "Angular":    ["ng-version", "angular.min.js"],
    "Bootstrap":  ["bootstrap.min.css", "bootstrap.bundle"],
    "jQuery":     ["jquery.min.js", "jquery-"],
    "Cloudflare": ["cf-ray", "cloudflare"],
    "PHP":        ["PHPSESSID", ".php"],
    "ASP.NET":    ["ASP.NET_SessionId", ".aspx"],
}


class TechStackModule(BaseModule):
    name = "techstack"
    description = "Technology fingerprinting (whatweb + HTTP signature fallback) + favicon hash"
    required_tools = []

    def execute(self):
        if tool_exists("whatweb"):
            results_by_host = self.map_hosts(self._check_whatweb)
        else:
            self.log("whatweb not found — using built-in HTTP signature engine...")
            results_by_host = self.map_hosts(self._check_python)

        self.add_finding(
            title=f"Technology Fingerprinting — {len(results_by_host)} host(s)",
            command="whatweb --log-json=-" if tool_exists("whatweb") else "HTTP header + HTML signature scan",
            result={"technologies_by_host": results_by_host},
            severity=None,
        )

        if mmh3 is not None:
            favicon_hashes = {
                h: v for h, v in self.map_hosts(self._favicon_hash).items()
                if isinstance(v, int)
            }
            if favicon_hashes:
                self.add_finding(
                    title=f"Favicon Hash (Shodan-compatible) — {len(favicon_hashes)} host(s)",
                    command="GET /favicon.ico → mmh3(base64(bytes))",
                    result={
                        "favicon_hashes": favicon_hashes,
                        "note": "Search 'http.favicon.hash:<value>' on Shodan to find related assets.",
                    },
                    severity=None,
                )
        return self.findings

    def _check_whatweb(self, host: str) -> list:
        url = f"https://{host}"
        result = self.run(["whatweb", "--log-json=-", "--no-errors", url], timeout_sec=60)
        try:
            parsed = json.loads(result.stdout.strip().splitlines()[-1]) if result.stdout.strip() else {}
            return list(parsed.get("plugins", {}).keys()) if isinstance(parsed, dict) else []
        except Exception:
            return []

    def _check_python(self, host: str) -> list:
        url = f"https://{host}"
        found = []
        try:
            resp = requests.get(url, timeout=8, verify=False, allow_redirects=True)
            hdrs = {k.lower(): v.lower() for k, v in resp.headers.items()}
            body = resp.text.lower()
            if hdrs.get("server"):
                found.append({"category": "Web Server", "name": resp.headers.get("Server")})
            if hdrs.get("x-powered-by"):
                found.append({"category": "Framework", "name": resp.headers.get("X-Powered-By")})
            for tech, keywords in _TECH_SIGNATURES.items():
                if any(kw in body or kw in str(hdrs) for kw in keywords):
                    if not any(t.get("name") == tech for t in found):
                        found.append({"category": "Detected", "name": tech})
        except Exception:
            pass
        return found

    @staticmethod
    def _favicon_hash(host: str):
        if mmh3 is None:
            return None
        for scheme in ("https", "http"):
            try:
                resp = requests.get(f"{scheme}://{host}/favicon.ico", timeout=6, verify=False)
                if resp.status_code == 200 and resp.content:
                    return mmh3.hash(base64.encodebytes(resp.content))
            except Exception:
                pass
        return None
