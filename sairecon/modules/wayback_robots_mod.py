import requests
from sairecon.core.base import BaseModule


class WaybackRobotsModule(BaseModule):
    name = "wayback_robots"
    description = "robots.txt & sitemap.xml disclosure review (passive GET)"
    required_tools = []

    def _check_host(self, host: str) -> dict:
        result = {}
        for fname in ("robots.txt", "sitemap.xml"):
            url = f"https://{host}/{fname}"
            try:
                resp = requests.get(url, timeout=6, verify=False)
                if resp.status_code == 200 and resp.text.strip():
                    result[fname] = {"found": True, "size_bytes": len(resp.text), "preview": resp.text[:1500]}
                else:
                    result[fname] = {"found": False, "status_code": resp.status_code}
            except Exception as e:
                result[fname] = {"found": False, "error": str(e)}
        return result

    def execute(self):
        results = self.map_hosts(self._check_host)
        disallowed = []
        for host, data in results.items():
            robots = data.get("robots.txt", {})
            if robots.get("found"):
                for line in robots["preview"].splitlines():
                    if line.strip().lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            disallowed.append({"host": host, "path": path})
        self.add_finding(
            title=f"robots.txt / sitemap.xml Review — {len(results)} host(s)",
            command="GET https://<host>/robots.txt ; GET https://<host>/sitemap.xml",
            result={"results_by_host": results, "disallowed_paths_disclosed": disallowed},
            severity=None,
        )
        return self.findings
