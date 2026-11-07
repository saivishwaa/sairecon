import json, os, tempfile
from sairecon.core.base import BaseModule
from sairecon.utils import dedupe_keep_order


class ParamDiscoveryModule(BaseModule):
    name = "param_discovery"
    description = "Hidden HTTP parameter discovery (Arjun) on endpoints from url_discovery"
    required_tools = ["arjun"]
    MAX_ENDPOINTS = 15

    def execute(self):
        if not self.guard_required_tools():
            return self.findings
        discovered = self.shared_context.get("discovered_urls", [])
        candidates = [u for u in discovered if "?" in u or "/api/" in u]
        if not candidates:
            candidates = [u for u in discovered if not u.split("?")[0].lower().endswith(
                (".js", ".css", ".png", ".jpg", ".svg", ".woff", ".ico"))]
        endpoints = dedupe_keep_order([u.split("?")[0] for u in candidates])[:self.MAX_ENDPOINTS]
        if not endpoints:
            self.add_finding(title="Parameter Discovery — Skipped (no candidate endpoints)",
                             command="n/a",
                             result={"status": "skipped"},
                             severity=None)
            return self.findings
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            f.write("\n".join(endpoints)); url_file = f.name
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            out_path = f.name
        self.log(f"Arjun against {len(endpoints)} endpoint(s)...")
        try:
            self.run(["arjun", "-i", url_file, "-oJ", out_path, "-t", "10", "-T", "5"], timeout_sec=300)
            try:
                with open(out_path) as f:
                    raw = json.load(f)
            except Exception:
                raw = {}
        finally:
            for p in (url_file, out_path):
                if os.path.exists(p): os.unlink(p)
        params_by_endpoint = {url: params for url, params in raw.items() if params}
        self.add_finding(
            title=f"Hidden Parameter Discovery — {sum(len(v) for v in params_by_endpoint.values())} param(s) found",
            command=f"arjun -i <{len(endpoints)} endpoints> -oJ",
            result={"endpoints_tested": len(endpoints), "params_by_endpoint": params_by_endpoint},
            severity=None,
        )
        return self.findings
