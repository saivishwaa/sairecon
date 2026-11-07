import json, os, tempfile
from sairecon.core.base import BaseModule


class WAFDetectModule(BaseModule):
    name = "waf_detect"
    description = "Web Application Firewall fingerprinting (wafw00f)"
    required_tools = ["wafw00f"]

    def execute(self):
        if not self.guard_required_tools():
            return self.findings
        urls = [f"https://{h}" for h in self.hosts]
        self.log(f"WAF fingerprinting on {len(urls)} host(s)...")
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tmp:
            out_path = tmp.name
        try:
            self.run(["wafw00f", *urls, "-a", "-o", out_path, "-f", "json"], timeout_sec=240)
            try:
                with open(out_path, "r") as f:
                    raw = json.load(f)
            except Exception:
                raw = []
        finally:
            if os.path.exists(out_path):
                os.unlink(out_path)
        results = [{"url": e.get("url"), "waf_detected": bool(e.get("detected")),
                    "firewall": e.get("firewall"), "manufacturer": e.get("manufacturer")}
                   for e in (raw if isinstance(raw, list) else [])]
        protected = sum(1 for r in results if r["waf_detected"])
        self.add_finding(
            title=f"WAF Fingerprinting — {protected}/{len(results)} host(s) behind a detected WAF",
            command=f"wafw00f {' '.join(urls[:3])}{' ...' if len(urls)>3 else ''} -a -f json",
            result={"results": results},
            severity=None,
        )
        return self.findings
