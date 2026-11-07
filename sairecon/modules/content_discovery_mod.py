import json, os, tempfile
from sairecon.config import COMMON_WORDLIST
from sairecon.core.base import BaseModule


class ContentDiscoveryModule(BaseModule):
    name = "content_discovery"
    description = "Directory/file discovery (ffuf bundled wordlist)"
    required_tools = ["ffuf"]

    def execute(self):
        if not self.guard_required_tools():
            return self.findings
        if not os.path.exists(COMMON_WORDLIST):
            self.add_finding(title="Content Discovery Skipped — Bundled Wordlist Missing",
                             command="n/a",
                             result={"status": "skipped", "expected": COMMON_WORDLIST},
                             severity=None)
            return self.findings

        results_by_host = {}
        for host in self.hosts:
            base = f"https://{host}"
            self.log(f"ffuf against {base}...")
            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as tmp:
                out_path = tmp.name
            try:
                self.run([
                    "ffuf", "-u", f"{base}/FUZZ", "-w", COMMON_WORDLIST,
                    "-mc", "200,201,204,301,302,307,401,403",
                    "-of", "json", "-o", out_path, "-s", "-t", "30", "-timeout", "6",
                ], timeout_sec=180)
                try:
                    with open(out_path) as f:
                        data = json.load(f)
                except Exception:
                    data = {}
            finally:
                if os.path.exists(out_path):
                    os.unlink(out_path)

            hits = [{"url": r.get("url"), "status": r.get("status"), "length": r.get("length")}
                    for r in data.get("results", [])]
            if hits:
                results_by_host[host] = hits
                self.log(f"{host}: {len(hits)} path(s)")

        notable = [h for v in results_by_host.values() for h in v if h.get("status") in {401, 403}]
        self.add_finding(
            title=f"Content Discovery — {sum(len(v) for v in results_by_host.values())} path(s) found",
            command=f"ffuf -u https://<host>/FUZZ -w {os.path.basename(COMMON_WORDLIST)} -mc 200,201,204,301,302,307,401,403",
            result={"results_by_host": results_by_host,
                    "auth_protected_paths": notable},
            severity="low" if notable else None,
        )
        return self.findings
