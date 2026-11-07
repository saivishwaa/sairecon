import json
from sairecon.core.base import BaseModule


class LiveReconModule(BaseModule):
    name = "live_recon"
    description = "Live host probing, HTTP fingerprinting & tech detection (httpx)"
    required_tools = ["httpx"]

    def execute(self):
        if not self.guard_required_tools():
            return self.findings

        self.log(f"Probing {len(self.hosts)} host(s) with httpx...")
        cmd = [
            "httpx", "-silent", "-json",
            "-status-code", "-title", "-tech-detect",
            "-cname", "-location", "-content-length", "-asn", "-ip",
        ]
        result = self.run(cmd, timeout_sec=300, input_text="\n".join(self.hosts))

        live_hosts = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            live_hosts.append({
                "url":              rec.get("url"),
                "host":             rec.get("host") or rec.get("input"),
                "status_code":      rec.get("status_code"),
                "title":            rec.get("title"),
                "technologies":     rec.get("tech", []),
                "cname":            rec.get("cname"),
                "ip":               rec.get("a") or rec.get("host"),
                "asn":              (rec.get("asn") or {}).get("as_name")
                                    if isinstance(rec.get("asn"), dict) else rec.get("asn"),
                "content_length":   rec.get("content_length"),
                "redirect_location": rec.get("location"),
            })

        self.live_hosts = [
            h["host"] or h["url"] for h in live_hosts if h.get("host") or h.get("url")
        ]

        self.add_finding(
            title=f"Live Host Probe — {len(live_hosts)} / {len(self.hosts)} host(s) responding",
            command=" ".join(cmd) + " < host_list.txt",
            result={"probed_count": len(self.hosts), "live_count": len(live_hosts), "live_hosts": live_hosts},
            severity=None,
        )
        return self.findings
