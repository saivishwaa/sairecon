import json
from sairecon.core.base import BaseModule


class PassiveExposureModule(BaseModule):
    name = "passive_exposure"
    description = "Passive multi-engine exposure search via uncover (Shodan/Censys/Fofa)"
    required_tools = ["uncover"]

    def execute(self):
        if not self.guard_required_tools():
            return self.findings
        apex = self.target
        query = f'ssl:"{apex}" || hostname:"{apex}"'
        self.log(f"Querying uncover for {apex}...")
        result = self.run(["uncover", "-q", query, "-silent", "-json", "-timeout", "20"], timeout_sec=60)
        records = []
        for line in result.stdout.splitlines():
            try:
                rec = json.loads(line.strip())
                records.append({"ip": rec.get("ip"), "port": rec.get("port"),
                                 "host": rec.get("host"), "source": rec.get("source")})
            except Exception:
                pass
        if not records:
            self.add_finding(
                title="Passive Exposure — No Results (likely no search-engine API keys configured)",
                command=result.cmd,
                result={"status": "no_data",
                        "hint": "Add API keys to ~/.config/uncover/provider-config.yaml"},
                severity=None,
            )
            return self.findings
        self.add_finding(
            title=f"Passive Exposure — {len(records)} indexed asset(s)",
            command=result.cmd,
            result={"assets": records},
            severity=None,
        )
        return self.findings
