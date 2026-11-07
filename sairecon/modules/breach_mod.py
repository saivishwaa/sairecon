import requests
from sairecon.core.base import BaseModule


class BreachModule(BaseModule):
    name = "breach_check"
    description = "Domain-wide data-breach exposure check (XposedOrNot free API)"
    required_tools = []

    def execute(self):
        domain = self.target
        self.log(f"Querying XposedOrNot for {domain}...")
        url = f"https://api.xposedornot.com/v1/breach-analytics?domain={domain}"
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                data    = resp.json()
                breaches = data.get("ExposedBreaches", {}).get("breaches_details", [])
                summary  = [{"breach": b.get("breach"), "date": b.get("xposed_date")} for b in breaches]
                self.add_finding(
                    title=f"Data Breach Exposure — {len(summary)} breach record(s) for {domain}",
                    command=f"GET {url}",
                    result={"breach_count": len(summary), "breaches": summary},
                    severity="medium" if summary else None,
                )
            else:
                self.add_finding(title="Data Breach Exposure — No Data / Domain Not Indexed",
                                 command=f"GET {url}",
                                 result={"status_code": resp.status_code},
                                 severity=None)
        except Exception as e:
            self.add_finding(title="Data Breach Exposure — Request Failed",
                             command=f"GET {url}",
                             result={"error": str(e)},
                             severity=None)
        return self.findings
