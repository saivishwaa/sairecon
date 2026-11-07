import json
from sairecon.core.base import BaseModule
from sairecon.utils import dedupe_keep_order, tool_exists


class ASNCloudReconModule(BaseModule):
    name = "asn_cloud_recon"
    description = "ASN/Org → CIDR mapping (asnmap) + CIDR expansion (mapcidr)"
    required_tools = ["asnmap"]

    def execute(self):
        if not self.guard_required_tools():
            return self.findings
        apex = self.target
        self.log(f"ASN/CIDR lookup for {apex}...")
        result = self.run(["asnmap", "-d", apex, "-silent", "-json"], timeout_sec=60)
        if result.returncode != 0 or not result.stdout.strip():
            self.add_finding(
                title="ASN/CIDR Lookup — No Data (likely missing PDCP_API_KEY)",
                command=result.cmd,
                result={"status": "no_data", "hint":
                        "asnmap needs a free ProjectDiscovery API key. Run 'asnmap -auth' once."},
                severity=None,
            )
            return self.findings
        asn_records, all_cidrs = [], []
        for line in result.stdout.splitlines():
            try:
                rec = json.loads(line.strip())
                cidrs = rec.get("cidr") or rec.get("cidrs") or []
                if isinstance(cidrs, str):
                    cidrs = [cidrs]
                asn_records.append({"asn": rec.get("as_number") or rec.get("asn"),
                                    "org": rec.get("as_name") or rec.get("org"),
                                    "country": rec.get("country"), "cidrs": cidrs})
                all_cidrs += cidrs
            except Exception:
                pass
        all_cidrs = dedupe_keep_order(all_cidrs)
        self.add_finding(
            title=f"ASN/CIDR Mapping — {len(all_cidrs)} CIDR range(s) across {len(asn_records)} ASN(s)",
            command=result.cmd,
            result={"asn_records": asn_records, "all_cidrs": all_cidrs},
            severity=None,
        )
        if all_cidrs and tool_exists("mapcidr"):
            count_result = self.run(["mapcidr", "-cidr", ",".join(all_cidrs), "-count", "-silent"], timeout_sec=30)
            total = sum(int(l.strip()) for l in count_result.stdout.splitlines() if l.strip().isdigit())
            self.add_finding(
                title=f"Network Footprint — ~{total:,} addressable IPs",
                command="mapcidr -cidr <ranges> -count",
                result={"total_addressable_ips": total,
                        "note": "Cross-reference scope before port-scanning any of it."},
                severity=None,
            )
        return self.findings
