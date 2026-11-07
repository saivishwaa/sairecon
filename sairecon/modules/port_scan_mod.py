"""
port_scan — naabu (fast) + nmap -sV (service/version).
Windows note: naabu requires Npcap on Windows; if absent module is skipped.
Python socket fallback runs when naabu is missing (no admin required).
"""
import json
import socket
from collections import defaultdict

from sairecon.core.base import BaseModule
from sairecon.utils import tool_exists


class PortScanModule(BaseModule):
    name = "port_scan"
    description = "Port discovery (naabu / Python socket) + service fingerprinting (nmap -sV)"
    required_tools = []

    TOP_PORTS = [
        80, 443, 21, 22, 23, 25, 53, 8080, 8443, 3306, 5432, 27017,
        3389, 8000, 8888, 6379, 9200, 9000, 11211, 8081, 8008, 587,
        993, 995, 465, 110, 143,
    ]
    SERVICE_MAP = {
        80: "http", 443: "https", 21: "ftp", 22: "ssh", 23: "telnet",
        25: "smtp", 53: "domain", 8080: "http-proxy", 8443: "https-alt",
        3306: "mysql", 5432: "postgresql", 27017: "mongodb",
        3389: "ms-wbt-server", 6379: "redis", 9200: "elasticsearch",
        9000: "sonarqube", 11211: "memcached", 8000: "http-alt",
    }

    def execute(self):
        if tool_exists("naabu"):
            return self._run_naabu()
        return self._run_python_socket()

    # ------------------------------------------------------------------
    def _run_naabu(self):
        self.log(f"Running naabu against {len(self.hosts)} host(s)...")
        result = self.run(
            ["naabu", "-silent", "-json", "-top-ports", "100"],
            timeout_sec=300,
            input_text="\n".join(self.hosts),
        )
        ports_by_host: dict = defaultdict(list)
        for line in result.stdout.splitlines():
            try:
                rec = json.loads(line.strip())
                host = rec.get("host") or rec.get("ip")
                port = rec.get("port")
                if host and port:
                    ports_by_host[host].append(port)
            except Exception:
                pass

        self.add_finding(
            title=f"Open Ports (naabu top-100) — {sum(len(v) for v in ports_by_host.values())} total",
            command="naabu -silent -json -top-ports 100 < host_list.txt",
            result={"hosts_with_open_ports": len(ports_by_host), "ports_by_host": dict(ports_by_host)},
            severity=None,
        )
        self._nmap_fingerprint(ports_by_host)
        return self.findings

    # ------------------------------------------------------------------
    def _run_python_socket(self):
        self.log(f"naabu not found — Python socket scan across {len(self.hosts)} host(s) (top {len(self.TOP_PORTS)} ports)...")
        ports_by_host: dict = defaultdict(list)
        for host in self.hosts:
            for port in self.TOP_PORTS:
                try:
                    s = socket.create_connection((host, port), timeout=1.5)
                    s.close()
                    ports_by_host[host].append(port)
                    self.log(f"  {host}:{port} open")
                except Exception:
                    pass

        self.add_finding(
            title=f"Open Ports (Python socket fallback) — {sum(len(v) for v in ports_by_host.values())} total",
            command=f"python socket.create_connection  ({len(self.TOP_PORTS)} ports per host)",
            result={
                "hosts_with_open_ports": len(ports_by_host),
                "ports_by_host": dict(ports_by_host),
                "note": "naabu not installed; Python socket scanner used (no raw-packet privileges required).",
            },
            severity=None,
        )
        self._nmap_fingerprint(ports_by_host)
        return self.findings

    # ------------------------------------------------------------------
    def _nmap_fingerprint(self, ports_by_host: dict):
        if not ports_by_host:
            return
        if not tool_exists("nmap"):
            self.add_finding(
                title="Service Fingerprinting Skipped (nmap missing)",
                command="required: nmap",
                result={"status": "skipped", "install_linux": "apt install nmap",
                        "install_windows": "https://nmap.org/download.html"},
                severity=None,
            )
            return
        service_results = {}
        for host, ports in ports_by_host.items():
            port_str = ",".join(str(p) for p in sorted(set(ports)))
            self.log(f"nmap -sV on {host} ports {port_str}...")
            result = self.run(["nmap", "-Pn", "-sV", "-p", port_str, host], timeout_sec=180)
            service_results[host] = result.stdout.strip()
        self.add_finding(
            title=f"Service/Version Fingerprinting (nmap -sV) — {len(service_results)} host(s)",
            command="nmap -Pn -sV -p <ports> <host>",
            result={"nmap_output_by_host": service_results},
            severity=None,
        )
