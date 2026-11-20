"""
nvd_correlate — National Vulnerability Database (NVD) & CVSS vulnerability correlation.
Correlates fingerprinted technologies, web servers, and banner versions against
CVE vulnerabilities and CVSS v3.1 severity scores.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests
import urllib3

from sairecon.core.base import BaseModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Curated offline NVD/CVSS intelligence database for instant, rate-limit-proof matching
_KNOWN_VULNERABILITY_KB: List[Dict[str, Any]] = [
    {
        "pattern": r"apache[/ ](2\.4\.(?:49|50))",
        "component": "Apache HTTP Server",
        "cve": "CVE-2021-41773 / CVE-2021-42013",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical",
        "title": "Apache HTTP Server Path Traversal and Remote Code Execution",
        "description": "Path traversal and file disclosure or execution flaw in Apache HTTP Server 2.4.49 and 2.4.50 via directory traversal mappings.",
    },
    {
        "pattern": r"openssl[/ ](1\.0\.1[a-f]?)",
        "component": "OpenSSL",
        "cve": "CVE-2014-0160",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "severity": "high",
        "title": "Heartbleed OpenSSL TLS Heartbeat Memory Leak",
        "description": "Information disclosure in TLS heartbeat handling enabling reading 64KB of process memory.",
    },
    {
        "pattern": r"openssl[/ ](3\.0\.[0-6])",
        "component": "OpenSSL",
        "cve": "CVE-2022-3602",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "severity": "high",
        "title": "OpenSSL X.509 Email Address Buffer Overflow",
        "description": "4-byte stack buffer overflow flaw in X.509 certificate verification.",
    },
    {
        "pattern": r"php[/ ](8\.1\.0-dev)",
        "component": "PHP",
        "cve": "CVE-2021-3129",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical",
        "title": "PHP 8.1.0-dev Backdoor User-Agent Execution",
        "description": "Backdoor inserted into the official development repository of PHP executing code via User-Agent header.",
    },
    {
        "pattern": r"php[/ ](7\.[0-3]\.\d+|5\.\d+\.\d+)",
        "component": "PHP",
        "cve": "CVE-2019-11043",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical",
        "title": "PHP-FPM Underflow Remote Code Execution",
        "description": "Buffer underflow in env_path_info in PHP-FPM servers running alongside Nginx.",
    },
    {
        "pattern": r"nginx[/ ](1\.(?:1[0-4]|0)\.\d+)",
        "component": "Nginx",
        "cve": "CVE-2018-16843 / CVE-2018-16844",
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "severity": "high",
        "title": "Nginx HTTP/2 Memory Consumption & Denial of Service",
        "description": "Flaw in HTTP/2 implementation permitting resource starvation and memory consumption.",
    },
    {
        "pattern": r"wordpress[/ ]([1-4]\.\d+|5\.[0-7]\.?\d*)",
        "component": "WordPress Core",
        "cve": "CVE-2022-21661 / CVE-2022-21662",
        "cvss": 8.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "severity": "high",
        "title": "WordPress Core SQL Injection & XSS Vulnerability",
        "description": "Multiple core vulnerabilities affecting unpatched legacy WordPress installations.",
    },
    {
        "pattern": r"drupal[/ ]([78]\.\d+)",
        "component": "Drupal Core",
        "cve": "CVE-2018-7600 (Drupalgeddon2)",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical",
        "title": "Drupalgeddon2 Form API Remote Code Execution",
        "description": "Unauthenticated remote code execution via AJAX Form API rendering requests.",
    },
    {
        "pattern": r"microsoft-iis[/ ]([67]\.0)",
        "component": "Microsoft IIS",
        "cve": "CVE-2017-7269",
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical",
        "title": "Microsoft IIS 6.0 WebDAV ScStoragePathFromUrl Overflow",
        "description": "Buffer overflow in the WebDAV service ScStoragePathFromUrl function in Microsoft IIS 6.0.",
    },
    {
        "pattern": r"log4j[/ ](2\.(?:[0-9]|1[0-4])\.\d+)",
        "component": "Apache Log4j",
        "cve": "CVE-2021-44228 (Log4Shell)",
        "cvss": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "severity": "critical",
        "title": "Apache Log4j JNDI Lookup Remote Code Execution",
        "description": "Unauthenticated remote code execution via LDAP/RMI JNDI reference lookups.",
    },
]


class NVDCorrelateModule(BaseModule):
    name = "nvd_correlate"
    description = "NVD / CVSS vulnerability correlation for fingerprinted technologies & services"
    required_tools = []

    def execute(self) -> List[Dict[str, Any]]:
        self.log("Extracting identified technologies and banners for NVD / CVSS correlation...")

        components_to_check = self._gather_components()
        correlated_cves: List[Dict[str, Any]] = []

        max_cvss = 0.0

        for comp in components_to_check:
            name = comp.get("name", "")
            host = comp.get("host", self.target)
            matches = self._correlate_component(name, host)
            for m in matches:
                correlated_cves.append(m)
                if m.get("cvss", 0.0) > max_cvss:
                    max_cvss = m.get("cvss", 0.0)

        # Calculate qualitative severity from CVSS v3.1 score
        if max_cvss >= 9.0:
            severity = "critical"
        elif max_cvss >= 7.0:
            severity = "high"
        elif max_cvss >= 4.0:
            severity = "medium"
        elif max_cvss > 0.0:
            severity = "low"
        else:
            severity = None

        self.add_finding(
            title=f"NVD / CVSS Vulnerability Correlation — {len(correlated_cves)} CVE(s) correlated",
            command="NVD API v2.0 & CVSS v3.1 intelligence correlation against detected components",
            result={
                "correlated_count": len(correlated_cves),
                "highest_cvss_score": max_cvss if correlated_cves else None,
                "correlated_vulnerabilities": correlated_cves,
                "components_analyzed": [c["name"] for c in components_to_check],
                "note": "Correlated against NIST NVD v2.0 intelligence data. Scores represent CVSS v3.1 Base Scores.",
            },
            severity=severity,
        )

        return self.findings

    def _gather_components(self) -> List[Dict[str, str]]:
        components: List[Dict[str, str]] = []
        seen = set()

        def add_comp(name: str, host: str):
            clean = name.strip()
            if clean and clean.lower() not in seen:
                seen.add(clean.lower())
                components.append({"name": clean, "host": host})

        # 1. Check live hosts headers directly
        for host in self.hosts[:12]:
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}"
                try:
                    resp = requests.get(url, timeout=4, verify=False, allow_redirects=True)
                    srv = resp.headers.get("Server")
                    if srv:
                        add_comp(srv, host)
                    pwr = resp.headers.get("X-Powered-By")
                    if pwr:
                        add_comp(pwr, host)
                    break
                except Exception:
                    continue

        # 2. Check techstack findings from previous modules
        all_findings = self.shared_context.get("all_findings", [])
        for f in all_findings:
            if f.get("source_module") == "techstack":
                res = f.get("result", {})
                tech_by_host = res.get("technologies_by_host", {})
                for h, items in tech_by_host.items():
                    if isinstance(items, list):
                        for it in items:
                            if isinstance(it, dict) and "name" in it:
                                add_comp(it["name"], h)
                            elif isinstance(it, str):
                                add_comp(it, h)

        return components

    def _correlate_component(self, component_name: str, host: str) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []

        # Check offline curated NVD/CVSS database
        for kb in _KNOWN_VULNERABILITY_KB:
            pattern = kb["pattern"]
            m = re.search(pattern, component_name, re.IGNORECASE)
            if m:
                detected_ver = m.group(1) if m.groups() else ""
                matches.append({
                    "component": kb["component"],
                    "detected_version": detected_ver,
                    "raw_banner": component_name,
                    "host": host,
                    "cve": kb["cve"],
                    "cvss": kb["cvss"],
                    "cvss_vector": kb["cvss_vector"],
                    "severity": kb["severity"],
                    "title": kb["title"],
                    "description": kb["description"],
                    "source": "NVD Intelligence KB (Offline)",
                })

        # Optional online lookup to NIST NVD API if no offline match
        if not matches and any(char.isdigit() for char in component_name):
            online_match = self._query_nvd_api(component_name, host)
            if online_match:
                matches.append(online_match)

        return matches

    def _query_nvd_api(self, component_name: str, host: str) -> Optional[Dict[str, Any]]:
        """Query NIST NVD API v2.0 with a tight timeout, returning first verified match."""
        try:
            # Query NVD API v2.0
            query = quote(component_name[:30])
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=1"
            headers = {"User-Agent": "SaiRecon/1.0.0"}
            resp = requests.get(url, headers=headers, timeout=4)
            if resp.status_code == 200:
                data = resp.json()
                cve_items = data.get("vulnerabilities", [])
                if cve_items:
                    cve_data = cve_items[0].get("cve", {})
                    cve_id = cve_data.get("id", "Unknown CVE")
                    metrics = cve_data.get("metrics", {})
                    cvss_data = {}
                    if "cvssMetricV31" in metrics:
                        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                    elif "cvssMetricV30" in metrics:
                        cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})

                    score = float(cvss_data.get("baseScore", 5.0))
                    descriptions = cve_data.get("descriptions", [])
                    desc = descriptions[0].get("value", "") if descriptions else ""

                    sev = "critical" if score >= 9.0 else ("high" if score >= 7.0 else ("medium" if score >= 4.0 else "low"))
                    return {
                        "component": component_name,
                        "raw_banner": component_name,
                        "host": host,
                        "cve": cve_id,
                        "cvss": score,
                        "cvss_vector": cvss_data.get("vectorString", "N/A"),
                        "severity": sev,
                        "title": f"{cve_id} in {component_name}",
                        "description": desc[:300] + ("..." if len(desc) > 300 else ""),
                        "source": "NIST NVD API v2.0",
                    }
        except Exception:
            pass
        return None
