import requests
from sairecon.core.base import BaseModule

SENSITIVE_PATHS = [
    {"path": "/.env",                 "name": "Environment Variables File (.env)",       "severity": "critical"},
    {"path": "/.git/config",          "name": "Exposed Git Repository (.git/config)",    "severity": "high"},
    {"path": "/.git/HEAD",            "name": "Exposed Git Repository (.git/HEAD)",      "severity": "high"},
    {"path": "/wp-config.php.bak",    "name": "WordPress Config Backup",                 "severity": "critical"},
    {"path": "/config.php.bak",       "name": "Configuration Backup File",               "severity": "high"},
    {"path": "/db.sqlite",            "name": "Exposed SQLite Database",                 "severity": "critical"},
    {"path": "/backup.sql",           "name": "Exposed SQL Dump",                        "severity": "critical"},
    {"path": "/actuator/env",         "name": "Spring Boot Actuator Env Leak",           "severity": "high"},
    {"path": "/swagger.json",         "name": "Swagger API Spec",                        "severity": "info"},
    {"path": "/v2/api-docs",          "name": "Springfox Swagger Docs",                  "severity": "info"},
    {"path": "/phpinfo.php",          "name": "Exposed phpinfo",                         "severity": "medium"},
    {"path": "/.vscode/sftp.json",    "name": "VSCode SFTP Credentials Leak",            "severity": "critical"},
    {"path": "/.aws/credentials",     "name": "AWS Credentials File Leak",               "severity": "critical"},
]


class SensitiveFilesModule(BaseModule):
    name = "sensitive_files"
    description = "Known sensitive-file exposure check (.env, .git, backups) — GET only, no fuzzing"
    required_tools = []

    def _check_host(self, host: str) -> list:
        exposed = []
        for item in SENSITIVE_PATHS:
            url = f"https://{host}{item['path']}"
            try:
                resp = requests.get(url, timeout=4, verify=False, allow_redirects=False)
                if resp.status_code == 200 and len(resp.text) > 10:
                    exposed.append({"file": item["name"], "path": item["path"],
                                    "url": url, "severity": item["severity"]})
                    self.log(f"EXPOSED: {url}")
            except Exception:
                pass
        return exposed

    def execute(self):
        raw = self.map_hosts(self._check_host)
        exposed_by_host = {h: v for h, v in raw.items() if isinstance(v, list) and v}
        all_exp = [f for files in exposed_by_host.values() for f in files]
        severity = ("critical" if any(f["severity"] == "critical" for f in all_exp)
                    else ("high" if all_exp else None))
        self.add_finding(
            title=f"Sensitive File Exposure — {len(all_exp)} finding(s) across {len(self.hosts)} host(s)",
            command=f"GET https://<host>/<path>  ({len(SENSITIVE_PATHS)} paths per host)",
            result={"exposed_by_host": exposed_by_host,
                    "tested_paths": [p["path"] for p in SENSITIVE_PATHS]},
            severity=severity,
        )
        return self.findings
