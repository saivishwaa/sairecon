import requests
from sairecon.core.base import BaseModule

REQUIRED_HEADERS = {
    "strict-transport-security": {"name": "Strict-Transport-Security (HSTS)",    "weight": 25},
    "content-security-policy":   {"name": "Content-Security-Policy (CSP)",        "weight": 25},
    "x-frame-options":           {"name": "X-Frame-Options",                      "weight": 15},
    "x-content-type-options":    {"name": "X-Content-Type-Options",               "weight": 15},
    "referrer-policy":           {"name": "Referrer-Policy",                      "weight": 10},
    "permissions-policy":        {"name": "Permissions-Policy",                   "weight": 10},
}


class SecurityPostureModule(BaseModule):
    name = "security_posture"
    description = "OWASP security-header defensive posture audit (passive HEAD/GET)"
    required_tools = []

    def _check_host(self, host: str) -> dict:
        url = f"https://{host}"
        score = 100
        present, missing = {}, []
        try:
            resp = requests.get(url, timeout=8, verify=False, allow_redirects=True)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            for key, meta in REQUIRED_HEADERS.items():
                if key in hdrs:
                    present[meta["name"]] = hdrs[key]
                else:
                    missing.append(meta["name"])
                    score -= meta["weight"]
            score = max(0, score)
        except Exception as e:
            self.log(f"Could not reach {url}: {e}")
            score = 0
            missing = [m["name"] for m in REQUIRED_HEADERS.values()]
        grade = self._grade(score)
        return {"score": score, "grade": grade, "present_headers": present, "missing_headers": missing}

    def execute(self):
        scores = self.map_hosts(self._check_host)
        worst = min((v["score"] for v in scores.values()), default=100)
        severity = "high" if worst < 50 else ("medium" if worst < 75 else None)
        self.add_finding(
            title=f"Security Header Posture Audit — {len(scores)} host(s)",
            command="GET <url> (read response headers only)",
            result={"posture_by_host": scores},
            severity=severity,
        )
        return self.findings

    @staticmethod
    def _grade(score: int) -> str:
        for threshold, grade in ((90,"A+"),(80,"A"),(70,"B"),(60,"C"),(40,"D")):
            if score >= threshold:
                return grade
        return "F"
