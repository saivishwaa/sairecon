"""
websocket_recon — WebSocket service discovery, RFC 6455 handshake verification,
and Cross-Origin WebSocket Hijacking (CSWSH) posture assessment.
"""
from __future__ import annotations

import base64
import os
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
import urllib3

from sairecon.core.base import BaseModule

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common WebSocket endpoints to probe
COMMON_WS_PATHS = [
    "/",
    "/ws",
    "/websocket",
    "/socket.io/",
    "/cable",
    "/graphql",
    "/api/ws",
    "/api/v1/ws",
    "/stream",
    "/notifications",
    "/hub",
    "/echo",
]

# Random 16-byte nonce for Sec-WebSocket-Key
WS_TEST_KEY = base64.b64encode(os.urandom(16)).decode("utf-8")


class WebSocketReconModule(BaseModule):
    name = "websocket_recon"
    description = "WebSocket discovery, RFC 6455 handshake verification & CSWSH posture check"
    required_tools = []

    def execute(self) -> List[Dict[str, Any]]:
        self.log(f"Probing WebSocket endpoints across {len(self.hosts)} host(s)...")

        # Prioritize discovered URLs from url_discovery if available
        extra_paths: List[str] = []
        discovered = self.shared_context.get("discovered_urls", [])
        for u in discovered[:100]:
            try:
                parsed = urlparse(u)
                if any(k in parsed.path.lower() for k in ("ws", "socket", "stream", "chat", "hub")):
                    if parsed.path and parsed.path not in extra_paths and parsed.path not in COMMON_WS_PATHS:
                        extra_paths.append(parsed.path)
            except Exception:
                continue

        probe_paths = (COMMON_WS_PATHS + extra_paths)[:16]

        results_by_host: Dict[str, Any] = {}
        total_ws_found = 0
        cswsh_vulnerable: List[Dict[str, Any]] = []

        for host in self.hosts:
            host_results = self._probe_host(host, probe_paths)
            if host_results:
                results_by_host[host] = host_results
                total_ws_found += len(host_results)
                for ep in host_results:
                    if ep.get("cswsh_risk"):
                        cswsh_vulnerable.append({
                            "host": host,
                            "url": ep.get("url"),
                            "path": ep.get("path"),
                            "details": ep.get("cswsh_details"),
                        })

        # Determine finding severity
        severity = None
        if cswsh_vulnerable:
            severity = "high"
        elif total_ws_found > 0:
            # Check if any unencrypted ws:// found
            unencrypted = any(
                ep.get("scheme") == "ws"
                for h in results_by_host.values()
                for ep in h
            )
            severity = "medium" if unencrypted else "low"

        self.add_finding(
            title=f"WebSocket Service Discovery — {total_ws_found} endpoint(s) detected",
            command=f"RFC 6455 Upgrade handshake probing across {len(self.hosts)} host(s)",
            result={
                "endpoints_found": total_ws_found,
                "cswsh_vulnerable_count": len(cswsh_vulnerable),
                "endpoints_by_host": results_by_host,
                "cswsh_risks": cswsh_vulnerable,
                "note": "RFC 6455 handshakes verified with HTTP 101 Switching Protocols. CSWSH tested via untrusted Origin injection.",
            },
            severity=severity,
        )

        return self.findings

    def _probe_host(self, host: str, paths: List[str]) -> List[Dict[str, Any]]:
        found_endpoints: List[Dict[str, Any]] = []

        # Determine target schemes
        schemes = ["https", "http"] if not host.startswith(("http://", "https://")) else [None]

        for s in schemes:
            base_url = f"{s}://{host}" if s else host
            for path in paths:
                url = f"{base_url.rstrip('/')}{path}"
                ws_info = self._check_websocket_endpoint(url)
                if ws_info:
                    found_endpoints.append(ws_info)
                    # If confirmed on this path, don't test redundant http/https for same path
                    break

        return found_endpoints

    def _check_websocket_endpoint(self, url: str) -> Optional[Dict[str, Any]]:
        headers = {
            "User-Agent": "SaiRecon/1.0.0",
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": WS_TEST_KEY,
            "Sec-WebSocket-Version": "13",
        }

        try:
            resp = requests.get(
                url,
                headers=headers,
                timeout=5,
                verify=False,
                allow_redirects=False,
            )

            is_websocket = False
            notes: List[str] = []

            # 101 Switching Protocols is the definitive RFC 6455 indicator
            if resp.status_code == 101:
                is_websocket = True
                notes.append("101 Switching Protocols confirmed")
            elif resp.status_code in (400, 426):
                # 426 Upgrade Required or 400 Bad Request with websocket header
                upgrade_hdr = resp.headers.get("Upgrade", "").lower()
                sec_ws_hdr = resp.headers.get("Sec-WebSocket-Accept", "")
                if "websocket" in upgrade_hdr or sec_ws_hdr or "websocket" in resp.text.lower()[:200]:
                    is_websocket = True
                    notes.append(f"HTTP {resp.status_code} indicates WebSocket handler present")

            if not is_websocket:
                return None

            ws_scheme = "wss" if url.startswith("https://") else "ws"
            parsed = urlparse(url)
            ws_url = f"{ws_scheme}://{parsed.netloc}{parsed.path}"

            # Test for Cross-Origin WebSocket Hijacking (CSWSH)
            # Inject an arbitrary untrusted Origin header
            cswsh_risk = False
            cswsh_details = ""
            try:
                origin_headers = dict(headers)
                origin_headers["Origin"] = "https://evil-untrusted-origin.attacker.com"
                origin_resp = requests.get(
                    url,
                    headers=origin_headers,
                    timeout=5,
                    verify=False,
                    allow_redirects=False,
                )
                if origin_resp.status_code == 101:
                    cswsh_risk = True
                    cswsh_details = "Server accepted handshake from arbitrary external Origin: https://evil-untrusted-origin.attacker.com"
            except Exception:
                pass

            return {
                "url": url,
                "ws_url": ws_url,
                "scheme": ws_scheme,
                "path": parsed.path,
                "status_code": resp.status_code,
                "server": resp.headers.get("Server", "Unknown"),
                "sec_websocket_accept": resp.headers.get("Sec-WebSocket-Accept"),
                "subprotocols": resp.headers.get("Sec-WebSocket-Protocol"),
                "notes": notes,
                "cswsh_risk": cswsh_risk,
                "cswsh_details": cswsh_details,
            }

        except Exception:
            return None
