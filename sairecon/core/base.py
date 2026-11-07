"""
BaseModule: contract every recon module implements.
"""
from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, TypeVar

from sairecon.config import IS_WINDOWS, REQUIRED_TOOLS
from sairecon.utils import CommandResult, run_command, tool_exists


class BaseModule:
    name: str = "base"
    description: str = "Base recon module"
    # Hard-required tools. If none are present the module records a SKIPPED
    # finding and returns — no silent pure-Python reimplementation.
    required_tools: List[str] = []

    def __init__(
        self,
        target: str,
        log_callback=None,
        hosts: Optional[List[str]] = None,
        shared_context: Optional[Dict[str, Any]] = None,
    ):
        self.target = target.strip().lower()
        self.log_callback = log_callback
        self.findings: List[Dict[str, Any]] = []
        self.hosts: List[str] = hosts if hosts is not None else [self.target]
        self.shared_context: Dict[str, Any] = (
            shared_context if shared_context is not None else {}
        )
        self.concurrency: int = int(self.shared_context.get("concurrency", 8))

    def log(self, message: str) -> None:
        if self.log_callback:
            self.log_callback(self.name, message)

    def add_finding(
        self,
        title: str,
        command: str,
        result: Any,
        severity: Optional[str] = None,
    ) -> Dict[str, Any]:
        finding = {
            "title": title,
            "command": command,
            "source_module": self.name,
            "result": result,
            "severity": severity,
        }
        self.findings.append(finding)
        return finding

    def missing_tools(self) -> List[str]:
        return [t for t in self.required_tools if not tool_exists(t)]

    def guard_required_tools(self) -> bool:
        missing = self.missing_tools()
        if missing and self.required_tools:
            platform_key = "install_windows" if IS_WINDOWS else "install_linux"
            hints = "; ".join(
                f"{t}: {REQUIRED_TOOLS.get(t, {}).get(platform_key, 'see README')}"
                for t in missing
            )
            self.log(f"SKIPPED — missing required tool(s): {', '.join(missing)}")
            self.add_finding(
                title=f"{self.description} — skipped (missing tools)",
                command=f"required: {', '.join(self.required_tools)}",
                result={"status": "skipped", "missing_tools": missing, "install_hints": hints},
                severity=None,
            )
            return False
        return True

    def run(
        self,
        cmd_args: List[str],
        timeout_sec: int = 120,
        input_text: Optional[str] = None,
    ) -> CommandResult:
        self.log(f"$ {' '.join(cmd_args)}")
        result = run_command(cmd_args, timeout_sec=timeout_sec, input_text=input_text)
        if result.timed_out:
            self.log(f"... timed out after {timeout_sec}s")
        return result

    def execute(self) -> List[Dict[str, Any]]:
        raise NotImplementedError("Subclasses must implement execute()")

    T = TypeVar("T")

    def map_hosts(self, fn: "Callable[[str], T]") -> "Dict[str, T]":
        """Run fn(host) across self.hosts with a thread pool."""
        results: Dict[str, Any] = {}
        with ThreadPoolExecutor(max_workers=max(1, self.concurrency)) as pool:
            future_to_host = {pool.submit(fn, host): host for host in self.hosts}
            for future in future_to_host:
                host = future_to_host[future]
                try:
                    results[host] = future.result()
                except Exception as e:  # noqa: BLE001
                    results[host] = e
        return results
