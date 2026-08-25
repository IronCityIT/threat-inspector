"""
service_fingerprint.py — identify the service + version behind each open port.

Uses nmap service/version detection (-sV) internally. Separate from port_scan so
a caller can discover ports quickly, then fingerprint only when they want depth;
cve_lookup consumes the versions this surfaces.
"""

from __future__ import annotations

import re
from typing import Any

from base import Finding, ScanModule

from ._util import run_cmd

# e.g. "22/tcp open  ssh  OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)"
_SVC_RE = re.compile(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.*)")


def parse_services(raw: str, target_value: str) -> list[Finding]:
    """Parse nmap -sV output into service/version findings (pure — unit tested)."""
    findings: list[Finding] = []
    for line in raw.splitlines():
        m = _SVC_RE.match(line.strip())
        if not m:
            continue
        port, proto, svc, version = m.groups()
        version = version.strip()
        if not version:
            continue
        findings.append(
            Finding(
                module="service_fingerprint",
                target=target_value,
                severity="info",
                title=f"Service identified on {port}/{proto}: {svc}",
                detail=version,
                evidence={
                    "port": int(port),
                    "protocol": proto,
                    "service": svc,
                    "version": version,
                },
            )
        )
    return findings


class ServiceFingerprint(ScanModule):
    name = "service_fingerprint"
    description = "Identifies the software and version exposed on each open port."
    target_kinds = ("ip", "domain", "hostname")
    groups = ("standard", "deep")

    def run(self, target, ctx: dict[str, Any]) -> list[Finding]:
        raw = run_cmd(
            ["nmap", "-T4", "-sV", "--top-ports", "1000", "-oN", "-", target.value],
            timeout=600,
        )
        if not raw:
            return []
        return parse_services(raw, target.value)
