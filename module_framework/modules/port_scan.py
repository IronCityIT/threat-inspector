"""
port_scan.py — reachable TCP ports and listening services.

Re-housed from the former port-scan workflow's inline nmap logic. nmap is used
internally; the capability is branded as network port discovery on any surface.
"""

from __future__ import annotations

import re
from typing import Any

from base import Finding, ScanModule

from ._util import run_cmd

_PORT_RE = re.compile(r"(\d+)/(tcp|udp)\s+open\s+(\S+)(.*)")


def parse_ports(raw: str, target_value: str) -> list[Finding]:
    """Parse nmap normal output into open-port findings (pure — unit tested)."""
    findings: list[Finding] = []
    for line in raw.splitlines():
        m = _PORT_RE.match(line.strip())
        if not m:
            continue
        port, proto, svc, extra = m.groups()
        findings.append(
            Finding(
                module="port_scan",
                target=target_value,
                severity="info",
                title=f"Open port {port}/{proto} ({svc})",
                detail=(svc + extra).strip(),
                evidence={"port": int(port), "protocol": proto, "service": svc},
            )
        )
    return findings


class PortScan(ScanModule):
    name = "port_scan"
    description = "Discovers reachable network ports and listening services."
    target_kinds = ("ip", "domain", "hostname")
    groups = ("quick", "standard", "deep")

    def run(self, target, ctx: dict[str, Any]) -> list[Finding]:
        raw = run_cmd(
            ["nmap", "-T4", "--top-ports", "1000", "-oN", "-", target.value],
            timeout=300,
        )
        if not raw:
            return []
        return parse_ports(raw, target.value)
