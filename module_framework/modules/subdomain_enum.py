"""
subdomain_enum.py — passive subdomain discovery for a domain.

Re-housed from the asset-discovery workflow. Uses subfinder internally; branded
as attack-surface / asset discovery.
"""

from __future__ import annotations

from typing import Any

from base import Finding, ScanModule

from ._util import run_cmd


def parse_subdomains(raw: str, domain: str) -> list[Finding]:
    """Turn a newline list of hostnames into findings (pure — unit tested)."""
    seen: set[str] = set()
    findings: list[Finding] = []
    for line in raw.splitlines():
        host = line.strip().lower()
        if not host or host in seen:
            continue
        seen.add(host)
        findings.append(
            Finding(
                module="subdomain_enum",
                target=domain,
                severity="info",
                title=f"Subdomain discovered: {host}",
                detail=f"{host} is part of the {domain} attack surface.",
                evidence={"subdomain": host},
            )
        )
    return findings


class SubdomainEnum(ScanModule):
    name = "subdomain_enum"
    description = "Enumerates subdomains that expand the target's attack surface."
    target_kinds = ("domain",)
    groups = ("standard", "deep")

    def run(self, target, ctx: dict[str, Any]) -> list[Finding]:
        raw = run_cmd(["subfinder", "-d", target.value, "-silent"], timeout=300)
        if not raw:
            return []
        return parse_subdomains(raw, target.value)
