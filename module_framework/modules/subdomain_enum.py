"""
subdomain_enum.py — passive subdomain discovery for a domain.

Re-housed from the asset-discovery workflow. Uses subfinder internally; branded
as attack-surface / asset discovery.
"""

from __future__ import annotations

import re
from typing import Any

from base import Finding, ScanModule

from ._util import run_cmd

# A syntactically valid hostname: dot-separated labels of letters, digits and
# hyphens, no label starting or ending with a hyphen, 253 characters at most.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$"
)


def _in_scope(host: str, domain: str) -> bool:
    """Is `host` the domain itself, or something under it?

    `endswith("." + domain)` rather than `endswith(domain)`, so `evil-acme.com`
    is not treated as part of `acme.com`.
    """
    return host == domain or host.endswith(f".{domain}")


def parse_subdomains(raw: str, domain: str) -> list[Finding]:
    """Turn a newline list of hostnames into findings (pure — unit tested).

    Every line used to become a finding. Two things got through:

        [INF] Enumerating subdomains for acme.com  ->  reported as a subdomain
        evil.example.net                           ->  reported as acme.com's

    The first is scanner chatter claimed as a discovered asset. The second is a
    host that is not the client's, attributed to the client's attack surface —
    on a security report, naming someone else's domain as part of your estate is
    worse than naming nothing.

    A line is now a subdomain only if it parses as a hostname AND sits under the
    domain that was scanned. Lines that do neither are counted and reported, so
    a scanner suddenly emitting something unexpected is visible rather than
    silently dropped.
    """
    seen: set[str] = set()
    findings: list[Finding] = []
    skipped = 0

    for line in raw.splitlines():
        host = line.strip().lower().rstrip(".")
        if not host:
            continue
        if not _HOSTNAME_RE.match(host) or not _in_scope(host, domain.strip().lower()):
            skipped += 1
            continue
        if host in seen:
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

    if skipped:
        # Dropping them silently would hide a scanner that has started emitting
        # something we do not understand — including results for a domain that
        # is not the client's.
        findings.append(
            Finding(
                module="subdomain_enum",
                target=domain,
                severity="info",
                title="Some discovery output was not a subdomain of this domain",
                detail=(
                    f"{skipped} line(s) of discovery output were not hostnames under "
                    f"{domain} and were not reported as part of its attack surface."
                ),
                evidence={"skipped_lines": skipped, "domain": domain},
            )
        )

    return findings


class SubdomainEnum(ScanModule):
    name = "subdomain_enum"
    description = "Enumerates subdomains that expand the target's attack surface."
    target_kinds = ("domain",)
    groups = ("standard", "deep")
    requires = ("subfinder",)

    def run(self, target, ctx: dict[str, Any]) -> list[Finding]:
        raw = run_cmd(["subfinder", "-d", target.value, "-silent"], timeout=300)
        if not raw:
            return []
        return parse_subdomains(raw, target.value)
