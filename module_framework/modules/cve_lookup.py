"""
cve_lookup.py — known CVEs for the services exposed on a host (NEW capability).

Uses nmap's vulners NSE script internally to map detected service versions to
published CVEs. Self-contained: it fingerprints and correlates in one pass so it
can run standalone. Branded as a known-vulnerability correlation.
"""

from __future__ import annotations

import re
from typing import Any

from base import Finding, ScanModule

from ._util import run_cmd

# A CVE identifier, and the CVSS score that USUALLY follows it:
#
#     |       CVE-2021-3156  9.8     https://vulners.com/cve/CVE-2021-3156
#
# The score is optional in this pattern on purpose. It used to be mandatory —
# `(CVE-\d{4}-\d{4,7})\s+([\d.]+)` — so a CVE the scanner reported WITHOUT a
# score matched nothing and was dropped silently:
#
#     CVE-2021-0001  https://vulners.com/cve/CVE-2021-0001   -> no finding
#     CVE-2021-0004  n/a  https://...                        -> no finding
#
# A published CVE affecting a client's host disappearing from their report
# because the scanner did not attach a number is the wrong trade in every
# direction.
_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})(?:\s+(\d+(?:\.\d+)?))?")

# The port line that precedes a vulners block, e.g.
#     22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
_PORT_RE = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)")

# Severity for a CVE the scanner reported without a usable score.
#
# Not "info": that reads as "not a problem", and it would hide a real CVE from
# anyone triaging medium-and-above — which is most people. Not "critical"
# either, which would overstate what is actually unknown. "medium" surfaces it
# without claiming to know how bad it is, and the detail says the score was not
# reported so the placeholder is visible rather than implied.
UNSCORED_SEVERITY = "medium"


def _severity_for(score: float | None) -> str:
    """CVSS v3 bands: 9.0+ critical, 7.0+ high, 4.0+ medium, >0 low, 0 none."""
    if score is None:
        return UNSCORED_SEVERITY
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def parse_cves(raw: str, target_value: str) -> list[Finding]:
    """Parse nmap/vulners output into per-CVE findings (pure — unit tested).

    Findings are de-duplicated per (CVE, port) rather than per CVE. The same
    CVE genuinely can affect two services on one host — an OpenSSH issue on 22
    and a library issue on 443 — and collapsing them lost the second occurrence
    AND left the survivor with no indication of which service it was about.
    """
    findings: list[Finding] = []
    seen: set[tuple[str, int | None]] = set()
    port: int | None = None
    protocol: str | None = None
    service: str | None = None

    for line in raw.splitlines():
        stripped = line.strip()

        port_match = _PORT_RE.match(stripped)
        if port_match:
            # A new service block: everything below belongs to this port until
            # the next one.
            port = int(port_match.group(1))
            protocol = port_match.group(2)
            service = port_match.group(3)
            continue

        m = _CVE_RE.search(stripped)
        if not m:
            continue

        cve = m.group(1)
        if (cve, port) in seen:
            continue
        seen.add((cve, port))

        raw_score = m.group(2)
        score: float | None = None
        if raw_score is not None:
            try:
                score = float(raw_score)
            except ValueError:
                score = None

        where = f" on {port}/{protocol}" if port is not None else ""
        if score is None:
            detail = (
                f"{cve} affects an exposed service{where}. "
                "The scanner reported no CVSS score, so the severity shown is a "
                "placeholder rather than a measurement."
            )
        else:
            detail = f"{cve} (CVSS {score}) affects an exposed service{where}."

        findings.append(
            Finding(
                module="cve_lookup",
                target=target_value,
                severity=_severity_for(score),
                title=f"Known vulnerability: {cve}",
                detail=detail,
                evidence={
                    "cve": cve,
                    "cvss": score,
                    "cvss_reported": score is not None,
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                },
            )
        )
    return findings


class CveLookup(ScanModule):
    name = "cve_lookup"
    description = "Correlates exposed service versions with known vulnerabilities."
    target_kinds = ("ip", "domain", "hostname")
    groups = ("standard", "deep")
    requires = ("nmap",)

    def run(self, target, ctx: dict[str, Any]) -> list[Finding]:
        raw = run_cmd(
            ["nmap", "-sV", "--script", "vulners", "--top-ports", "1000", "-oN", "-", target.value],
            timeout=900,
        )
        if not raw:
            return []
        return parse_cves(raw, target.value)
