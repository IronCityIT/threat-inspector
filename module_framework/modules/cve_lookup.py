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

# vulners emits lines like: "    CVE-2021-3156  9.8  https://vulners.com/cve/CVE-2021-3156"
_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})\s+([\d.]+)")


def _severity_for(score: float) -> str:
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
    """Parse nmap/vulners output into per-CVE findings (pure — unit tested)."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        m = _CVE_RE.search(line)
        if not m:
            continue
        cve, score_s = m.group(1), m.group(2)
        if cve in seen:
            continue
        seen.add(cve)
        try:
            score = float(score_s)
        except ValueError:
            score = 0.0
        findings.append(
            Finding(
                module="cve_lookup",
                target=target_value,
                severity=_severity_for(score),
                title=f"Known vulnerability: {cve}",
                detail=f"{cve} (CVSS {score}) affects an exposed service.",
                evidence={"cve": cve, "cvss": score},
            )
        )
    return findings


class CveLookup(ScanModule):
    name = "cve_lookup"
    description = "Correlates exposed service versions with known vulnerabilities."
    target_kinds = ("ip", "domain", "hostname")
    groups = ("standard", "deep")

    def run(self, target, ctx: dict[str, Any]) -> list[Finding]:
        raw = run_cmd(
            ["nmap", "-sV", "--script", "vulners", "--top-ports", "1000", "-oN", "-", target.value],
            timeout=900,
        )
        if not raw:
            return []
        return parse_cves(raw, target.value)
