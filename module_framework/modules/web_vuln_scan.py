"""
web_vuln_scan.py — active web-application vulnerability scan (NEW capability).

A deep-only, intrusive check. Uses a community template scanner internally;
branded as a web application vulnerability assessment. Runs only against URL
targets so it never fires blindly at raw IPs.
"""
from __future__ import annotations

import json
from typing import Any

from base import SEVERITIES, Finding, ScanModule

from ._util import run_cmd


def parse_findings(raw: str, target_value: str) -> list[Finding]:
    """Parse JSONL scanner output into findings (pure — unit tested)."""
    findings: list[Finding] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {}) or {}
        sev = str(info.get("severity", "info")).lower()
        if sev not in SEVERITIES:
            sev = "info"
        findings.append(
            Finding(
                module="web_vuln_scan",
                target=target_value,
                severity=sev,
                title=info.get("name") or "Web application finding",
                detail=obj.get("matched-at") or obj.get("host") or "",
                evidence={
                    "template": obj.get("template-id"),
                    "matched_at": obj.get("matched-at"),
                },
            )
        )
    return findings


class WebVulnScan(ScanModule):
    name = "web_vuln_scan"
    description = "Actively probes a web application for known vulnerabilities."
    target_kinds = ("url",)
    groups = ("deep",)

    def run(self, target, ctx: dict[str, Any]) -> list[Finding]:
        raw = run_cmd(
            ["nuclei", "-u", target.value, "-jsonl", "-silent"],
            timeout=900,
        )
        if not raw:
            return []
        return parse_findings(raw, target.value)
