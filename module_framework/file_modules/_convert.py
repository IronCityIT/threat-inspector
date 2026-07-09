"""
_convert.py — ParsedVulnerability (tool) -> Finding (framework).

The single mapping every FileModule shares. Keeping it here means the parsers
stay untouched and the framework's Finding stays generic; only this seam knows
both shapes.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from base import Finding

from threat_inspector.parsers.base import BaseParser

if TYPE_CHECKING:
    from threat_inspector.parsers.base import ParsedVulnerability, ParseResult


def _target_for(v: ParsedVulnerability, source_file: str) -> str:
    """Best asset identifier for a finding: URL > IP > host > the source file."""
    return v.asset_url or v.asset_ip or v.asset_name or source_file


def to_findings(module_name: str, result: ParseResult) -> list[Finding]:
    """Convert a parser's ParseResult into framework Findings.

    Severity is re-normalized through the parser's own mapping so it always lands
    in the framework's SEVERITIES set (Finding hard-errors otherwise) even if a
    parser emitted a raw vendor value.
    """
    source_file = str(result.scan_metadata.get("source_file", "uploaded-file"))
    findings: list[Finding] = []
    for v in result.vulnerabilities:
        detail = v.description or v.solution or ""
        evidence = {
            "asset_name": v.asset_name,
            "asset_ip": v.asset_ip,
            "asset_port": v.asset_port,
            "asset_url": v.asset_url,
            "cve_id": v.cve_id,
            "cwe_id": v.cwe_id,
            "cvss_score": v.cvss_score,
            "cvss_vector": v.cvss_vector,
            "solution": v.solution,
            "source_file": source_file,
        }
        # Drop empties so evidence stays readable on every surface.
        evidence = {k: val for k, val in evidence.items() if val not in ("", None)}
        findings.append(
            Finding(
                module=module_name,
                target=_target_for(v, source_file),
                severity=BaseParser.normalize_severity(v.severity),
                title=v.title,
                detail=detail,
                evidence=evidence,
            )
        )
    return findings
