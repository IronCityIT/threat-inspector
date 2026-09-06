"""
tls_cert_check.py — transport security grade + certificate health.

Re-housed from the ssl-grade workflow. Uses the public SSL Labs grading API and
the platform's own TLS stack (stdlib) internally; branded as transport security.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from base import Finding, ScanModule

from ._util import fetch_cert, http_get

# Cert-expiry thresholds (days) → severity.
_EXPIRY_CRITICAL = 0
_EXPIRY_HIGH = 14
_EXPIRY_MEDIUM = 30


def _hostname(target) -> str:
    """Extract a bare hostname from a domain/hostname/url target."""
    val: str = target.value
    if "://" in val:
        from urllib.parse import urlparse

        return urlparse(val).hostname or val
    return val


def grade_finding(grade: str | None, host: str) -> list[Finding]:
    """Turn an SSL Labs letter grade into a finding (pure — unit tested)."""
    if not grade:
        return []
    weak = grade[0].upper() in {"C", "D", "E", "F", "T", "M"}
    return [
        Finding(
            module="tls_cert_check",
            target=host,
            severity="high" if weak else "info",
            title=f"Transport security grade: {grade}",
            detail=f"Endpoint graded {grade} for TLS configuration.",
            evidence={"grade": grade},
        )
    ]


def cert_finding(days_left: int | None, host: str) -> list[Finding]:
    """Turn days-until-expiry into a finding (pure — unit tested)."""
    if days_left is None:
        return []
    if days_left <= _EXPIRY_CRITICAL:
        sev, msg = "critical", "certificate has expired"
    elif days_left <= _EXPIRY_HIGH:
        sev, msg = "high", "certificate expires within two weeks"
    elif days_left <= _EXPIRY_MEDIUM:
        sev, msg = "medium", "certificate expires within a month"
    else:
        sev, msg = "info", "certificate validity is healthy"
    return [
        Finding(
            module="tls_cert_check",
            target=host,
            severity=sev,
            title=f"Certificate expiry: {days_left} day(s) remaining",
            detail=msg.capitalize() + ".",
            evidence={"days_until_expiry": days_left},
        )
    ]


_NOT_AFTER = "%b %d %H:%M:%S %Y"


def _parse_not_after(not_after: str) -> datetime | None:
    """Parse a certificate notAfter string into an aware UTC datetime.

    This used to be a single strptime with %Z, which accepts only "GMT", "UTC"
    and whatever the local machine's zone happens to be called. Every other
    rendering — a numeric offset, some other abbreviation, or no zone at all —
    returned None, and a None makes run() skip the expiry finding entirely. An
    expired certificate produced no finding whatsoever, which is the one case
    this module exists to catch.

    RFC 5280 requires certificate validity times to be expressed in Zulu time,
    so a trailing zone name is a rendering artefact and UTC is the correct
    reading of any of these forms.
    """
    if not isinstance(not_after, str):
        return None
    # OpenSSL pads single-digit days to two spaces ("Jun  1"); collapse runs.
    text = " ".join(not_after.split())
    if not text:
        return None

    # A genuine numeric offset ("... 2027 +0000") is honoured as given.
    try:
        return datetime.strptime(text, _NOT_AFTER + " %z").astimezone(timezone.utc)
    except ValueError:
        pass

    # Otherwise drop a trailing zone name ("GMT", "CEST", ...) and read as UTC.
    head, _, tail = text.rpartition(" ")
    if head and tail.isalpha():
        text = head
    try:
        return datetime.strptime(text, _NOT_AFTER).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _days_until(not_after: str) -> int | None:
    """Days from now until a certificate notAfter, or None if unparseable."""
    expiry = _parse_not_after(not_after)
    if expiry is None:
        return None
    return (expiry - datetime.now(timezone.utc)).days


class TlsCertCheck(ScanModule):
    name = "tls_cert_check"
    description = "Grades transport security and flags certificates nearing expiry."
    target_kinds = ("domain", "hostname", "url")
    groups = ("quick", "standard", "deep")

    def run(self, target, ctx: dict[str, Any]) -> list[Finding]:
        host = _hostname(target)
        findings: list[Finding] = []

        # Certificate expiry via the platform TLS stack (no external tool needed).
        cert = fetch_cert(host)
        if cert and cert.get("notAfter"):
            findings.extend(cert_finding(_days_until(cert["notAfter"]), host))

        # Best-effort transport grade via the public SSL Labs API.
        body = http_get(
            f"https://api.ssllabs.com/api/v3/analyze?host={host}&fromCache=on&all=done",
            timeout=30,
        )
        if body:
            try:
                data = json.loads(body)
                endpoints = data.get("endpoints") or []
                if endpoints:
                    findings.extend(grade_finding(endpoints[0].get("grade"), host))
            except (json.JSONDecodeError, AttributeError, IndexError):
                pass

        return findings
