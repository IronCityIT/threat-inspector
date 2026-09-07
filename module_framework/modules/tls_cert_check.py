"""
tls_cert_check.py — transport security grade + certificate health.

Re-housed from the ssl-grade workflow. Uses the public SSL Labs grading API and
the platform's own TLS stack (stdlib) internally; branded as transport security.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlparse

from base import Finding, ScanModule

from ._util import http_get, inspect_tls

# Cert-expiry thresholds (days) → severity.
_EXPIRY_CRITICAL = 0
_EXPIRY_HIGH = 14
_EXPIRY_MEDIUM = 30


def _hostname(target) -> str:
    """Extract a bare hostname from a domain/hostname/url target."""
    val: str = target.value
    if "://" in val:
        return urlparse(val).hostname or val
    return val


def _port(target) -> int:
    """The port to inspect — a URL target's own, or the TLS default.

    urlparse().hostname drops the port, so an `https://host:8443` target was
    silently inspected on 443. That grades a different service from the one the
    caller named, and on a host where 443 is closed it reported nothing at all.
    """
    val: str = target.value
    if "://" in val:
        return urlparse(val).port or 443
    return 443


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


def grade_findings(body: str, host: str) -> list[Finding]:
    """Grade EVERY endpoint the grading API reported (pure — unit tested).

    Only `endpoints[0]` used to be read. A name that resolves to several
    addresses is graded per address, and they routinely differ — one node left
    on an old configuration is exactly the finding worth having. Whenever the
    worst-configured endpoint was not the first in the list, its grade was
    discarded.
    """
    try:
        data = json.loads(body)
        endpoints = data.get("endpoints") or []
    except (json.JSONDecodeError, AttributeError):
        return []
    if not isinstance(endpoints, list):
        return []

    findings: list[Finding] = []
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        # An endpoint still being analysed carries no grade yet; the API is
        # asynchronous, so this is the normal state of a first request.
        findings.extend(grade_finding(endpoint.get("grade"), host))
    return findings


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


# OpenSSL's own verification wording -> (severity, what it means for the client).
# Matched as substrings, worst first, against the message the handshake gave us.
_VERIFY_FAILURES = (
    (
        "certificate has expired",
        "critical",
        "The certificate has expired. Browsers and clients refuse the connection outright.",
    ),
    (
        "certificate is not yet valid",
        "high",
        "The certificate is not valid yet, so clients refuse the connection.",
    ),
    (
        "hostname mismatch",
        "high",
        "The certificate does not cover this hostname, so clients refuse the connection.",
    ),
    (
        "self-signed certificate",
        "high",
        "The certificate is self-signed, so no client trusts it without manual configuration.",
    ),
    (
        "self signed certificate",
        "high",
        "The certificate is self-signed, so no client trusts it without manual configuration.",
    ),
    (
        "unable to get local issuer certificate",
        "high",
        "The certificate chain is incomplete or issued by an untrusted authority.",
    ),
    (
        "certificate revoked",
        "critical",
        "The certificate has been revoked by its issuer.",
    ),
)


def untrusted_finding(reason: str, host: str) -> list[Finding]:
    """Turn a failed certificate validation into a finding (pure — unit tested).

    This is the branch that did not exist. Every one of these conditions used
    to arrive as `fetch_cert() -> None`, which the module read as "no expiry
    finding" — indistinguishable from a certificate in perfect health.
    """
    if not reason:
        return []
    lowered = reason.lower()
    severity, detail = "high", "The certificate could not be validated."
    for needle, sev, message in _VERIFY_FAILURES:
        if needle in lowered:
            severity, detail = sev, message
            break
    return [
        Finding(
            module="tls_cert_check",
            target=host,
            severity=severity,
            title="Certificate failed validation",
            detail=f"{detail} Reported as: {reason}.",
            evidence={"verification_error": reason},
        )
    ]


def unreachable_finding(host: str, port: int, error: str) -> list[Finding]:
    """Say that transport security was not assessed, rather than staying silent.

    An empty result reads, in the report, exactly like a healthy endpoint.
    """
    return [
        Finding(
            module="tls_cert_check",
            target=host,
            severity="info",
            title="Transport security could not be assessed",
            detail=(
                f"No TLS service answered on {host}:{port}, so the certificate and "
                "transport configuration were not evaluated. This is not a finding "
                "of good configuration."
            ),
            evidence={"host": host, "port": port, "error": error, "state": "not_assessed"},
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
        port = _port(target)
        findings: list[Finding] = []

        # Certificate health via the platform TLS stack (no external tool needed).
        # The three outcomes are kept apart deliberately: a certificate that
        # FAILS validation is a finding, not an absence.
        tls = inspect_tls(host, port=port)
        if not tls.reachable:
            findings.extend(unreachable_finding(host, port, tls.error))
        elif not tls.verified:
            findings.extend(untrusted_finding(tls.reason, host))
        elif tls.cert and tls.cert.get("notAfter"):
            findings.extend(cert_finding(_days_until(tls.cert["notAfter"]), host))

        # Best-effort transport grade via the public SSL Labs API.
        # quote() because the host is interpolated into a query string: a value
        # carrying '&' or '#' would otherwise rewrite the request's parameters.
        body = http_get(
            f"https://api.ssllabs.com/api/v3/analyze?host={quote(host, safe='')}"
            "&fromCache=on&all=done",
            timeout=30,
        )
        if body:
            findings.extend(grade_findings(body, host))

        return findings
