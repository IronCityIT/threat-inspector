"""
header_security_check.py — presence of HTTP security response headers.

Re-housed from the ssl-grade workflow's header step. Passive: one HEAD request,
flags missing hardening headers.
"""

from __future__ import annotations

from typing import Any

from base import Finding, ScanModule

from ._util import http_head

# header name -> (human label, severity when missing)
_EXPECTED = {
    "strict-transport-security": ("HTTP Strict Transport Security (HSTS)", "medium"),
    "content-security-policy": ("Content Security Policy", "medium"),
    "x-frame-options": ("Clickjacking protection (X-Frame-Options)", "low"),
    "x-content-type-options": ("MIME-sniffing protection (X-Content-Type-Options)", "low"),
    "referrer-policy": ("Referrer Policy", "low"),
}


def evaluate_headers(headers: dict[str, str], target_value: str) -> list[Finding]:
    """Flag missing security headers (pure — unit tested)."""
    present = {k.lower() for k in headers}
    findings: list[Finding] = []
    for name, (label, sev) in _EXPECTED.items():
        if name not in present:
            findings.append(
                Finding(
                    module="header_security_check",
                    target=target_value,
                    severity=sev,
                    title=f"Missing security header: {label}",
                    detail=f"The response does not set {label}.",
                    evidence={"header": name},
                )
            )
    return findings


def _to_url(target) -> str:
    val: str = target.value
    if "://" in val:
        return val
    return f"https://{val}"


class HeaderSecurityCheck(ScanModule):
    name = "header_security_check"
    description = "Checks for recommended HTTP security response headers."
    target_kinds = ("domain", "hostname", "url")
    groups = ("quick", "standard", "deep")

    def run(self, target, ctx: dict[str, Any]) -> list[Finding]:
        headers = http_head(_to_url(target))
        if headers is None:
            return []
        return evaluate_headers(headers, target.value)
