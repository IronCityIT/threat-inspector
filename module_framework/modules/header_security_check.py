"""
header_security_check.py — HTTP security response headers, and whether they work.

Re-housed from the ssl-grade workflow's header step. Passive: one HEAD request,
flags hardening headers that are missing OR set to a value that provides no
protection.

The presence-only version of this check graded a header by whether the name
appeared. `Strict-Transport-Security: max-age=0` switches HSTS OFF, and
`X-Content-Type-Options: enabled` does nothing at all — a browser accepts only
the exact token `nosniff` — yet both counted as protected and produced no
finding. A header that is present and inert is arguably worse than one that is
absent: it survives an audit that greps for the name.
"""

from __future__ import annotations

from collections.abc import Callable
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


def _directives(value: str) -> dict[str, str]:
    """Split `max-age=0; includeSubDomains` into {'max-age': '0', 'includesubdomains': ''}."""
    parsed: dict[str, str] = {}
    for part in value.split(";"):
        part = part.strip().lower()
        if not part:
            continue
        name, _, val = part.partition("=")
        parsed[name.strip()] = val.strip().strip('"')
    return parsed


def _check_hsts(value: str) -> tuple[str, str] | None:
    """max-age is what makes HSTS do anything; zero or absent means it does not.

    A short-but-nonzero max-age is deliberately NOT flagged. It is weaker than
    the usual recommendation but it is a policy judgement, and this check
    reports facts a client can verify rather than opinions about duration.
    """
    directives = _directives(value)
    if "max-age" not in directives:
        return ("the header sets no max-age, so no policy is stored", "medium")
    try:
        max_age = int(directives["max-age"])
    except ValueError:
        return (f"max-age is not a number ({directives['max-age']!r})", "medium")
    if max_age <= 0:
        return ("max-age is 0, which switches HSTS off and clears any stored policy", "medium")
    return None


def _check_frame_options(value: str) -> tuple[str, str] | None:
    """Only DENY and SAMEORIGIN are honoured; ALLOW-FROM was dropped by browsers."""
    token = value.strip().lower()
    if token in ("deny", "sameorigin"):
        return None
    if token.startswith("allow-from"):
        return ("ALLOW-FROM is obsolete and ignored by current browsers", "low")
    return (f"{value.strip()!r} is not a recognised value, so no framing policy applies", "low")


def _check_content_type_options(value: str) -> tuple[str, str] | None:
    """`nosniff` is the only token that exists; anything else is ignored."""
    if value.strip().lower() == "nosniff":
        return None
    return (f"{value.strip()!r} is not 'nosniff', so MIME-sniffing is not disabled", "low")


def _check_referrer_policy(value: str) -> tuple[str, str] | None:
    """unsafe-url sends the full URL, path and query included, to any origin."""
    tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
    if not tokens:
        return ("the header is empty, so the browser default applies", "low")
    # The last token a browser recognises is the one it uses.
    if "unsafe-url" in tokens:
        return ("'unsafe-url' sends the full URL, including path and query, cross-origin", "low")
    return None


def _check_csp(value: str) -> tuple[str, str] | None:
    """A policy that re-allows inline script gives up most of what CSP is for."""
    policy = value.lower()
    weaknesses = [token for token in ("'unsafe-inline'", "'unsafe-eval'") if token in policy]
    if weaknesses:
        return (
            f"the policy allows {' and '.join(weaknesses)}, which permits injected script",
            "low",
        )
    return None


# Only headers whose VALUE can render them inert need an entry here.
_VALUE_CHECKS: dict[str, Callable[[str], tuple[str, str] | None]] = {
    "strict-transport-security": _check_hsts,
    "x-frame-options": _check_frame_options,
    "x-content-type-options": _check_content_type_options,
    "referrer-policy": _check_referrer_policy,
    "content-security-policy": _check_csp,
}


def evaluate_headers(headers: dict[str, str], target_value: str) -> list[Finding]:
    """Flag hardening headers that are missing or ineffective (pure — unit tested)."""
    normalised = {k.lower(): v for k, v in headers.items()}
    findings: list[Finding] = []

    for name, (label, missing_severity) in _EXPECTED.items():
        if name not in normalised:
            findings.append(
                Finding(
                    module="header_security_check",
                    target=target_value,
                    severity=missing_severity,
                    title=f"Missing security header: {label}",
                    detail=f"The response does not set {label}.",
                    evidence={"header": name, "state": "missing"},
                )
            )
            continue

        value = normalised[name]
        problem = _VALUE_CHECKS[name](value)
        if problem is None:
            continue
        reason, severity = problem
        findings.append(
            Finding(
                module="header_security_check",
                target=target_value,
                severity=severity,
                title=f"Ineffective security header: {label}",
                detail=f"{label} is set, but {reason}.",
                evidence={
                    "header": name,
                    "state": "ineffective",
                    "value": value,
                    "reason": reason,
                },
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
        url = _to_url(target)
        headers = http_head(url)
        if headers is None:
            # Returning [] here reads, in the report, exactly like a site with
            # every header correctly set: no findings for this module. It is
            # not the same thing. The run itself did not fail, so the scan's
            # health counters — which track module EXCEPTIONS — do not catch
            # it either. Say plainly that the question was never answered.
            return [
                Finding(
                    module="header_security_check",
                    target=target.value,
                    severity="info",
                    title="Security headers could not be assessed",
                    detail=(
                        f"No usable HTTP response was received from {url}, so the "
                        "security headers were not evaluated. This is not a finding "
                        "of good configuration."
                    ),
                    evidence={"url": url, "state": "not_assessed"},
                )
            ]
        return evaluate_headers(headers, target.value)
