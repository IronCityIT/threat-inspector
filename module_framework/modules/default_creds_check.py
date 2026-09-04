"""
default_creds_check.py — exposed management interfaces (NEW capability).

Default-credential attacks require an exposed admin/management surface first.
This module probes a curated list of well-known management paths and flags the
reachable ones so they can be checked for default credentials. It is deliberately
non-intrusive: it does NOT attempt credential pairs. Active credential testing is
a scoped follow-up (see PRODUCTIZE_NOTES.md) — not fabricated here.
"""

from __future__ import annotations

from typing import Any

from base import Finding, ScanModule

from ._util import http_probe

# Management/admin surfaces that commonly ship with default credentials.
_ADMIN_PATHS = (
    "/admin",
    "/login",
    "/manager/html",
    "/phpmyadmin",
    "/wp-admin",
    "/wp-login.php",
    "/administrator",
    "/console",
    "/actuator",
)


# How each status class reads. An interface that answers 401/403 is present and
# asking for credentials — the strongest signal there is for this check — so it
# is reported at least as loudly as one that answers 200.
_AUTH_STATUSES = (401, 403, 407)


def evaluate(results: dict[str, int | None], target_value: str) -> list[Finding]:
    """Map path -> HTTP status into findings for reachable interfaces (pure — tested)."""
    findings: list[Finding] = []
    for path, status in results.items():
        if status is None:
            continue  # no HTTP response at all — nothing is exposed here
        if status == 404 or status == 410 or status >= 500:
            continue  # absent, or broken enough not to be a usable interface
        if status in _AUTH_STATUSES:
            severity = "medium"
            detail = (
                f"{path} responded {status} — a management interface is present and "
                "prompting for credentials. Verify it does not accept default or "
                "weak credentials, and that it should be reachable from here at all."
            )
        else:
            severity = "medium"
            detail = (
                f"{path} responded {status}. Verify it does not accept default or weak credentials."
            )
        findings.append(
            Finding(
                module="default_creds_check",
                target=target_value,
                severity=severity,
                title=f"Exposed management interface: {path}",
                detail=detail,
                evidence={"path": path, "status": status},
            )
        )
    return findings


def _to_base_url(target) -> str:
    val: str = target.value
    if "://" in val:
        return val.rstrip("/")
    return f"https://{val}"


class DefaultCredsCheck(ScanModule):
    name = "default_creds_check"
    description = "Flags exposed management interfaces prone to default credentials."
    target_kinds = ("domain", "hostname", "url", "ip")
    groups = ("standard", "deep")

    def run(self, target, ctx: dict[str, Any]) -> list[Finding]:
        base = _to_base_url(target)
        results: dict[str, int | None] = {}
        for path in _ADMIN_PATHS:
            # http_probe, NOT http_head. http_head collapses every non-2xx/3xx
            # into None, so this module used to hardcode `200 if headers else
            # None` and could not see a 401/403 at all — which meant the single
            # most telling response for an exposed admin panel was discarded,
            # and evaluate()'s 404/5xx branch was unreachable from here.
            probe = http_probe(f"{base}{path}", timeout=10)
            results[path] = probe.status if probe is not None else None
        return evaluate(results, target.value)
