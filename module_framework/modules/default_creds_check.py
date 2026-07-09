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

from ._util import http_head

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


def evaluate(results: dict[str, int | None], target_value: str) -> list[Finding]:
    """Map path -> HTTP status into findings for reachable interfaces (pure — tested)."""
    findings: list[Finding] = []
    for path, status in results.items():
        if status is None:
            continue
        # Reachable (not missing, not server error) = an exposed interface worth review.
        if status == 404 or status >= 500:
            continue
        findings.append(
            Finding(
                module="default_creds_check",
                target=target_value,
                severity="medium",
                title=f"Exposed management interface: {path}",
                detail=(
                    f"{path} responded ({status}). Verify it does not accept "
                    "default or weak credentials."
                ),
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
            headers = http_head(f"{base}{path}", timeout=10)
            # http_head returns headers on 2xx/3xx; None on error/4xx/5xx via urlopen.
            results[path] = 200 if headers is not None else None
        return evaluate(results, target.value)
