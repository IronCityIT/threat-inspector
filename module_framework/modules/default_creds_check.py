"""
default_creds_check.py — exposed management interfaces (NEW capability).

Default-credential attacks require an exposed admin/management surface first.
This module probes a curated list of well-known management paths and flags the
reachable ones so they can be checked for default credentials. It is deliberately
non-intrusive: it does NOT attempt credential pairs. Active credential testing is
a scoped follow-up (see PRODUCTIZE_NOTES.md) — not fabricated here.
"""

from __future__ import annotations

import secrets
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


def _is_present(status: int | None) -> bool:
    """True if a path answering this status may be a usable interface."""
    if status is None:
        return False  # no HTTP response at all — nothing is exposed here
    # 404/410 is absent; 5xx is broken enough not to be a usable interface.
    return not (status == 404 or status == 410 or status >= 500)


def evaluate(
    results: dict[str, int | None],
    target_value: str,
    scheme: str = "https",
    tls_verified: bool = True,
    baseline_status: int | None = None,
) -> list[Finding]:
    """Map path -> HTTP status into findings for reachable interfaces (pure — tested).

    `baseline_status` is what the site answers for a path that cannot exist. A
    path answering the same is indistinguishable from that default, so it is
    listed in a single info finding instead of being reported as an interface.
    None means there is no baseline, and nothing is suppressed.
    """
    findings: list[Finding] = []
    not_assessed: list[str] = []
    for path, status in results.items():
        if not _is_present(status):
            continue
        if status not in _AUTH_STATUSES and status == baseline_status:
            not_assessed.append(path)
            continue
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
                evidence={
                    "path": path,
                    "status": status,
                    "scheme": scheme,
                    "tls_verified": tls_verified,
                },
            )
        )
    if not_assessed:
        findings.append(
            Finding(
                module="default_creds_check",
                target=target_value,
                severity="info",
                title="Management paths could not be assessed",
                detail=(
                    f"{len(not_assessed)} management path(s) could not be told apart from the "
                    f"site's default response ({baseline_status} for a path that does not "
                    "exist) and were not assessed. This does not show that no management "
                    "interface is present on them."
                ),
                evidence={
                    # Every finding from this module carries a string "path".
                    "path": ", ".join(not_assessed),
                    "paths": not_assessed,
                    "state": "not_assessed",
                    "baseline_status": baseline_status,
                    "scheme": scheme,
                    "tls_verified": tls_verified,
                },
            )
        )
    return findings


# Resolving the base is a reachability question, not a slow one, and it is now
# tried up to three times per target. A host behind a firewall that DROPS rather
# than refuses costs the full timeout on each miss, so this is deliberately
# shorter than the probe timeout below: worst case 10s of negotiation per target
# instead of 30s. The probes themselves keep the longer timeout, because by then
# the host has already answered once and is worth waiting for.
_RESOLVE_TIMEOUT = 5
_PROBE_TIMEOUT = 10


# A base URL to try, and whether to validate the certificate when trying it.
_Candidate = tuple[str, bool]


def _candidate_bases(target) -> list[_Candidate]:
    """Base URLs to try, best first, as (base, verify_tls).

    This used to be a single `https://{value}`, which found nothing at all on an
    `ip` target. An IP has no name to match, so certificate validation fails,
    urlopen raises, and the probe reports "no HTTP response" — indistinguishable
    from a host with nothing on it. A plain-HTTP admin panel was equally
    invisible because http:// was never tried. Both cases returned zero findings
    against a management interface answering 401 on the very next line.

    That is the wrong way round for this check: appliances on an internal range
    are the population most likely to still hold default credentials, and they
    are exactly the hosts that answer on a bare IP behind a self-signed
    certificate.

    An explicit URL target keeps the scheme it was given — the caller said what
    they meant. Everything else tries, in order: HTTPS validated, HTTPS
    unvalidated, then HTTP.
    """
    val: str = target.value
    if "://" in val:
        return [(val.rstrip("/"), True)]
    return [(f"https://{val}", True), (f"https://{val}", False), (f"http://{val}", True)]


def _to_base_url(target) -> str:
    """The first base URL that would be tried (kept for callers and tests)."""
    return _candidate_bases(target)[0][0]


class DefaultCredsCheck(ScanModule):
    name = "default_creds_check"
    description = "Flags exposed management interfaces prone to default credentials."
    target_kinds = ("domain", "hostname", "url", "ip")
    groups = ("standard", "deep")

    def run(self, target, ctx: dict[str, Any]) -> list[Finding]:
        # Settle on ONE base first, with a single request per candidate, rather
        # than retrying every candidate for all nine paths. A host that speaks
        # HTTP at all answers something at "/" — any status, 404 included — and
        # that is enough to know which scheme to use for the real probes.
        resolved: _Candidate | None = None
        for base, verify_tls in _candidate_bases(target):
            if http_probe(f"{base}/", timeout=_RESOLVE_TIMEOUT, verify_tls=verify_tls) is not None:
                resolved = (base, verify_tls)
                break
        if resolved is None:
            return []  # nothing answered on any scheme — no web surface here

        base, verify_tls = resolved
        results: dict[str, int | None] = {}
        for path in _ADMIN_PATHS:
            # http_probe, NOT http_head. http_head collapses every non-2xx/3xx
            # into None, so this module used to hardcode `200 if headers else
            # None` and could not see a 401/403 at all — which meant the single
            # most telling response for an exposed admin panel was discarded,
            # and evaluate()'s 404/5xx branch was unreachable from here.
            probe = http_probe(f"{base}{path}", timeout=_PROBE_TIMEOUT, verify_tls=verify_tls)
            results[path] = probe.status if probe is not None else None
        scheme = "https" if base.startswith("https://") else "http"

        # Catch-all sites (single-page apps, redirect-to-home, 405 to every HEAD)
        # answer all nine paths alike, so ask what a nonexistent path looks like.
        # Sent only when an answer depends on it, and unguessable so that it
        # cannot name something real.
        baseline_status: int | None = None
        if any(_is_present(s) and s not in _AUTH_STATUSES for s in results.values()):
            baseline = http_probe(
                f"{base}/{secrets.token_hex(16)}", timeout=_PROBE_TIMEOUT, verify_tls=verify_tls
            )
            baseline_status = baseline.status if baseline is not None else None

        return evaluate(
            results,
            target.value,
            scheme=scheme,
            tls_verified=verify_tls,
            baseline_status=baseline_status,
        )
