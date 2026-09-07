"""Read stored scan results over the API, scoped to the caller's tenant.

The API's own scan set (`_inspectors` in main.py) is a process-local dict: it
does not survive a restart and does not work behind more than one replica. That
was recorded as a known gap, and under the self-hosted direction it is also a
direct conflict with the rule that persistent state lives in MariaDB.

These routes are the read side of that store. They are **additive** — the
existing upload/analyze flow is untouched — and they are what a dashboard would
call instead of reading Firestore directly.

Tenancy
-------
Every route depends on `current_tenant`, so the tenant comes from the caller's
credential and never from the request, and every query goes through
`ScanRepository`, which has no unscoped entry point. Those are the same two
properties `firestore.rules` and `exchangeAuth0Token` enforced between them,
and neither is optional here.

Availability
------------
The store is optional at runtime. With no `DATABASE_URL` these routes answer
**503**, and the rest of the API keeps working — the app must not fail to start
just because the store is not configured yet. SQLAlchemy is imported lazily for
the same reason: it is a declared dependency, but the API should not become
unimportable on a machine that has not installed it.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from threat_inspector.api.auth import current_tenant

log = logging.getLogger("threat_inspector.api.store")

router = APIRouter(prefix="/api/v1/store", tags=["store"])

# Engines are pooled and expensive to build, so one is kept per DSN rather than
# created per request. Keyed by URL so a test that repoints DATABASE_URL gets a
# new engine instead of silently reusing the previous database.
_engines: dict[str, Any] = {}


def _engine(url: str) -> Any:
    if url not in _engines:
        from sqlalchemy import create_engine

        _engines[url] = create_engine(url)
    return _engines[url]


def reset_engines() -> None:
    """Dispose cached engines. For tests and for a configuration reload."""
    for engine in _engines.values():
        engine.dispose()
    _engines.clear()


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        # 503, not 500: the store is not broken, it is not configured. A caller
        # can tell "come back later" from "something is wrong".
        raise HTTPException(
            status_code=503,
            detail="store_not_configured: set DATABASE_URL to enable stored scan results",
        )
    return url


def session_factory():
    """FastAPI dependency yielding a repository bound to one request."""
    url = _database_url()
    try:
        from sqlalchemy.orm import Session
    except ImportError as e:  # pragma: no cover - dependency is declared
        raise HTTPException(
            status_code=503, detail="store_unavailable: sqlalchemy is not installed"
        ) from e

    from threat_inspector.storage.repository import ScanRepository

    with Session(_engine(url)) as session:
        yield ScanRepository(session)


def _scan_dict(scan: Any) -> dict[str, Any]:
    """One scan, as a client-facing record.

    `diagnostics` carries Iron City module ids only — never an underlying
    scanner's name — so it is safe on a client surface.
    """
    return {
        "scan_id": scan.scan_id,
        "client_id": scan.client_id,
        "scan_type": scan.scan_type,
        "target": scan.target,
        "status": scan.status,
        # Kept distinct from `status` on purpose: an empty findings list means
        # "nothing found" OR "some capability never ran", and a client must not
        # be shown the first when it was the second.
        "scan_status": scan.scan_status,
        "consensus_status": scan.consensus_status,
        "summary": scan.summary or {},
        "diagnostics": scan.diagnostics,
        "error": scan.error,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
    }


def _finding_dict(finding: Any) -> dict[str, Any]:
    return {
        "module": finding.module,
        "target": finding.target,
        "severity": finding.severity,
        "title": finding.title,
        "detail": finding.detail,
        "cve_id": finding.cve_id,
        "cvss_score": finding.cvss_score,
        "asset_ip": finding.asset_ip,
        "asset_port": finding.asset_port,
        "evidence": finding.evidence,
    }


@router.get("/scans")
async def list_scans(
    limit: int = Query(50, ge=1, le=500),
    client_id: str = Depends(current_tenant),
    repository=Depends(session_factory),
):
    """This tenant's stored scans, newest first."""
    scans = repository.list_scans(client_id, limit=limit)
    return {"client_id": client_id, "count": len(scans), "scans": [_scan_dict(s) for s in scans]}


@router.get("/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    client_id: str = Depends(current_tenant),
    repository=Depends(session_factory),
):
    """One stored scan.

    A scan id belonging to another tenant is a 404, not a 403: from this
    tenant's side it does not exist, which is the same answer firestore.rules
    gave and it discloses nothing about another tenant's scan ids.
    """
    scan = repository.get_scan(client_id, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan_not_found")
    return _scan_dict(scan)


@router.get("/scans/{scan_id}/findings")
async def get_scan_findings(
    scan_id: str,
    severity: str | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
    client_id: str = Depends(current_tenant),
    repository=Depends(session_factory),
):
    """Findings for one stored scan, worst first."""
    if repository.get_scan(client_id, scan_id) is None:
        raise HTTPException(status_code=404, detail="scan_not_found")
    findings = repository.list_findings(client_id, scan_id=scan_id, severity=severity, limit=limit)
    return {
        "client_id": client_id,
        "scan_id": scan_id,
        "count": len(findings),
        "findings": [_finding_dict(f) for f in findings],
    }


@router.get("/findings")
async def list_findings(
    severity: str | None = Query(None),
    limit: int = Query(500, ge=1, le=5000),
    client_id: str = Depends(current_tenant),
    repository=Depends(session_factory),
):
    """Every stored finding for this tenant, worst first."""
    findings = repository.list_findings(client_id, severity=severity, limit=limit)
    return {
        "client_id": client_id,
        "count": len(findings),
        "findings": [_finding_dict(f) for f in findings],
    }


@router.get("/summary")
async def get_summary(
    scan_id: str | None = Query(None),
    client_id: str = Depends(current_tenant),
    repository=Depends(session_factory),
):
    """Severity totals for this tenant, or for one of its scans.

    Every band is present, zeros included: a missing key renders as "—" and a
    zero renders as 0, and those say different things to whoever reads them.
    """
    return {
        "client_id": client_id,
        "scan_id": scan_id,
        "severity_counts": repository.severity_counts(client_id, scan_id=scan_id),
    }
