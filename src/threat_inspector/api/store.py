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
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile

from threat_inspector.api.auth import current_tenant
from threat_inspector.parsers import SUPPORTED_FORMATS, parse_file

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


# Diagnostic keys whose VALUES name an underlying scanner rather than an Iron
# City capability. `modules_skipped` entries carry `missing: ["nuclei"]`, which
# is a tool identity and must not cross a client-facing boundary.
_TOOL_NAMING_KEYS = ("missing",)


def _safe_diagnostics(diagnostics: Any) -> Any:
    """Strip underlying scanner names out of the diagnostics a client is shown.

    The white-label rule covers anything a client can see, and this response is
    consumed by the client-facing dashboard. The COUNT of skipped capabilities
    is what a client needs — "2 checks did not run" — not which scanner was
    absent, which is an operational detail about our estate.

    Everything else is passed through: module ids, error counts, timings and
    rejected targets are Iron City identifiers and numbers.
    """
    if not isinstance(diagnostics, dict):
        return diagnostics

    cleaned = dict(diagnostics)
    skipped = cleaned.get("modules_skipped")
    if isinstance(skipped, list):
        cleaned["modules_skipped"] = [
            {k: v for k, v in entry.items() if k not in _TOOL_NAMING_KEYS}
            if isinstance(entry, dict)
            else entry
            for entry in skipped
        ]
    return cleaned


def _scan_dict(scan: Any) -> dict[str, Any]:
    """One scan, as a client-facing record.

    Diagnostics are sanitised on the way out — see _safe_diagnostics.
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
        "diagnostics": _safe_diagnostics(scan.diagnostics),
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


# The client-safe category for an uploaded export. The white-label rule means a
# stored finding must never carry the format's vendor name, so the scanner type
# is mapped here and the raw type is not stored at all.
_SOURCE_LABELS = {
    "qualys": "Vulnerability Assessment",
    "nessus": "Vulnerability Assessment",
    "zap": "Web Application Scan",
    "nmap": "Network Scan",
}


def _source_label(scanner_type: str) -> str:
    return _SOURCE_LABELS.get((scanner_type or "").lower(), "Security Assessment")


def _to_finding(vulnerability, source: str) -> dict[str, Any]:
    """One parsed vulnerability, in the shape ScanRepository stores.

    `module` is the neutral id `file_ingest` rather than the parser's name.
    The framework's own ingest modules are called nessus_ingest / zap_ingest /
    qualys_ingest — vendor names that travel on every finding they produce — and
    that is recorded in docs/HANDOFF.md as a decision for Bill. A new write path
    should not add a third convention or a fourth place the names appear, so the
    format is carried as a client-safe label in evidence instead.
    """
    return {
        "module": "file_ingest",
        "target": vulnerability.asset_url or vulnerability.asset_ip or vulnerability.asset_name,
        "severity": vulnerability.severity,
        "title": vulnerability.title,
        "detail": vulnerability.description,
        "cve_id": vulnerability.cve_id,
        "cvss_score": vulnerability.cvss_score,
        "asset_ip": vulnerability.asset_ip,
        "asset_port": vulnerability.asset_port,
        "evidence": {
            "source": source,
            "asset_name": vulnerability.asset_name,
            "asset_url": vulnerability.asset_url,
            "cwe_id": vulnerability.cwe_id,
            "solution": vulnerability.solution,
        },
    }


def _ingest_status(result) -> str:
    """How much of the upload was actually understood.

    Storing "ok" for a file the parser read and recognised nothing in is the
    failure this product keeps finding in its own ingestion: a client shown a
    clean report for a scan that was never really read.

    The parsers distinguish the two cases already. An ERROR means the file could
    not be read (rejected above). A WARNING with no findings means it was read
    and nothing in it was recognised — most often a column mismatch — and that
    is a degraded ingest, not a clean one.
    """
    if result.errors:
        return "partial"
    if not result.vulnerabilities:
        # Warnings tell us it was read but not understood; silence means the
        # file genuinely had nothing in it, which is a real and clean result.
        return "degraded" if result.warnings else "ok"
    return "partial" if result.warnings else "ok"


@router.post("/scans/{scan_id}/upload")
async def upload_scan(
    scan_id: str,
    file: UploadFile = File(...),
    scanner_type: str | None = Query(
        None, description="Scan format hint (auto-detected if omitted)"
    ),
    client_id: str = Depends(current_tenant),
    repository=Depends(session_factory),
):
    """Parse an uploaded scan export and PERSIST it for this tenant.

    The difference from `/api/v1/scans/upload` is the whole point: that one
    parses into a process-local dict that does not survive a restart and does
    not work behind a second replica. This one writes rows.

    A parse that produced nothing but errors is a 400, not a stored empty scan:
    a corrupt upload recorded as a clean result is the failure this product has
    repeatedly found in its own ingestion, and it must not be reintroduced at
    the API.
    """
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in SUPPORTED_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=f"unsupported_format: {suffix or '(none)'}",
        )

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await file.read())
        tmp_path = Path(tmp.name)

    try:
        result = parse_file(tmp_path, scanner_type)
    except ValueError as e:
        # The caller asserted a scanner_type that is unknown, or that cannot
        # read this file. That is a bad request and the reason is the caller's
        # own input, so it is safe and useful to say what was wrong.
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        # Anything else is ours. Report the type, not the message, which can
        # carry paths or file contents.
        raise HTTPException(status_code=400, detail=f"parse_failed: {type(e).__name__}") from e
    finally:
        tmp_path.unlink(missing_ok=True)

    if result.errors and not result.vulnerabilities:
        # The parser said why. Carrying it up is what stops a corrupt upload
        # from being stored as a successful, empty ingest.
        raise HTTPException(
            status_code=400, detail={"error": "parse_failed", "reasons": result.errors}
        )

    source = _source_label(result.scanner_type)
    scan_status = _ingest_status(result)
    payload = {
        "client_id": client_id,
        "scan_id": scan_id,
        "scan_type": "file_ingest",
        "target": file.filename,
        "status": "completed",
        "scan_status": scan_status,
        "summary": {"total": result.total_count, **result.severity_counts},
        "diagnostics": {
            "modules_run": ["file_ingest"],
            "source": source,
            "parser_errors": list(result.errors),
            "parser_warnings": list(result.warnings),
            "rows_recognised": result.total_count,
        },
        "findings": [_to_finding(v, source) for v in result.vulnerabilities],
    }

    scan = repository.store_scan(payload)
    repository.commit()

    return {
        "status": "stored",
        "client_id": client_id,
        "scan_id": scan.scan_id,
        "source": source,
        "findings": result.total_count,
        "scan_status": scan_status,
        "severity_breakdown": result.severity_counts,
        "warnings": list(result.warnings),
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
