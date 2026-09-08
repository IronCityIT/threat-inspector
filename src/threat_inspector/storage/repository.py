"""Tenant-scoped access to stored scan results.

Every public method takes a `client_id` and filters on it. There is no method
that reads across tenants, and no method that takes a scan's primary key without
also taking the tenant it must belong to.

That is the whole design. `firestore.rules` enforced tenant isolation
declaratively, outside the application, and fifteen emulator tests proved it. On
a relational store there is no such outer gate: isolation is whatever the
queries do. So it is made structural here — a caller cannot *forget* to scope,
because there is no unscoped entry point to call — and the same fifteen
invariants are re-expressed against this layer in tests/test_storage_repository.py.

The invariants that must hold, carried over verbatim from firestore.rules:

  * a tenant can read its own client record, its own scans, and its own findings
  * a tenant CANNOT read another tenant's client record, scan, or scan list
  * isolation holds in BOTH directions
  * a caller with no tenant reads nothing
  * naming another tenant's scan id does not reach that scan

Nothing here is wired into the workflows and nothing is deployed. See
docs/HANDOFF.md.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import case, delete, func, select
from sqlalchemy.orm import Session

from .schema import SEVERITIES, Client, Finding, Scan, utcnow


class TenantScopeError(ValueError):
    """Raised when a call would act outside the tenant it was given.

    An error, never a silent empty result. A cross-tenant attempt is a bug or an
    attack, and returning [] for it would hide both.
    """


def _require_client_id(client_id: str) -> str:
    """A tenant is mandatory, and an empty string is not a tenant.

    Guarded explicitly because `WHERE client_id = ''` is a perfectly valid query
    that quietly returns nothing — which reads as "this tenant has no data"
    rather than "no tenant was supplied".
    """
    cleaned = (client_id or "").strip()
    if not cleaned:
        raise TenantScopeError("a client_id is required; refusing to run an unscoped query")
    return cleaned


class ScanRepository:
    """Reads and writes scan results for exactly one tenant per call."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def commit(self) -> None:
        """Commit the work done through this repository.

        Exists so callers do not reach past the repository into its session:
        the point of this class is that every path to the data is scoped, and a
        caller holding the raw session can write whatever it likes.
        """
        self._session.commit()

    # -- writes ----------------------------------------------------------

    def upsert_client(self, client_id: str, client_name: str | None = None) -> Client:
        """Create or update a tenant record."""
        client_id = _require_client_id(client_id)
        client = self._session.get(Client, client_id)
        if client is None:
            client = Client(client_id=client_id, client_name=client_name)
            self._session.add(client)
        elif client_name:
            client.client_name = client_name
            client.updated_at = utcnow()
        self._session.flush()
        return client

    def store_scan(self, payload: dict[str, Any]) -> Scan:
        """Store a scan record built by tools/build_store_payload.py.

        Accepts the payload shape the pipeline already produces, so the store
        step can be repointed without reshaping what it sends.

        Status is MONOTONIC, exactly as storeScanResults made it: a scan that has
        already stored findings is never downgraded to "failed". The workflows
        report a failure whenever ANY job in the run failed, which includes the
        case where the scan itself succeeded and only the downstream analysis
        broke. That run has already written real findings, and clobbering them
        would lose client data. The failure is still recorded, as a non-fatal
        error on the record.
        """
        client_id = _require_client_id(str(payload.get("client_id") or ""))
        scan_id = str(payload.get("scan_id") or "").strip()
        if not scan_id:
            raise ValueError("scan_id is required")

        self.upsert_client(client_id, payload.get("client_name"))

        scan = self._session.scalar(
            select(Scan).where(Scan.client_id == client_id, Scan.scan_id == scan_id)
        )
        incoming_status = str(payload.get("status") or "completed")

        if scan is not None and incoming_status == "failed" and scan.status == "completed":
            # Already completed: record the failure without touching findings.
            scan.error = payload.get("error") or {"message": "a stage of this run failed"}
            scan.updated_at = utcnow()
            self._session.flush()
            return scan

        if scan is None:
            scan = Scan(client_id=client_id, scan_id=scan_id)
            self._session.add(scan)

        scan.scan_type = str(payload.get("scan_type") or "unknown")
        scan.target = payload.get("target")
        scan.status = incoming_status
        scan.scan_status = payload.get("scan_status")
        consensus = payload.get("consensus") or {}
        scan.consensus_status = consensus.get("status") if isinstance(consensus, dict) else None
        scan.summary = payload.get("summary") or {}
        scan.diagnostics = payload.get("diagnostics")
        scan.error = payload.get("error")
        scan.updated_at = utcnow()
        self._session.flush()

        self._replace_findings(scan, payload.get("findings") or [])
        return scan

    def _replace_findings(self, scan: Scan, findings: list[dict[str, Any]]) -> None:
        """Re-storing a scan replaces its findings rather than appending.

        A retried run must not double every finding, which is what appending
        would do and what a client would read as the estate getting twice as bad.
        """
        self._session.execute(delete(Finding).where(Finding.scan_pk == scan.id))
        for raw in findings:
            if not isinstance(raw, dict):
                continue
            severity = str(raw.get("severity") or "info").lower().strip()
            if severity not in SEVERITIES:
                # Store it rather than drop it, at the band that overstates
                # nothing. A finding with an unrecognised severity is still a
                # finding, and dropping it would lose client data over a label.
                severity = "info"
            evidence = raw.get("evidence") if isinstance(raw.get("evidence"), dict) else None
            # Scan modules record a CVE in evidence; ingested exports carry it as
            # a top-level field. Promote either into the indexed column, because
            # "which of my hosts has this CVE" is the query an analyst runs.
            cve_id = raw.get("cve_id") or (evidence or {}).get("cve")
            self._session.add(
                Finding(
                    scan_pk=scan.id,
                    client_id=scan.client_id,
                    module=raw.get("module"),
                    target=raw.get("target"),
                    severity=severity,
                    title=str(raw.get("title") or "(untitled finding)"),
                    detail=raw.get("detail"),
                    cve_id=str(cve_id) if cve_id else None,
                    cvss_score=_as_float(raw.get("cvss_score") or (evidence or {}).get("cvss")),
                    asset_ip=raw.get("asset_ip"),
                    asset_port=_as_int(raw.get("asset_port") or (evidence or {}).get("port")),
                    evidence=evidence,
                )
            )
        self._session.flush()

    # -- reads -----------------------------------------------------------

    def get_client(self, client_id: str) -> Client | None:
        return self._session.get(Client, _require_client_id(client_id))

    def list_scans(self, client_id: str, limit: int = 50) -> list[Scan]:
        """Most recent scans for one tenant, newest first."""
        client_id = _require_client_id(client_id)
        return list(
            self._session.scalars(
                select(Scan)
                .where(Scan.client_id == client_id)
                .order_by(Scan.created_at.desc(), Scan.id.desc())
                .limit(limit)
            )
        )

    def get_scan(self, client_id: str, scan_id: str) -> Scan | None:
        """One scan, and only if it belongs to this tenant.

        Naming another tenant's scan id returns None. It does NOT return that
        scan, and it does not raise something a caller might treat as
        "exists but forbidden" — from this tenant's side the scan simply is not
        there, which is the same answer firestore.rules gave.
        """
        client_id = _require_client_id(client_id)
        return self._session.scalar(
            select(Scan).where(Scan.client_id == client_id, Scan.scan_id == scan_id)
        )

    def list_findings(
        self,
        client_id: str,
        scan_id: str | None = None,
        severity: str | None = None,
        limit: int | None = None,
    ) -> list[Finding]:
        """Findings for one tenant, worst first.

        Every branch filters on client_id, including when a scan_id is given —
        the scan lookup is itself tenant-scoped, so a scan id belonging to
        another tenant resolves to nothing rather than to their findings.
        """
        client_id = _require_client_id(client_id)
        stmt = select(Finding).where(Finding.client_id == client_id)

        if scan_id is not None:
            scan = self.get_scan(client_id, scan_id)
            if scan is None:
                return []
            stmt = stmt.where(Finding.scan_pk == scan.id)

        if severity is not None:
            stmt = stmt.where(Finding.severity == severity.lower().strip())

        # Worst first, by the product's own ordering rather than alphabetically —
        # "critical" sorts after "high" as a string.
        ordering = _severity_ordering()
        stmt = stmt.order_by(ordering, Finding.id)
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self._session.scalars(stmt))

    def severity_counts(self, client_id: str, scan_id: str | None = None) -> dict[str, int]:
        """Severity totals for one tenant. Every band present, zeros included.

        A missing key and a zero are different things to a caller rendering a
        summary, and the absent key is the one that turns into "—" instead of 0.
        """
        client_id = _require_client_id(client_id)
        stmt = (
            select(Finding.severity, func.count(Finding.id))
            .where(Finding.client_id == client_id)
            .group_by(Finding.severity)
        )
        if scan_id is not None:
            scan = self.get_scan(client_id, scan_id)
            if scan is None:
                return dict.fromkeys(SEVERITIES, 0)
            stmt = stmt.where(Finding.scan_pk == scan.id)

        counts = dict.fromkeys(SEVERITIES, 0)
        for severity, count in self._session.execute(stmt):
            if severity in counts:
                counts[severity] = int(count)
        return counts

    def delete_scan(self, client_id: str, scan_id: str) -> bool:
        """Delete one scan and its findings. Returns whether anything was deleted.

        Tenant-scoped like every other method: naming another tenant's scan id
        deletes nothing and reports False.
        """
        scan = self.get_scan(client_id, scan_id)
        if scan is None:
            return False
        self._session.delete(scan)
        self._session.flush()
        return True


def _severity_ordering():
    """ORDER BY that puts critical first.

    A plain `ORDER BY severity` is alphabetical, which puts "critical" after
    "high" and "info" second — the exact opposite of useful on the page a client
    reads first. CASE is portable across SQLite and MariaDB alike.
    """
    return case(
        {name: index for index, name in enumerate(SEVERITIES)},
        value=Finding.severity,
        else_=len(SEVERITIES),
    )


def _as_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None and value != "" else None
    except (TypeError, ValueError):
        return None


def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None and value != "" else None
    except (TypeError, ValueError):
        return None
