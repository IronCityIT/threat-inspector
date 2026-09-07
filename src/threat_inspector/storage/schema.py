"""Relational schema for scan results, targeting MariaDB.

Replaces the Firestore document at `clients/{client_id}/scans/{scan_id}`.

Why relational is a real gain here, not a lateral move
------------------------------------------------------
The Firestore record held every finding inside ONE document, and Firestore
rejects a document over 1 MB. Over roughly 2,000 findings the write failed
outright and the client received *nothing* rather than a truncated report. The
fix at the time was to pack the record to an 800 KB budget, most-severe-first,
declaring the truncation — correct, but still lossy by construction.

Findings are rows here. That entire class of data loss does not exist.

Tenancy
-------
The tenant key is `client_id`: the lowercase-hyphen slug the whole pipeline
already derives from `client_name` — `toClientId()` in functions/index.js,
`resolveClientId()` in functions/exchange.js, and the shell derivation in
_consensus-store.yml all produce it identically.

This is a deliberate departure from src/threat_inspector/models/__init__.py,
which keys tenancy on an autoincrement integer `clients.id`. That mismatch is
recorded in docs/HANDOFF.md §4.1 as something that must be resolved before any
migration, and it is resolved *here*, in favour of the slug: the slug is what
every existing stored record, workflow and token claim already carries, so an
integer key would have to be invented and mapped, and a mapping that exists in
only one place is a tenancy bug waiting to happen.

`findings.client_id` is denormalised on purpose. It is redundant against
`findings.scan_id -> scans.client_id`, and it is what lets every finding query
filter on the tenant directly rather than depending on a join being written
correctly at each call site. Tenant isolation should not rest on remembering to
join. A composite foreign key ties it back to its scan's tenant so the two can
never disagree.

MariaDB specifics
-----------------
* Every String has an explicit length. MariaDB cannot index a VARCHAR without
  one, and this is the most common way a schema that works on SQLite fails on
  MySQL/MariaDB. `tests/test_storage_repository.py` compiles the DDL against
  the MySQL dialect precisely to catch it.
* utf8mb4 / InnoDB are set per table. Scan output contains arbitrary bytes from
  a client's estate; utf8 (3-byte) would reject anything outside the BMP.
* Indexed VARCHAR columns are kept at 255 or below: utf8mb4 at 255 is 1020
  bytes, comfortably inside InnoDB's 3072-byte index key limit on DYNAMIC rows.
* Timestamps are stored as timezone-aware UTC. MariaDB DATETIME does not carry
  a zone, so writing anything else loses the offset silently.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# Applied to every table. InnoDB for foreign keys and transactions; utf8mb4
# because findings carry whatever a client's estate emitted.
_TABLE_ARGS = {"mysql_engine": "InnoDB", "mysql_charset": "utf8mb4"}

# The finding severities the product uses, worst first. Constrained in the
# database as well as in code: a severity outside this set silently breaks
# every summary count that groups by it.
SEVERITIES = ("critical", "high", "medium", "low", "info")

# Run-health values cli.py emits. Kept unconstrained in the database on purpose
# — a new status value must not make a scan unstorable, which would lose the
# findings along with it.
SCAN_STATUSES = ("ok", "partial", "degraded", "failed", "dry_run")


def utcnow() -> dt.datetime:
    """Timezone-aware UTC. Never datetime.utcnow(), which returns naive."""
    return dt.datetime.now(dt.timezone.utc)


class Base(DeclarativeBase):
    """Declarative base for the self-hosted store.

    Deliberately separate from models/__init__.py's Base: that schema describes
    an asset/engagement inventory (clients, domains, projects, uploaded files)
    and this one describes stored scan results. Sharing a MetaData would couple
    the migration of one to the other for no benefit.
    """


metadata = Base.metadata


class Client(Base):
    """A tenant. The slug is the primary key, not a surrogate integer."""

    __tablename__ = "ti_clients"
    __table_args__ = _TABLE_ARGS

    client_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Display name as the caller supplied it; the slug is derived from it but is
    # not reversible, so the original has to be kept to render a report header.
    client_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    scans: Mapped[list[Scan]] = relationship(back_populates="client", cascade="all, delete-orphan")


class Scan(Base):
    """One scan run for one tenant.

    `(client_id, scan_id)` is unique rather than `scan_id` alone: scan ids are
    caller-supplied, and two tenants choosing the same one must not collide —
    still less overwrite each other.
    """

    __tablename__ = "ti_scans"
    __table_args__ = (
        UniqueConstraint("client_id", "scan_id", name="uq_ti_scans_client_scan"),
        # Supports the dashboard's "latest scans for this tenant" read, which is
        # the query the product makes most.
        Index("ix_ti_scans_client_created", "client_id", "created_at"),
        # Referenced by ti_findings' composite FK, which is what stops a finding
        # from being attached to a scan belonging to a different tenant.
        UniqueConstraint("id", "client_id", name="uq_ti_scans_id_client"),
        _TABLE_ARGS,
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    client_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("ti_clients.client_id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str] = mapped_column(String(128), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Whether the RUN completed. Monotonic: a scan that has stored findings is
    # never downgraded to "failed" — see ScanRepository.store_scan.
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    # The scan's own health, which is a different question. An empty findings
    # list means "nothing found" OR "every capability failed", and a client must
    # never be shown the first when it was the second.
    scan_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    consensus_status: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Severity totals, kept as written rather than recomputed, so a truncated or
    # partial store still reports what the scan actually found.
    summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # modules_run, module_errors, rejected_targets, timings, skipped capabilities.
    diagnostics: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Present only on failure records; lets a dashboard render "scan failed" with
    # a reason instead of leaving the scan pending forever.
    error: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    client: Mapped[Client] = relationship(back_populates="scans")
    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", passive_deletes=True
    )


class Finding(Base):
    """One finding. A row, not a field inside a document.

    The composite foreign key `(scan_pk, client_id) -> ti_scans(id, client_id)`
    is the point of this table's design: the database itself refuses a finding
    whose tenant does not match its scan's tenant. Denormalising client_id makes
    tenant-scoped queries direct; the composite key makes the denormalised copy
    impossible to get wrong.
    """

    __tablename__ = "ti_findings"
    __table_args__ = (
        ForeignKeyConstraint(
            ["scan_pk", "client_id"],
            ["ti_scans.id", "ti_scans.client_id"],
            ondelete="CASCADE",
            name="fk_ti_findings_scan_tenant",
        ),
        Index("ix_ti_findings_client_scan", "client_id", "scan_pk"),
        Index("ix_ti_findings_client_severity", "client_id", "severity"),
        CheckConstraint(
            "severity IN ('critical','high','medium','low','info')",
            name="ck_ti_findings_severity",
        ),
        _TABLE_ARGS,
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_pk: Mapped[int] = mapped_column(Integer, nullable=False)
    client_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Iron City module id — never an underlying scanner's name. The white-label
    # rule applies to anything a client can see, and this column is rendered.
    module: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    # Titles are Text, not an indexed VARCHAR: a scanner plugin name can be long,
    # and truncating what a client is shown to fit an index would be the wrong
    # trade.
    title: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Correlation identifiers, indexed lightly — these are what an analyst
    # actually searches on.
    cve_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    asset_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    asset_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Whatever the module recorded. Deliberately schemaless: evidence shape is
    # per-module and pinning it here would mean a migration every time a module
    # learns to record one more thing.
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="findings")
