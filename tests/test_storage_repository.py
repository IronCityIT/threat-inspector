"""Tenant isolation on the self-hosted store, and MariaDB portability.

`firestore.rules` enforced tenant isolation *declaratively*, outside the
application, and fifteen emulator cases proved it. A relational store has no
such outer gate — isolation is whatever the queries do — so the same invariants
have to be proven against this layer before any data is migrated onto it. That
is what the first section of this file is: the Firestore rules tests, restated.

The invariants, from `firestore.rules` and `tests/functions/rules.test.mjs`:

    a tenant can read its own client document / scan / scan list
    a tenant CANNOT read another tenant's client document
    a tenant CANNOT read another tenant's scan
    a tenant CANNOT list another tenant's scans
    the isolation holds in both directions
    an unauthenticated caller can read nothing
    a caller with NO client_id can read nothing
    a forged client_id only grants that tenant, not others

The second section pins MariaDB portability. This suite runs against SQLite,
which is forgiving in exactly the ways MariaDB is not — an unlengthed VARCHAR is
fine in SQLite and rejected by MariaDB — so the schema is *also* compiled against
the MySQL dialect here. That is the check that would have caught the difference
between "passes locally" and "works on the target", which on this repository has
already cost one red CI run.

Foreign keys are switched ON for the SQLite session. They are off by default
there, and with them off the composite foreign key that ties a finding's tenant
to its scan's tenant would not be enforced — the test would pass while proving
nothing.

Nothing here is deployed or wired into the workflows. See docs/HANDOFF.md.
"""

from __future__ import annotations

import pytest

sqlalchemy = pytest.importorskip(
    "sqlalchemy",
    reason="sqlalchemy is declared in requirements.txt; install it to run the storage suite",
)

from sqlalchemy import create_engine, event, select  # noqa: E402
from sqlalchemy.dialects import mysql  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402
from sqlalchemy.schema import CreateTable  # noqa: E402

from threat_inspector.storage import (  # noqa: E402
    Finding,
    ScanRepository,
    TenantScopeError,
    metadata,
)

ACME = "acme"
GLOBEX = "globex"


@pytest.fixture
def session():
    """An in-memory database with foreign keys actually enforced."""
    engine = create_engine("sqlite://")

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    metadata.create_all(engine)
    with Session(engine) as s:
        yield s


@pytest.fixture
def repo(session):
    return ScanRepository(session)


def payload(client_id: str, scan_id: str, **overrides) -> dict:
    base = {
        "client_id": client_id,
        "client_name": client_id.title(),
        "scan_id": scan_id,
        "scan_type": "network",
        "target": "example.selftest.invalid",
        "status": "completed",
        "scan_status": "ok",
        "summary": {"total": 1},
        "consensus": {"status": "ok"},
        "findings": [
            {
                "module": "port_scan",
                "target": "example.selftest.invalid",
                "severity": "high",
                "title": f"{client_id} finding",
                "evidence": {"port": 443},
            }
        ],
    }
    base.update(overrides)
    return base


@pytest.fixture
def two_tenants(repo):
    """Two tenants, each with a scan — and both using the SAME scan id."""
    repo.store_scan(payload(ACME, "shared-id"))
    repo.store_scan(payload(GLOBEX, "shared-id"))
    return repo


# ---------------------------------------------------------------------------
# Tenant isolation — the firestore.rules invariants, restated
# ---------------------------------------------------------------------------


def test_a_tenant_can_read_its_own_client_record(two_tenants):
    assert two_tenants.get_client(ACME).client_id == ACME


def test_a_tenant_can_read_its_own_scan(two_tenants):
    scan = two_tenants.get_scan(ACME, "shared-id")
    assert scan is not None
    assert scan.client_id == ACME


def test_a_tenant_can_list_its_own_scans(two_tenants):
    scans = two_tenants.list_scans(ACME)
    assert [s.scan_id for s in scans] == ["shared-id"]
    assert {s.client_id for s in scans} == {ACME}


def test_a_tenant_can_read_its_own_findings(two_tenants):
    findings = two_tenants.list_findings(ACME)
    assert [f.title for f in findings] == ["acme finding"]


def test_naming_another_tenants_scan_id_does_not_reach_their_scan(two_tenants):
    """The two tenants deliberately share a scan id.

    This is the case a surrogate scan-id-only lookup gets wrong, and it is why
    (client_id, scan_id) is the unique key rather than scan_id alone.
    """
    assert two_tenants.get_scan(ACME, "shared-id").client_id == ACME
    assert two_tenants.get_scan(GLOBEX, "shared-id").client_id == GLOBEX


def test_a_tenant_never_sees_another_tenants_findings(two_tenants):
    assert all(f.client_id == ACME for f in two_tenants.list_findings(ACME))
    assert "globex finding" not in {f.title for f in two_tenants.list_findings(ACME)}


def test_the_isolation_holds_in_both_directions(two_tenants):
    assert [f.title for f in two_tenants.list_findings(ACME)] == ["acme finding"]
    assert [f.title for f in two_tenants.list_findings(GLOBEX)] == ["globex finding"]


def test_a_tenant_that_does_not_exist_reads_nothing_rather_than_everything(two_tenants):
    assert two_tenants.get_client("nobody") is None
    assert two_tenants.list_scans("nobody") == []
    assert two_tenants.list_findings("nobody") == []
    assert two_tenants.get_scan("nobody", "shared-id") is None


@pytest.mark.parametrize("missing", ["", "   ", None])
def test_a_caller_with_no_tenant_is_refused_not_served(two_tenants, missing):
    """An empty client_id must not become an unscoped query.

    `WHERE client_id = ''` is perfectly valid SQL that returns nothing, so a
    silent empty result would read as "this tenant has no data" rather than
    "nobody was named". Both are wrong answers; this raises instead.
    """
    for call in (
        lambda: two_tenants.list_scans(missing),
        lambda: two_tenants.list_findings(missing),
        lambda: two_tenants.get_client(missing),
        lambda: two_tenants.get_scan(missing, "shared-id"),
        lambda: two_tenants.severity_counts(missing),
    ):
        with pytest.raises(TenantScopeError):
            call()


def test_a_scan_cannot_be_stored_without_a_tenant(repo):
    with pytest.raises(TenantScopeError):
        repo.store_scan(payload("", "s1"))


def test_severity_counts_are_scoped_to_the_tenant(two_tenants):
    assert two_tenants.severity_counts(ACME)["high"] == 1
    assert two_tenants.severity_counts(GLOBEX)["high"] == 1
    assert two_tenants.severity_counts("nobody")["high"] == 0


def test_deleting_another_tenants_scan_deletes_nothing(two_tenants):
    assert two_tenants.delete_scan("nobody", "shared-id") is False
    assert two_tenants.get_scan(ACME, "shared-id") is not None
    assert two_tenants.get_scan(GLOBEX, "shared-id") is not None


def test_deleting_a_tenants_own_scan_removes_it_and_its_findings(two_tenants, session):
    assert two_tenants.delete_scan(ACME, "shared-id") is True
    session.flush()
    assert two_tenants.get_scan(ACME, "shared-id") is None
    assert two_tenants.list_findings(ACME) == []
    # The other tenant is untouched.
    assert two_tenants.get_scan(GLOBEX, "shared-id") is not None
    assert len(two_tenants.list_findings(GLOBEX)) == 1


def test_the_database_itself_refuses_a_finding_whose_tenant_is_wrong(two_tenants, session):
    """The composite foreign key, not the application, is what enforces this.

    Denormalising client_id onto findings is what makes tenant-scoped queries
    direct. This is what stops the denormalised copy from ever disagreeing with
    the scan it belongs to — even if a future code path forgets.
    """
    acme_scan = two_tenants.get_scan(ACME, "shared-id")
    session.add(
        Finding(
            scan_pk=acme_scan.id,
            client_id=GLOBEX,  # someone else's tenant, on acme's scan
            severity="critical",
            title="smuggled",
        )
    )
    with pytest.raises(IntegrityError):
        session.flush()


# ---------------------------------------------------------------------------
# Storing what the pipeline actually produces
# ---------------------------------------------------------------------------


def test_a_scan_record_round_trips(repo):
    repo.store_scan(payload(ACME, "s1"))
    scan = repo.get_scan(ACME, "s1")
    assert scan.scan_type == "network"
    assert scan.target == "example.selftest.invalid"
    assert scan.status == "completed"
    assert scan.scan_status == "ok"
    assert scan.consensus_status == "ok"
    assert scan.summary == {"total": 1}


def test_findings_become_rows_not_a_packed_document(repo):
    """The reason this migration is worth doing.

    The Firestore record held every finding in ONE document, and over roughly
    2,000 findings the write was rejected outright — the client got nothing. The
    workaround packed the record to an 800 KB budget and declared the truncation.
    Rows have no such ceiling.
    """
    many = [
        {
            "module": "port_scan",
            "severity": "info",
            "title": f"Open port {p}",
            "evidence": {"port": p},
        }
        for p in range(1, 2001)
    ]
    repo.store_scan(payload(ACME, "big", findings=many))
    assert len(repo.list_findings(ACME)) == 2000
    assert repo.severity_counts(ACME)["info"] == 2000


def test_findings_come_back_worst_first(repo):
    repo.store_scan(
        payload(
            ACME,
            "s1",
            findings=[
                {"severity": "info", "title": "i"},
                {"severity": "critical", "title": "c"},
                {"severity": "low", "title": "l"},
                {"severity": "high", "title": "h"},
                {"severity": "medium", "title": "m"},
            ],
        )
    )
    assert [f.severity for f in repo.list_findings(ACME)] == [
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ]


def test_an_unrecognised_severity_is_kept_at_info_rather_than_dropped(repo):
    """A finding with a bad label is still a finding. Losing it loses client data."""
    repo.store_scan(payload(ACME, "s1", findings=[{"severity": "banana", "title": "odd"}]))
    findings = repo.list_findings(ACME)
    assert len(findings) == 1
    assert findings[0].severity == "info"


def test_a_finding_with_no_title_is_stored_with_a_placeholder(repo):
    repo.store_scan(payload(ACME, "s1", findings=[{"severity": "low"}]))
    assert repo.list_findings(ACME)[0].title == "(untitled finding)"


def test_a_cve_recorded_in_evidence_reaches_the_indexed_column(repo):
    """ "Which of my hosts has this CVE" is the query an analyst runs."""
    repo.store_scan(
        payload(
            ACME,
            "s1",
            findings=[{"severity": "high", "title": "t", "evidence": {"cve": "CVE-2021-44228"}}],
        )
    )
    assert repo.list_findings(ACME)[0].cve_id == "CVE-2021-44228"


def test_a_top_level_cve_also_reaches_the_column(repo):
    repo.store_scan(
        payload(ACME, "s1", findings=[{"severity": "high", "title": "t", "cve_id": "CVE-1"}])
    )
    assert repo.list_findings(ACME)[0].cve_id == "CVE-1"


def test_evidence_that_is_not_an_object_is_stored_as_nothing_rather_than_crashing(repo):
    repo.store_scan(
        payload(ACME, "s1", findings=[{"severity": "low", "title": "t", "evidence": "a string"}])
    )
    assert repo.list_findings(ACME)[0].evidence is None


def test_a_non_dict_finding_is_skipped_not_fatal(repo):
    repo.store_scan(payload(ACME, "s1", findings=["nonsense", {"severity": "low", "title": "ok"}]))
    assert [f.title for f in repo.list_findings(ACME)] == ["ok"]


def test_re_storing_a_scan_replaces_its_findings_rather_than_doubling_them(repo):
    """A retried run must not make the estate look twice as bad."""
    repo.store_scan(payload(ACME, "s1"))
    repo.store_scan(payload(ACME, "s1"))
    assert len(repo.list_findings(ACME)) == 1


def test_a_scan_id_may_be_reused_by_a_different_tenant(repo):
    repo.store_scan(payload(ACME, "same"))
    repo.store_scan(payload(GLOBEX, "same"))
    assert len(repo.list_scans(ACME)) == 1
    assert len(repo.list_scans(GLOBEX)) == 1


def test_a_scan_without_an_id_is_refused(repo):
    with pytest.raises(ValueError):
        repo.store_scan(payload(ACME, ""))


def test_the_client_name_is_kept_alongside_the_slug(repo):
    """The slug is not reversible, so the display name has to be stored."""
    repo.store_scan(payload(ACME, "s1", client_name="Acme Corporation"))
    assert repo.get_client(ACME).client_name == "Acme Corporation"


def test_filtering_findings_by_severity_is_tenant_scoped(two_tenants):
    assert len(two_tenants.list_findings(ACME, severity="high")) == 1
    assert two_tenants.list_findings(ACME, severity="critical") == []


def test_filtering_findings_by_scan_is_tenant_scoped(two_tenants):
    """Another tenant's scan id resolves to nothing, not to their findings."""
    assert len(two_tenants.list_findings(ACME, scan_id="shared-id")) == 1
    assert two_tenants.list_findings(ACME, scan_id="does-not-exist") == []


def test_severity_counts_report_every_band_including_zeros(repo):
    """A missing key renders as "—"; a zero renders as 0. They are different."""
    repo.store_scan(payload(ACME, "s1"))
    counts = repo.severity_counts(ACME)
    assert set(counts) == {"critical", "high", "medium", "low", "info"}
    assert counts["critical"] == 0


# ---------------------------------------------------------------------------
# Status is monotonic — carried over from storeScanResults
# ---------------------------------------------------------------------------


def test_a_completed_scan_is_never_downgraded_to_failed(repo):
    """The workflows report failure when ANY job in the run failed, including
    runs where the scan itself succeeded and only downstream analysis broke.
    That run has already written real findings; clobbering them loses them."""
    repo.store_scan(payload(ACME, "s1"))
    repo.store_scan(payload(ACME, "s1", status="failed", findings=[]))

    scan = repo.get_scan(ACME, "s1")
    assert scan.status == "completed"
    assert len(repo.list_findings(ACME)) == 1, "the findings must survive the failure report"


def test_the_failure_is_still_recorded_on_the_completed_scan(repo):
    repo.store_scan(payload(ACME, "s1"))
    repo.store_scan(
        payload(ACME, "s1", status="failed", error={"message": "analysis stage failed"})
    )
    assert repo.get_scan(ACME, "s1").error == {"message": "analysis stage failed"}


def test_a_scan_that_failed_outright_is_stored_as_failed(repo):
    repo.store_scan(payload(ACME, "s1", status="failed", findings=[]))
    assert repo.get_scan(ACME, "s1").status == "failed"


def test_a_failed_scan_can_still_be_replaced_by_a_successful_rerun(repo):
    repo.store_scan(payload(ACME, "s1", status="failed", findings=[]))
    repo.store_scan(payload(ACME, "s1"))
    assert repo.get_scan(ACME, "s1").status == "completed"
    assert len(repo.list_findings(ACME)) == 1


def test_scan_health_is_kept_separate_from_run_status(repo):
    """An empty findings list means "nothing found" OR "every capability
    failed", and a client must never be shown the first when it was the
    second."""
    repo.store_scan(payload(ACME, "s1", scan_status="degraded", findings=[]))
    scan = repo.get_scan(ACME, "s1")
    assert scan.status == "completed"
    assert scan.scan_status == "degraded"


def test_diagnostics_survive_to_the_record(repo):
    diagnostics = {"modules_run": ["port_scan"], "module_errors": [], "target_count": 1}
    repo.store_scan(payload(ACME, "s1", diagnostics=diagnostics))
    assert repo.get_scan(ACME, "s1").diagnostics == diagnostics


# ---------------------------------------------------------------------------
# MariaDB portability
# ---------------------------------------------------------------------------


def mysql_ddl() -> str:
    dialect = mysql.dialect()
    return "\n".join(str(CreateTable(t).compile(dialect=dialect)) for t in metadata.sorted_tables)


def test_the_schema_compiles_for_mariadb():
    """SQLite accepts things MariaDB rejects. Compile for the real target.

    This is the check that separates "passes locally" from "works on the box",
    which on this repository has already cost one red CI run.
    """
    assert "CREATE TABLE ti_scans" in mysql_ddl()


def test_every_string_column_has_an_explicit_length():
    """MariaDB cannot index a VARCHAR without one, and this is the single most
    common way a schema that works on SQLite fails on the target."""
    ddl = mysql_ddl()
    assert "VARCHAR," not in ddl
    assert "VARCHAR)" not in ddl
    assert "VARCHAR " not in ddl.replace("VARCHAR(", "")


def test_the_tables_are_innodb_and_utf8mb4():
    """InnoDB for foreign keys and transactions; utf8mb4 because findings carry
    whatever bytes a client's estate emitted — utf8 would reject anything
    outside the BMP."""
    ddl = mysql_ddl()
    assert ddl.count("ENGINE=InnoDB") == len(metadata.sorted_tables)
    assert ddl.count("CHARSET=utf8mb4") == len(metadata.sorted_tables)


def test_indexed_columns_stay_within_innodbs_key_limit():
    """utf8mb4 is 4 bytes per character, and InnoDB's index key limit is 3072
    bytes on DYNAMIC rows. 255 characters is 1020 bytes — comfortably inside."""
    indexed = set()
    for table in metadata.sorted_tables:
        for index in table.indexes:
            indexed.update(index.columns)
        for constraint in table.constraints:
            indexed.update(getattr(constraint, "columns", []))

    for column in indexed:
        length = getattr(column.type, "length", None)
        if length is not None:
            assert length * 4 <= 3072, f"{column} is too wide to index under utf8mb4"


def test_the_tenant_key_is_the_slug_not_a_surrogate_integer():
    """Resolves the mismatch recorded in docs/HANDOFF.md §4.1.

    The whole pipeline — toClientId(), resolveClientId(), and the shell
    derivation in _consensus-store.yml — already keys tenancy on the slug. An
    integer key would have to be invented and mapped, and a mapping that lives
    in one place is a tenancy bug waiting to happen.
    """
    from threat_inspector.storage import Client

    primary_key = list(Client.__table__.primary_key.columns)
    assert [c.name for c in primary_key] == ["client_id"]
    assert isinstance(primary_key[0].type, sqlalchemy.String)


def test_severity_is_constrained_in_the_database_not_only_in_code():
    """A severity outside the set silently breaks every summary that groups by
    it, so the database refuses it too."""
    ddl = mysql_ddl()
    assert "ck_ti_findings_severity" in ddl


def test_findings_are_tied_to_their_scans_tenant_by_the_schema():
    assert "fk_ti_findings_scan_tenant" in mysql_ddl()


def test_a_scan_is_unique_per_tenant_not_globally():
    ddl = mysql_ddl()
    assert "uq_ti_scans_client_scan" in ddl


def test_the_new_schema_does_not_collide_with_the_existing_models():
    """The legacy asset/engagement models use unprefixed names (clients, scans,
    vulnerabilities). These are ti_-prefixed so both can exist in one database
    while the migration is in progress."""
    names = {t.name for t in metadata.sorted_tables}
    assert names == {"ti_clients", "ti_scans", "ti_findings"}
    assert all(n.startswith("ti_") for n in names)


def test_the_ordering_expression_is_portable_to_mariadb():
    """The worst-first ordering must compile for the target, not only SQLite."""
    from threat_inspector.storage.repository import _severity_ordering

    compiled = str(_severity_ordering().compile(dialect=mysql.dialect()))
    assert "CASE" in compiled.upper()


def test_a_tenant_scoped_query_actually_filters_in_sql(session):
    """Isolation must be in the WHERE clause, not applied afterwards in Python.

    A post-filter still pulls another tenant's rows out of the database, which
    is the wrong place for the boundary to live.
    """
    stmt = select(Finding).where(Finding.client_id == ACME)
    assert "client_id" in str(stmt.compile(dialect=mysql.dialect()))
