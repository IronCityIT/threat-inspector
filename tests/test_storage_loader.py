"""Writing a scan into the self-hosted store, and refusing to when it cannot.

This is the self-hosted counterpart of the `POST to storeScanResults` step, and
it inherits that step's hardest-won lesson. `_consensus-store.yml` once read:

    if [ -z "$STORE_URL" ]; then
      echo "::warning::STORE_SCAN_RESULTS_URL not set — skipping store"
      exit 0
    fi

`STORE_SCAN_RESULTS_URL` had never been set, so **every scan the product had
ever run discarded its findings at the last step and reported success.** A green
run said nothing about whether the client's results existed.

So the tests that matter most here are the refusals. Nothing exits 0 unless a
row was actually written, and each way of failing has its own exit code so a
workflow can tell them apart rather than parsing a message.

These run against SQLite. No MariaDB has ever been connected to from this
repository and no credential exists (docs/HANDOFF.md §13.2).
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("sqlalchemy", reason="sqlalchemy is required for the storage suite")
pytest.importorskip("alembic", reason="alembic is declared in requirements.txt")

from alembic import command  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

from tests.test_storage_migrations import alembic_config  # noqa: E402
from threat_inspector.storage import loader  # noqa: E402

PAYLOAD = {
    "scan_type": "modular_scan",
    "scan_id": "acme-1757280000",
    "client_id": "acme",
    "client_name": "Acme Corporation",
    "target": "example.selftest.invalid",
    "status": "completed",
    "scan_status": "degraded",
    "summary": {"total": 2, "critical": 1},
    "consensus": {"status": "success"},
    "diagnostics": {
        "modules_run": ["tls_cert_check", "header_security_check"],
        "modules_skipped": [{"module": "web_vuln_scan", "missing": ["nuclei"]}],
    },
    "findings": [
        {
            "module": "tls_cert_check",
            "target": "example.selftest.invalid",
            "severity": "critical",
            "title": "Certificate failed validation",
            "evidence": {"verification_error": "certificate has expired"},
        },
        {
            "module": "header_security_check",
            "severity": "medium",
            "title": "Missing security header: HSTS",
            "evidence": {"header": "strict-transport-security"},
        },
    ],
}


@pytest.fixture
def payload_file(tmp_path):
    def write(payload, name="payload.json"):
        path = tmp_path / name
        path.write_text(
            json.dumps(payload) if not isinstance(payload, str) else payload,
            encoding="utf-8",
        )
        return path

    return write


@pytest.fixture
def url(tmp_path, monkeypatch):
    """An unmigrated database, with DATABASE_URL pointed at it."""
    dsn = f"sqlite:///{tmp_path / 'store.db'}"
    monkeypatch.setenv("DATABASE_URL", dsn)
    return dsn


@pytest.fixture
def migrated_url(url):
    command.upgrade(alembic_config(url), "head")
    return url


def rows(dsn: str, sql: str):
    with create_engine(dsn).connect() as connection:
        return list(connection.execute(text(sql)))


# ---------------------------------------------------------------------------
# The happy path — and it must genuinely write
# ---------------------------------------------------------------------------


def test_a_payload_is_written_to_the_database(migrated_url, payload_file, capsys):
    assert loader.main(["--payload", str(payload_file(PAYLOAD))]) == loader.EXIT_OK

    assert rows(migrated_url, "SELECT client_id, client_name FROM ti_clients") == [
        ("acme", "Acme Corporation")
    ]
    assert rows(migrated_url, "SELECT COUNT(*) FROM ti_findings") == [(2,)]


def test_the_result_is_reported_as_json_on_stdout(migrated_url, payload_file, capsys):
    """A workflow step reads this; it must be machine-readable, not prose."""
    loader.main(["--payload", str(payload_file(PAYLOAD))])
    reported = json.loads(capsys.readouterr().out)
    assert reported == {
        "status": "stored",
        "client_id": "acme",
        "scan_id": "acme-1757280000",
        "findings": 2,
    }


def test_the_findings_count_reported_is_the_count_actually_stored(
    migrated_url, payload_file, capsys
):
    """Reporting the payload's length rather than the stored rows would let a
    partial write be announced as a complete one."""
    loader.main(["--payload", str(payload_file(PAYLOAD))])
    reported = json.loads(capsys.readouterr().out)["findings"]
    assert [(reported,)] == rows(migrated_url, "SELECT COUNT(*) FROM ti_findings")


def test_the_scans_own_health_survives_the_load(migrated_url, payload_file):
    """`scan_status` is what distinguishes "nothing found" from "nothing ran"."""
    loader.main(["--payload", str(payload_file(PAYLOAD))])
    assert rows(migrated_url, "SELECT status, scan_status FROM ti_scans") == [
        ("completed", "degraded")
    ]


def test_diagnostics_survive_the_load(migrated_url, payload_file):
    """Including which capabilities never ran — otherwise the record cannot
    distinguish "we looked and found nothing" from "we never looked"."""
    loader.main(["--payload", str(payload_file(PAYLOAD))])
    [(raw,)] = rows(migrated_url, "SELECT diagnostics FROM ti_scans")
    diagnostics = json.loads(raw) if isinstance(raw, str) else raw
    assert diagnostics["modules_skipped"][0]["module"] == "web_vuln_scan"


def test_loading_the_same_payload_twice_does_not_double_the_findings(migrated_url, payload_file):
    """A retried workflow run must not make the estate look twice as bad."""
    path = payload_file(PAYLOAD)
    assert loader.main(["--payload", str(path)]) == loader.EXIT_OK
    assert loader.main(["--payload", str(path)]) == loader.EXIT_OK
    assert rows(migrated_url, "SELECT COUNT(*) FROM ti_findings") == [(2,)]


def test_two_tenants_do_not_collide_on_a_shared_scan_id(migrated_url, payload_file):
    loader.main(["--payload", str(payload_file(PAYLOAD, "a.json"))])
    other = {**PAYLOAD, "client_id": "globex", "client_name": "Globex"}
    loader.main(["--payload", str(payload_file(other, "b.json"))])

    assert sorted(rows(migrated_url, "SELECT client_id FROM ti_scans")) == [
        ("acme",),
        ("globex",),
    ]
    assert rows(migrated_url, "SELECT COUNT(*) FROM ti_findings") == [(4,)]


def test_a_scan_with_no_findings_is_still_recorded(migrated_url, payload_file):
    """A clean scan is a result. Storing nothing at all would leave it looking
    like the scan never happened."""
    empty = {**PAYLOAD, "findings": []}
    assert loader.main(["--payload", str(payload_file(empty))]) == loader.EXIT_OK
    assert rows(migrated_url, "SELECT COUNT(*) FROM ti_scans") == [(1,)]


# ---------------------------------------------------------------------------
# The refusals — the part that matters
# ---------------------------------------------------------------------------


def test_an_unset_database_url_is_refused_not_skipped(migrated_url, payload_file, monkeypatch):
    """The exact shape of the bug this replaces: a missing destination once
    produced a warning and exit 0, and the findings went nowhere."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert loader.main(["--payload", str(payload_file(PAYLOAD))]) == loader.EXIT_CONFIG


def test_an_empty_database_url_is_also_refused(migrated_url, payload_file, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "   ")
    assert loader.main(["--payload", str(payload_file(PAYLOAD))]) == loader.EXIT_CONFIG


def test_an_unmigrated_database_is_refused(url, payload_file):
    """Creating the tables on the fly would work, and would also mean nobody
    ever noticed the migration had not been applied."""
    assert loader.main(["--payload", str(payload_file(PAYLOAD))]) == loader.EXIT_SCHEMA


def test_a_database_behind_the_code_is_refused(migrated_url, payload_file):
    """A stale schema accepts most of a payload and silently drops whatever the
    newest revision added — the same quiet data loss this product keeps finding
    in its own scanners."""
    with create_engine(migrated_url).begin() as connection:
        connection.execute(text("UPDATE alembic_version SET version_num = 'an_older_revision'"))

    assert loader.main(["--payload", str(payload_file(PAYLOAD))]) == loader.EXIT_SCHEMA


def test_nothing_is_written_when_the_schema_is_refused(url, payload_file):
    assert loader.main(["--payload", str(payload_file(PAYLOAD))]) == loader.EXIT_SCHEMA
    with create_engine(url).connect() as connection:
        tables = connection.exec_driver_sql(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    assert not any(name.startswith("ti_") for (name,) in tables)


def test_a_missing_payload_file_is_refused(migrated_url, tmp_path):
    assert loader.main(["--payload", str(tmp_path / "nope.json")]) == loader.EXIT_CONFIG


def test_malformed_json_is_refused(migrated_url, payload_file):
    assert loader.main(["--payload", str(payload_file("not json at all"))]) == loader.EXIT_CONFIG


def test_a_payload_that_is_not_an_object_is_refused(migrated_url, payload_file):
    assert loader.main(["--payload", str(payload_file("[1, 2, 3]"))]) == loader.EXIT_CONFIG


@pytest.mark.parametrize("missing", ["client_id", "scan_id"])
def test_a_payload_without_a_tenant_or_a_scan_id_is_refused(migrated_url, payload_file, missing):
    incomplete = {k: v for k, v in PAYLOAD.items() if k != missing}
    assert loader.main(["--payload", str(payload_file(incomplete))]) == loader.EXIT_CONFIG


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_tenant_is_refused(migrated_url, payload_file, blank):
    assert (
        loader.main(["--payload", str(payload_file({**PAYLOAD, "client_id": blank}))])
        == loader.EXIT_CONFIG
    )


def test_the_payload_is_checked_before_a_connection_is_opened(url, payload_file):
    """An invalid payload should be a config error, not a schema error — the
    database is never reached, so it cannot be blamed."""
    assert loader.main(["--payload", str(payload_file({"client_id": "acme"}))]) == (
        loader.EXIT_CONFIG
    )


def test_a_write_failure_does_not_leak_the_connection_string(
    migrated_url, payload_file, monkeypatch, caplog
):
    """A SQLAlchemy error message can carry the DSN, and the DSN carries the
    password. Only the exception type is logged."""
    from sqlalchemy.exc import OperationalError

    def boom(*args, **kwargs):
        raise OperationalError("SELECT 1", {}, Exception("mysql://user:hunter2@host/db"))

    monkeypatch.setattr("threat_inspector.storage.repository.ScanRepository.store_scan", boom)

    with caplog.at_level("ERROR"):
        assert loader.main(["--payload", str(payload_file(PAYLOAD))]) == loader.EXIT_WRITE

    logged = caplog.text
    assert "hunter2" not in logged
    assert "OperationalError" in logged


# ---------------------------------------------------------------------------
# Exit codes are distinct, so a workflow can react to each
# ---------------------------------------------------------------------------


def test_every_exit_code_is_distinct():
    codes = [loader.EXIT_OK, loader.EXIT_CONFIG, loader.EXIT_SCHEMA, loader.EXIT_WRITE]
    assert len(set(codes)) == len(codes)
    assert loader.EXIT_OK == 0
    assert all(code != 0 for code in codes[1:])
