"""Migrations: does the schema on disk match the schema in the code?

`metadata.create_all()` builds the tables from `schema.py`. Alembic builds them
from a revision file. Those are two descriptions of one thing, and they drift —
someone adds a column to the model, the tests pass because they run against
`create_all`, and the migration that a real database would actually apply never
learns about it. The database then diverges from the code silently, which on a
store holding client findings is not a small problem.

`test_the_migration_and_the_models_agree` is the check for that, and it is the
reason this file exists: it upgrades a database with Alembic and then asks
Alembic to compare the result against the models. Any difference at all is a
failure.

The other property tested here is a safety one. The target MariaDB instance is
**shared** — the legacy `models/__init__.py` schema may live there, and
`ironcity-api` certainly does, with a schema this repository has never seen
(docs/HANDOFF.md §3.3). Autogenerate's default behaviour against a shared
database is to propose dropping every table it does not recognise. `env.py`
confines this migration set to the `ti_` prefix, and
`test_a_table_we_do_not_own_is_never_touched` proves it.

Nothing here connects to MariaDB. No credential exists (docs/HANDOFF.md §13.2),
so these run against SQLite and the MariaDB-specific properties are checked by
compiling DDL for the MySQL dialect in tests/test_storage_repository.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("sqlalchemy", reason="sqlalchemy is required for the storage suite")
pytest.importorskip("alembic", reason="alembic is declared in requirements.txt")

from alembic import command  # noqa: E402
from alembic.autogenerate import compare_metadata  # noqa: E402
from alembic.config import Config  # noqa: E402
from alembic.migration import MigrationContext  # noqa: E402
from sqlalchemy import (  # noqa: E402
    Column,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    inspect,
)

from threat_inspector.storage.schema import metadata  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent


def alembic_config(url: str) -> Config:
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option(
        "script_location", str(REPO_ROOT / "src/threat_inspector/storage/migrations")
    )
    return config


@pytest.fixture
def database(tmp_path, monkeypatch):
    """A file-backed SQLite database Alembic can migrate.

    File-backed rather than in-memory: Alembic opens its own connection, and an
    in-memory database would be a different, empty one.
    """
    url = f"sqlite:///{tmp_path / 'store.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    return url


@pytest.fixture
def migrated(database):
    """A database at head."""
    command.upgrade(alembic_config(database), "head")
    return database


# ---------------------------------------------------------------------------
# The migration builds what the code describes
# ---------------------------------------------------------------------------


def test_upgrade_creates_the_store(migrated):
    tables = set(inspect(create_engine(migrated)).get_table_names())
    assert {"ti_clients", "ti_scans", "ti_findings"} <= tables


def test_the_migration_and_the_models_agree(migrated):
    """The drift check.

    Upgrade with Alembic, then ask Alembic to compare the result against the
    models. An empty diff means a real database built by migration is exactly
    the database the code expects. A non-empty one means someone changed
    schema.py without writing a migration, and every test that runs against
    `create_all` would still have passed.
    """
    engine = create_engine(migrated)
    with engine.connect() as connection:
        context = MigrationContext.configure(
            connection,
            opts={
                "compare_type": True,
                "include_object": _only_ours,
            },
        )
        diff = compare_metadata(context, metadata)

    assert diff == [], f"schema.py and the migrations have diverged: {diff}"


def test_downgrade_removes_everything_it_created(database):
    config = alembic_config(database)
    command.upgrade(config, "head")
    command.downgrade(config, "base")

    tables = set(inspect(create_engine(database)).get_table_names())
    assert not {"ti_clients", "ti_scans", "ti_findings"} & tables


def test_upgrade_downgrade_upgrade_is_stable(database):
    """A downgrade that leaves residue makes the next upgrade fail."""
    config = alembic_config(database)
    command.upgrade(config, "head")
    command.downgrade(config, "base")
    command.upgrade(config, "head")

    tables = set(inspect(create_engine(database)).get_table_names())
    assert {"ti_clients", "ti_scans", "ti_findings"} <= tables


def test_the_migrated_schema_actually_accepts_a_scan(migrated):
    """Built by migration, not by create_all — the repository must work on it."""
    from sqlalchemy.orm import Session

    from threat_inspector.storage import ScanRepository

    engine = create_engine(migrated)
    with Session(engine) as session:
        repo = ScanRepository(session)
        repo.store_scan(
            {
                "client_id": "acme",
                "scan_id": "s1",
                "status": "completed",
                "findings": [{"severity": "high", "title": "found on a migrated schema"}],
            }
        )
        session.commit()
        assert [f.title for f in repo.list_findings("acme")] == ["found on a migrated schema"]


# ---------------------------------------------------------------------------
# The migration set owns only its own tables
# ---------------------------------------------------------------------------


def _only_ours(obj, name, type_, reflected, compare_to) -> bool:
    """Mirrors env.py's include_object, so the tests exercise the same rule."""
    if type_ == "table":
        return name.startswith("ti_")
    parent = getattr(obj, "table", None)
    if parent is not None:
        return parent.name.startswith("ti_")
    return True


def test_a_table_we_do_not_own_is_never_touched(migrated):
    """The safety property.

    The target MariaDB instance is shared: ironcity-api's schema is on it, and
    this repository has never seen it. Autogenerate's default is to propose a
    DROP for every table not present in target_metadata — pointed at that
    database with no filter, the first generated revision would propose
    dropping another service's data.
    """
    engine = create_engine(migrated)

    # Stand in for someone else's table.
    foreign = MetaData()
    Table(
        "ironcity_api_things",
        foreign,
        Column("id", Integer, primary_key=True),
        Column("value", String(50)),
    )
    foreign.create_all(engine)

    with engine.connect() as connection:
        context = MigrationContext.configure(
            connection, opts={"compare_type": True, "include_object": _only_ours}
        )
        diff = compare_metadata(context, metadata)

    rendered = str(diff)
    assert "ironcity_api_things" not in rendered, (
        "a migration generated here would touch a table this product does not own"
    )
    assert diff == []


def test_the_filter_would_otherwise_have_proposed_a_drop(migrated):
    """Proves the previous test is testing something.

    Without the filter, the foreign table IS proposed for removal — so the
    filter is load-bearing rather than decorative.
    """
    engine = create_engine(migrated)
    foreign = MetaData()
    Table("ironcity_api_things", foreign, Column("id", Integer, primary_key=True))
    foreign.create_all(engine)

    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        diff = compare_metadata(context, metadata)

    assert "ironcity_api_things" in str(diff)


# ---------------------------------------------------------------------------
# The connection string is a deployment fact, not a tracked one
# ---------------------------------------------------------------------------


def test_alembic_ini_carries_no_connection_string():
    """A DSN in a tracked file is how credentials reach git history."""
    text = (REPO_ROOT / "alembic.ini").read_text()
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert not stripped.startswith("sqlalchemy.url"), "alembic.ini must not carry a DSN"


def test_a_missing_database_url_is_refused_not_guessed(tmp_path, monkeypatch):
    """Falling back to a default database is how a migration lands somewhere
    nobody intended."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(Exception) as excinfo:
        command.upgrade(alembic_config("unused"), "head")
    assert "DATABASE_URL" in str(excinfo.value)


def test_offline_mode_emits_sql_for_review(database, capsys):
    """`alembic upgrade head --sql` is how a migration gets reviewed before it
    touches a database holding client findings."""
    command.upgrade(alembic_config(database), "head", sql=True)
    emitted = capsys.readouterr().out
    assert "CREATE TABLE ti_clients" in emitted
    assert "CREATE TABLE ti_findings" in emitted


def test_running_a_migration_does_not_disable_application_logging(database):
    """A migration has no business switching off the application's loggers.

    alembic's generated env.py calls `fileConfig(config.config_file_name)`, and
    that function's default is `disable_existing_loggers=True` — which disables
    every logger not named in alembic.ini, including this product's own. In a
    process that migrates and then does something else (the loader checks the
    schema revision before it writes), it silently swallowed the loader's error
    output: a failed write returned its exit code and logged nothing.

    Caught by test_a_write_failure_does_not_leak_the_connection_string, which
    could see the exit code but not the message it was supposed to inspect.
    """
    import logging

    app_logger = logging.getLogger("threat_inspector.storage.loader")
    command.upgrade(alembic_config(database), "head")

    assert not app_logger.disabled, "the migration disabled the application's logger"

    # And it still emits. A handler is attached AFTER the migration on purpose:
    # fileConfig replaces root's handlers as well as disabling loggers, so
    # pytest's own caplog handler does not survive a migration run inside the
    # test body. The property under test is that the logger still works, not
    # which handler happens to be listening.
    emitted: list[str] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            emitted.append(record.getMessage())

    handler = Capture()
    logging.getLogger().addHandler(handler)
    try:
        app_logger.error("still audible after a migration")
    finally:
        logging.getLogger().removeHandler(handler)

    assert "still audible after a migration" in emitted


def test_there_is_exactly_one_head(database):
    """Two heads mean two migration branches and an ambiguous upgrade."""
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(alembic_config(database))
    assert len(script.get_heads()) == 1
