#!/usr/bin/env python3
"""Write a built scan payload into the self-hosted store.

This is the self-hosted counterpart of the `POST to storeScanResults` step in
`_consensus-store.yml`. It takes exactly the payload `tools/build_store_payload.py`
already produces, so repointing the pipeline later is a change of step, not a
change of contract.

**Not wired into any workflow yet.** See docs/HANDOFF.md §3.3 for what is still
UNKNOWN about the target (credentials, whether this product owns its own schema
or POSTs to the shared `/ingest`). This exists so that decision is the only
thing left to make.

Fail-closed, deliberately
-------------------------
The store step this replaces once read:

    if [ -z "$STORE_URL" ]; then
      echo "::warning::STORE_SCAN_RESULTS_URL not set — skipping store"
      exit 0
    fi

`STORE_SCAN_RESULTS_URL` had never been set, so **every scan the product had
ever run discarded its findings at the last step and reported success.** A green
run meant nothing about whether the client's results existed.

Nothing here exits 0 unless a row was written. An unset `DATABASE_URL`, an
unreadable payload, an unmigrated database and a failed write are all non-zero,
each with its own code so a workflow can tell them apart.

Refusing to write into a stale schema
-------------------------------------
The loader checks the database is at the migration head before writing. A schema
behind the code accepts *most* of a payload and silently drops whatever the
newest revision added — which is the same class of quiet data loss this product
keeps finding in its own scanners. Better to refuse and say so.

Usage:
    export DATABASE_URL='mysql+pymysql://user:pass@host/db'
    python3 -m threat_inspector.storage.loader --payload payload.json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

log = logging.getLogger("threat_inspector.storage.loader")

# Distinct so a workflow can react to each without parsing the message.
EXIT_OK = 0
EXIT_CONFIG = 1  # no DATABASE_URL, unreadable or invalid payload
EXIT_SCHEMA = 2  # database is not migrated, or is behind the code
EXIT_WRITE = 3  # the write itself failed

MIGRATION_HINT = (
    "run `alembic upgrade head` against this database "
    "(see docs/HANDOFF.md §14.3) before loading results"
)


class LoaderError(Exception):
    """A refusal, carrying the exit code the caller should use."""

    def __init__(self, message: str, code: int) -> None:
        super().__init__(message)
        self.code = code


def database_url() -> str:
    """The target database. From the environment, and never defaulted.

    Falling back to a local SQLite file here would be the worst possible
    behaviour: the load would succeed, the workflow would go green, and the
    client's findings would be sitting in a file on a runner that is deleted
    when the job ends.
    """
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise LoaderError(
            "DATABASE_URL is not set — refusing to guess where a client's findings should go.",
            EXIT_CONFIG,
        )
    return url


def read_payload(path: Path) -> dict[str, Any]:
    """Read and sanity-check the payload before opening a connection."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        raise LoaderError(f"cannot read {path}: {e}", EXIT_CONFIG) from e

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        raise LoaderError(f"{path} is not valid JSON: {e}", EXIT_CONFIG) from e

    if not isinstance(payload, dict):
        raise LoaderError(f"{path} must contain a JSON object", EXIT_CONFIG)
    if not str(payload.get("client_id") or "").strip():
        raise LoaderError("payload has no client_id", EXIT_CONFIG)
    if not str(payload.get("scan_id") or "").strip():
        raise LoaderError("payload has no scan_id", EXIT_CONFIG)
    return payload


def schema_revision(connection: Any) -> str | None:
    """What migration the database is at, or None if it has never been migrated."""
    from alembic.migration import MigrationContext

    return MigrationContext.configure(connection).get_current_revision()


def expected_revision() -> str:
    """The single head this code expects."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    root = Path(__file__).resolve().parent.parent.parent.parent
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(Path(__file__).resolve().parent / "migrations"))
    heads = ScriptDirectory.from_config(config).get_heads()
    if len(heads) != 1:
        raise LoaderError(f"expected exactly one migration head, found {len(heads)}", EXIT_SCHEMA)
    return heads[0]


def check_schema(connection: Any) -> None:
    """Refuse to write into a database that is not at the expected revision."""
    current = schema_revision(connection)
    if current is None:
        raise LoaderError(f"database has no schema — {MIGRATION_HINT}", EXIT_SCHEMA)
    expected = expected_revision()
    if current != expected:
        raise LoaderError(
            f"database is at migration {current}, this code expects {expected} — {MIGRATION_HINT}",
            EXIT_SCHEMA,
        )


def load(payload: dict[str, Any], url: str) -> tuple[str, str, int]:
    """Write one payload. Returns (client_id, scan_id, findings stored).

    The whole load is one transaction: a scan is either stored with all of its
    findings or not stored at all. A half-written scan would be reported to a
    client as a complete one.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.exc import SQLAlchemyError
    from sqlalchemy.orm import Session

    from .repository import ScanRepository

    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            check_schema(connection)

        with Session(engine) as session:
            repository = ScanRepository(session)
            scan = repository.store_scan(payload)
            stored = len(repository.list_findings(scan.client_id, scan_id=scan.scan_id))
            session.commit()
            return scan.client_id, scan.scan_id, stored
    except LoaderError:
        raise
    except SQLAlchemyError as e:
        # The message can carry the DSN, which carries the password.
        raise LoaderError(f"the write failed: {type(e).__name__}", EXIT_WRITE) from e
    finally:
        engine.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Write a built scan payload into the self-hosted store."
    )
    parser.add_argument(
        "--payload",
        type=Path,
        required=True,
        help="payload.json as produced by tools/build_store_payload.py",
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=("debug", "info", "warning", "error"),
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(levelname)-7s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    try:
        payload = read_payload(args.payload)
        url = database_url()
        client_id, scan_id, stored = load(payload, url)
    except LoaderError as e:
        # Never log the exception's own repr for a database error — see load().
        log.error("%s", e)
        return e.code

    log.info(
        "stored scan %s for client %s with %d finding(s)",
        scan_id,
        client_id,
        stored,
    )
    print(
        json.dumps(
            {"status": "stored", "client_id": client_id, "scan_id": scan_id, "findings": stored}
        )
    )
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
