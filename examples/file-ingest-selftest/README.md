# File-ingestion self-test fixtures

**Synthetic. Not a client export, and not a real scan of anything.**

`file-scan.yml` had never completed a run — it takes uploaded third-party scan
exports, and with nothing committed to point it at there was no way to exercise
the path end to end. Dispatching it against any directory in the repo failed with
`no input files`, which is correct fail-closed behaviour and also meant the
workflow could never be green.

These files exist so the ingestion path can be proven without a real export.

## What is here

| File | Exercises | Findings |
|---|---|---|
| `nessus-export.csv` | vulnerability scan import | 8 |
| `qualys-export.csv` | spreadsheet vulnerability import | 5 |
| `qualys-compliance-export.csv` | compliance control import | 5 |
| `network-scan.xml` | network discovery import | 2 |
| `zap-report.json` | web application assessment import | 5 |

All five file-ingest modules are covered, and the set spans every severity band
(critical, high, medium, low, info) so severity mapping is exercised all the way
to the dashboard rather than only on the happy path. Current total: **25
findings across 5 files**.

## Everything here is unroutable on purpose

Hosts live in `10.255.255.0/24` and under `*.selftest.invalid`. `.invalid` is
reserved by RFC 2606 and can never resolve; the 10/8 addresses are private. The
CVE identifiers that appear (e.g. `CVE-2021-44228`) are real published
identifiers used as realistic *text* — the rows they sit on are invented and
describe no actual system.

## Running it

Locally, which is also what `tools/smoke_test.py` does:

    python3 module_framework/ingest.py --group ingest \
      --files-dir examples/file-ingest-selftest \
      --client fixture-selftest --scan-id local-1

Through the workflow:

    gh workflow run file-scan.yml -R IronCityIT/threat-inspector --ref main \
      -f files_path=examples/file-ingest-selftest \
      -f client_name=fixture-selftest \
      -f group=ingest

Run it under a self-test client, never a real one. Using a real `client_name`
would write invented findings into that client's Firestore partition, which is
the one thing this fixture must never be used for.

## Adding to the set

Keep every host unroutable, keep `Synthetic fixture row.`-style text in the
description so a row can never be mistaken for a real finding, and re-run the
smoke test — it asserts that all five modules still produce findings and that
the severity coverage holds.
