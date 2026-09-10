"""Which module ingests an uploaded file.

`module_framework/ingest.py` is the file-ingestion entry point: it selects
modules, walks the inputs, and picks the one module that should read each file.
When several selected modules accept an extension — `.csv` is claimed by three —
`resolve_module` defers to content detection to break the tie.

**Content detection had no notion of a compliance export.** It distinguished
"vulnerability scan export" from "spreadsheet" and nothing else, so a control
export was routed to the VULNERABILITY parser unless its *filename* happened to
contain "compliance". The same file, renamed:

    controls.csv                 -> qualys_ingest            -> 0 findings
    qualys-compliance-export.csv -> qualys_compliance_ingest -> 5 findings

Five control results, present or absent depending on what the client called the
file. Visible rather than silent — the spreadsheet parser warns that it read
rows and recognised nothing — but still the wrong module reading the file.

This file also covers the dispatch branches that had no test at all: a file no
selected module accepts, and the tie-break fallback when content detection
cannot decide.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import registry
from ingest import collect_files, resolve_module

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "examples" / "file-ingest-selftest"

COMPLIANCE_CSV = FIXTURES / "qualys-compliance-export.csv"
VULN_CSV = FIXTURES / "qualys-export.csv"
NESSUS_CSV = FIXTURES / "nessus-export.csv"


@pytest.fixture
def modules():
    return list(registry.select(registry.discover_files("file_modules"), group="ingest"))


def route(path: Path, modules) -> str | None:
    module = resolve_module(path, modules)
    return module.name if module else None


def findings_for(path: Path, modules) -> int:
    module = resolve_module(path, modules)
    return len(module.ingest_report(path, {}).findings) if module else 0


# ---------------------------------------------------------------------------
# A compliance export is a compliance export whatever it is called
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["controls.csv", "export.csv", "2026-Q1.csv", "audit-results.csv"])
def test_a_compliance_export_routes_by_content_not_by_name(tmp_path, modules, name):
    """The regression. Every one of these went to the vulnerability module."""
    path = tmp_path / name
    path.write_bytes(COMPLIANCE_CSV.read_bytes())
    assert route(path, modules) == "qualys_compliance_ingest"


def test_a_renamed_compliance_export_yields_the_same_findings(tmp_path, modules):
    """Five control results, present or absent depending on the filename."""
    renamed = tmp_path / "controls.csv"
    renamed.write_bytes(COMPLIANCE_CSV.read_bytes())
    assert findings_for(renamed, modules) == findings_for(COMPLIANCE_CSV, modules) == 5


def test_the_filename_hint_still_works_when_it_is_there(modules):
    assert route(COMPLIANCE_CSV, modules) == "qualys_compliance_ingest"


def test_a_compliance_spreadsheet_routes_by_content_too(tmp_path, modules):
    """.xlsx had the same defect and no filename fallback worth relying on:
    the Excel branch returned the vulnerability parser unconditionally."""
    pd = pytest.importorskip("pandas")
    path = tmp_path / "controls.xlsx"
    pd.DataFrame(
        {"Control": ["CIS 1.1"], "Status": ["Failed"], "Remediation": ["Set the policy."]}
    ).to_excel(path, index=False)
    assert route(path, modules) == "qualys_compliance_ingest"


def test_a_vulnerability_spreadsheet_still_routes_to_the_vulnerability_module(tmp_path, modules):
    pd = pytest.importorskip("pandas")
    path = tmp_path / "findings.xlsx"
    pd.DataFrame({"QID": [1], "Vulnerability Title": ["Weak cipher"], "Severity": [3]}).to_excel(
        path, index=False
    )
    assert route(path, modules) == "qualys_ingest"


def test_an_unreadable_spreadsheet_does_not_break_selection(tmp_path, modules):
    """Selection must never fail because a file is corrupt — reporting the
    reason is the parser's job, and it does."""
    path = tmp_path / "broken.xlsx"
    path.write_bytes(b"not really a spreadsheet")
    assert route(path, modules) == "qualys_ingest"


# ---------------------------------------------------------------------------
# ...and the other formats still go where they went
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("nessus-export.csv", "nessus_ingest"),
        ("qualys-export.csv", "qualys_ingest"),
        ("qualys-compliance-export.csv", "qualys_compliance_ingest"),
        ("network-scan.xml", "nmap_ingest"),
        ("zap-report.json", "zap_ingest"),
    ],
)
def test_every_committed_fixture_reaches_its_own_module(modules, fixture, expected):
    assert route(FIXTURES / fixture, modules) == expected


def test_every_committed_fixture_still_yields_findings(modules):
    """Routing correctly and parsing to nothing would be the same failure in a
    different place."""
    for fixture in FIXTURES.glob("*"):
        if fixture.suffix.lower() not in {".csv", ".xml", ".json", ".nessus"}:
            continue
        assert findings_for(fixture, modules) > 0, f"{fixture.name} ingested to nothing"


def test_a_vulnerability_export_is_not_mistaken_for_a_compliance_one(tmp_path, modules):
    """The check keys on a control column; a vulnerability export has none."""
    path = tmp_path / "anything.csv"
    path.write_bytes(VULN_CSV.read_bytes())
    assert route(path, modules) == "qualys_ingest"


def test_a_vulnerability_scan_export_still_wins_on_its_own_columns(tmp_path, modules):
    path = tmp_path / "anything.csv"
    path.write_bytes(NESSUS_CSV.read_bytes())
    assert route(path, modules) == "nessus_ingest"


# ---------------------------------------------------------------------------
# Dispatch branches that had no test
# ---------------------------------------------------------------------------


def test_a_file_no_selected_module_accepts_is_not_routed(tmp_path, modules):
    """It is skipped and reported as skipped, not silently ingested by
    whichever module happened to be first."""
    path = tmp_path / "archive.zip"
    path.write_bytes(b"PK\x03\x04")
    assert resolve_module(path, modules) is None


def test_narrowing_the_selection_narrows_what_is_accepted(tmp_path):
    """With only one module selected, a file it does not accept is unrouted —
    even though another module would have taken it."""
    reg = registry.discover_files("file_modules")
    only_zap = list(registry.select(reg, modules=["zap_ingest"]))
    path = tmp_path / "scan.csv"
    path.write_bytes(NESSUS_CSV.read_bytes())
    assert resolve_module(path, only_zap) is None


def test_a_single_accepting_module_is_used_without_content_detection(tmp_path):
    """One candidate means no tie to break."""
    reg = registry.discover_files("file_modules")
    only_qualys = list(registry.select(reg, modules=["qualys_ingest"]))
    path = tmp_path / "anything.csv"
    path.write_bytes(COMPLIANCE_CSV.read_bytes())
    assert route(path, only_qualys) == "qualys_ingest"


def test_the_tie_break_is_stable_when_content_cannot_decide(tmp_path, modules):
    """A .csv that resolves to no parser at all must still route somewhere
    deterministic rather than differing run to run."""
    path = tmp_path / "empty.csv"
    path.write_bytes(b"")
    first = route(path, modules)
    assert first is not None
    assert all(route(path, modules) == first for _ in range(3))


# ---------------------------------------------------------------------------
# Collecting the inputs
# ---------------------------------------------------------------------------


def test_files_and_directories_are_both_collected(tmp_path, modules):
    known = {e for m in modules for e in m.extensions}
    folder = tmp_path / "uploads"
    folder.mkdir()
    (folder / "a.csv").write_bytes(NESSUS_CSV.read_bytes())
    loose = tmp_path / "b.csv"
    loose.write_bytes(NESSUS_CSV.read_bytes())

    collected = collect_files([str(loose)], [str(folder)], known)
    assert {p.name for p in collected} == {"a.csv", "b.csv"}


def test_a_directory_is_walked_recursively(tmp_path, modules):
    known = {e for m in modules for e in m.extensions}
    nested = tmp_path / "uploads" / "deep"
    nested.mkdir(parents=True)
    (nested / "a.csv").write_bytes(NESSUS_CSV.read_bytes())
    assert [p.name for p in collect_files([], [str(tmp_path / "uploads")], known)] == ["a.csv"]


def test_files_with_an_unknown_extension_are_not_collected(tmp_path, modules):
    known = {e for m in modules for e in m.extensions}
    folder = tmp_path / "uploads"
    folder.mkdir()
    (folder / "notes.md").write_text("not a scan")
    (folder / "a.csv").write_bytes(NESSUS_CSV.read_bytes())
    assert [p.name for p in collect_files([], [str(folder)], known)] == ["a.csv"]


def test_the_same_file_named_twice_is_collected_once(tmp_path, modules):
    known = {e for m in modules for e in m.extensions}
    path = tmp_path / "a.csv"
    path.write_bytes(NESSUS_CSV.read_bytes())
    assert len(collect_files([f"{path},{path}"], [str(tmp_path)], known)) == 1


# ---------------------------------------------------------------------------
# The command-line surface
# ---------------------------------------------------------------------------


def test_listing_modules_reports_the_catalog(capsys):
    """`--list-modules` is what the dashboard's catalog is built from."""
    import json

    import ingest

    assert ingest.main(["--list-modules"]) == 0
    catalog = json.loads(capsys.readouterr().out)
    assert {m["name"] for m in catalog["modules"]} >= {
        "nessus_ingest",
        "qualys_ingest",
        "qualys_compliance_ingest",
    }
    assert "ingest" in catalog["groups"]


def test_an_unknown_module_selection_is_refused(capsys):
    import ingest

    assert ingest.main(["--modules", "nope_ingest", "--files", "x.csv"]) == 2


def test_no_input_files_is_refused_rather_than_reported_as_a_clean_run(capsys, tmp_path):
    """Zero files ingested is not a successful ingest of zero findings."""
    import ingest

    assert ingest.main(["--group", "ingest", "--files-dir", str(tmp_path)]) == 2


def test_a_real_ingest_reports_its_findings_and_status(capsys, tmp_path):
    import json

    import ingest

    path = tmp_path / "controls.csv"
    path.write_bytes(COMPLIANCE_CSV.read_bytes())

    assert ingest.main(["--group", "ingest", "--files", str(path), "--client", "acme"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["status"] == "ok"
    assert doc["file_count"] == 1
    assert len(doc["findings"]) == 5
    assert doc["files_failed"] == []


def test_a_file_that_cannot_be_parsed_is_reported_as_failed_not_ingested(capsys, tmp_path):
    """A corrupt upload passing for a clean, empty export is the failure this
    entry point was written to prevent."""
    import json

    import ingest

    path = tmp_path / "broken.xml"
    path.write_text("<not-closed")

    ingest.main(["--group", "ingest", "--files", str(path)])
    doc = json.loads(capsys.readouterr().out)
    assert doc["status"] == "failed"
    assert doc["file_count"] == 0
    assert len(doc["files_failed"]) == 1


def test_strict_turns_a_parse_failure_into_a_non_zero_exit(tmp_path):
    import ingest

    path = tmp_path / "broken.xml"
    path.write_text("<not-closed")
    assert ingest.main(["--group", "ingest", "--files", str(path), "--strict"]) == 1


def test_a_warning_from_a_parser_reaches_the_ingest_document(capsys, tmp_path):
    """A warning that stops at the parser is a warning nobody sees."""
    import json

    import ingest

    path = tmp_path / "odd.csv"
    path.write_text("Foo,Bar\n1,2\n", encoding="utf-8")

    ingest.main(["--group", "ingest", "--files", str(path)])
    doc = json.loads(capsys.readouterr().out)
    assert doc["warnings"], "the parser's warning must survive to the document"
