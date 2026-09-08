"""Importing a client's compliance control export.

`QualysComplianceParser` backs the registered `qualys_compliance_ingest` module,
so everything it produces is client-facing. It had **no direct tests** — the
only ones naming it asserted which parser gets *selected*, never what it
produces — and it carried three defects its sibling in the same file does not.

**1. Blank cells reached the client as the literal string "nan".**

pandas reads an empty cell as `NaN`, and `str(NaN)` is `"nan"`. The sibling
parser reads through a NaN-aware helper and has a test named for exactly this;
this one used `str(row.get(...))` directly. Measured:

    Control,Status,Description,Asset Name,IP,Remediation
    CIS 1.1 Ensure X,Failed,,host1,10.0.0.1,

    -> description='nan'   solution='nan'

A control whose remediation cell was empty was reported to the client with
**"nan" as its remediation step**.

**2. An unrecognised export fabricated findings.**

The title fell back to the literal `"Unknown"`, which is neither empty nor
`"nan"`, so every row became a finding called "Unknown" at severity info. Three
junk columns produced two junk findings. That is worse than reporting nothing:
it invents rows that were never in the file.

**3. Nothing recorded how many controls passed.**

Every row becomes a `ParsedVulnerability`, so a 500-control export where 490
passed counts as 500 findings. The passes are severity `info` and carry their
status, so keeping them drops no data — but a reader needs the breakdown to say
"500 controls, 10 failed" instead of "500 findings".
"""

from __future__ import annotations

from pathlib import Path

import pytest

from threat_inspector.parsers.qualys import QualysComplianceParser

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "examples" / "file-ingest-selftest" / "qualys-compliance-export.csv"

HEADER = "Control,Status,Description,Asset Name,IP,Remediation"


@pytest.fixture
def export(tmp_path):
    def write(body: str, name: str = "controls.csv") -> Path:
        path = tmp_path / name
        path.write_text(body, encoding="utf-8")
        return path

    return write


def parse(path: Path):
    return QualysComplianceParser().parse(path)


# ---------------------------------------------------------------------------
# Blank cells
# ---------------------------------------------------------------------------


def test_an_empty_cell_is_empty_not_the_word_nan(export):
    """The regression. A control with no remediation text was reported to the
    client with "nan" as its remediation step."""
    result = parse(export(f"{HEADER}\nCIS 1.1 Ensure X,Failed,,host1,10.0.0.1,\n"))
    finding = result.vulnerabilities[0]
    assert finding.description == ""
    assert finding.solution == ""
    assert "nan" not in (finding.description + finding.solution).lower()


def test_no_field_of_any_finding_ever_says_nan(export):
    """Belt and braces across every column this parser reads."""
    result = parse(export(f"{HEADER}\nCIS 1.1,Failed,,,,\n"))
    finding = result.vulnerabilities[0]
    for value in (
        finding.description,
        finding.asset_name,
        finding.asset_ip,
        finding.solution,
    ):
        assert value != "nan"


def test_a_whitespace_only_cell_is_treated_as_empty(export):
    result = parse(export(f"{HEADER}\nCIS 1.1,Failed,   ,host1,10.0.0.1,   \n"))
    assert result.vulnerabilities[0].description == ""
    assert result.vulnerabilities[0].solution == ""


def test_values_that_are_present_survive(export):
    result = parse(
        export(f"{HEADER}\nCIS 1.1,Failed,Why it matters,db01,10.0.0.9,Set the policy.\n")
    )
    finding = result.vulnerabilities[0]
    assert finding.description == "Why it matters"
    assert finding.asset_name == "db01"
    assert finding.asset_ip == "10.0.0.9"
    assert finding.solution == "Set the policy."


# ---------------------------------------------------------------------------
# An export we cannot read must not invent findings
# ---------------------------------------------------------------------------


def test_an_unrecognised_export_produces_nothing_rather_than_junk(export):
    """It used to emit one finding per row, every one titled "Unknown"."""
    result = parse(export("Foo,Bar,Baz\n1,2,3\n4,5,6\n"))
    assert result.total_count == 0
    assert not any(v.title == "Unknown" for v in result.vulnerabilities)


def test_an_unrecognised_export_says_what_it_looked_for(export):
    """Producing nothing silently is the other half of the same problem."""
    result = parse(export("Foo,Bar,Baz\n1,2,3\n4,5,6\n"))
    assert len(result.warnings) == 1
    assert "2 row(s) read" in result.warnings[0]
    assert "Control" in result.warnings[0]
    assert "Foo, Bar, Baz" in result.warnings[0]


def test_a_row_with_a_blank_control_is_skipped_not_titled_unknown(export):
    result = parse(export(f"{HEADER}\n,Failed,d,host1,10.0.0.1,fix\nCIS 1.2,Failed,,,,\n"))
    assert [v.title for v in result.vulnerabilities] == ["CIS 1.2"]


def test_a_header_only_export_is_not_reported_as_a_mismatch(export):
    """No rows read is an empty export, not a broken mapping."""
    result = parse(export(f"{HEADER}\n"))
    assert result.total_count == 0
    assert result.warnings == []
    assert result.errors == []


def test_the_control_name_may_arrive_under_title(export):
    result = parse(export("Title,Status\nCIS 1.1,Failed\n"))
    assert result.vulnerabilities[0].title == "CIS 1.1"


def test_control_wins_over_title_when_both_are_present(export):
    result = parse(export("Control,Title,Status\nFrom Control,From Title,Failed\n"))
    assert result.vulnerabilities[0].title == "From Control"


@pytest.mark.parametrize(
    ("columns", "row", "expected_asset"),
    [
        ("Control,Status,Asset Name", "CIS 1.1,Failed,db01", "db01"),
        ("Control,Status,Host", "CIS 1.1,Failed,web01", "web01"),
    ],
)
def test_the_asset_may_arrive_under_either_name(export, columns, row, expected_asset):
    result = parse(export(f"{columns}\n{row}\n"))
    assert result.vulnerabilities[0].asset_name == expected_asset


@pytest.mark.parametrize("column", ["IP", "Asset IP"])
def test_the_address_may_arrive_under_either_name(export, column):
    result = parse(export(f"Control,Status,{column}\nCIS 1.1,Failed,10.0.0.7\n"))
    assert result.vulnerabilities[0].asset_ip == "10.0.0.7"


@pytest.mark.parametrize("column", ["Remediation", "Solution"])
def test_the_fix_may_arrive_under_either_name(export, column):
    result = parse(export(f"Control,Status,{column}\nCIS 1.1,Failed,Do the thing.\n"))
    assert result.vulnerabilities[0].solution == "Do the thing."


# ---------------------------------------------------------------------------
# Control status becomes severity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("Failed", "high"),
        ("FAILED", "high"),
        ("Fail", "high"),
        ("Warning", "medium"),
        ("Warn", "medium"),
        ("Passed", "info"),
        ("Not Applicable", "info"),
        ("", "info"),
    ],
)
def test_a_controls_status_decides_its_severity(export, status, expected):
    result = parse(export(f"Control,Status\nCIS 1.1,{status}\n"))
    assert result.vulnerabilities[0].severity == expected


def test_the_raw_status_is_kept_alongside_the_severity(export):
    """A reader has to be able to see what the export actually said."""
    result = parse(export("Control,Status\nCIS 1.1,Failed\n"))
    assert result.vulnerabilities[0].scanner_severity == "failed"


def test_a_missing_status_column_does_not_break_the_import(export):
    result = parse(export("Control\nCIS 1.1\n"))
    assert result.total_count == 1
    assert result.vulnerabilities[0].severity == "info"


# ---------------------------------------------------------------------------
# How many controls passed
# ---------------------------------------------------------------------------


def test_the_pass_and_fail_breakdown_is_recorded(export):
    """Every row becomes a finding, so without this a 500-control export where
    490 passed reads as "500 findings"."""
    result = parse(export("Control,Status\nA,Passed\nB,Passed\nC,Warning\nD,Failed\n"))
    assert result.scan_metadata["control_status_counts"] == {
        "failed": 1,
        "warning": 1,
        "passed": 2,
    }


def test_the_breakdown_accounts_for_every_imported_control(export):
    result = parse(export("Control,Status\nA,Passed\nB,Failed\nC,Warning\n"))
    counts = result.scan_metadata["control_status_counts"]
    assert sum(counts.values()) == result.total_count


def test_the_breakdown_is_present_even_when_nothing_was_imported(export):
    """A consumer should not have to guess whether the key exists."""
    result = parse(export("Foo\n1\n"))
    assert result.scan_metadata["control_status_counts"] == {
        "failed": 0,
        "warning": 0,
        "passed": 0,
    }


def test_a_passed_control_is_still_imported(export):
    """Keeping passes drops no data; the severity and status say what they are."""
    result = parse(export("Control,Status\nCIS 1.1,Passed\n"))
    assert result.total_count == 1
    assert result.vulnerabilities[0].severity == "info"


# ---------------------------------------------------------------------------
# The committed fixture, and degenerate files
# ---------------------------------------------------------------------------


def test_the_committed_fixture_parses():
    result = parse(FIXTURE)
    assert result.total_count == 5
    assert result.errors == []
    assert result.scan_metadata["control_status_counts"]["failed"] == 3


def test_the_committed_fixture_carries_no_nan_text():
    """The defect this file exists for, checked against the real fixture."""
    for finding in parse(FIXTURE).vulnerabilities:
        assert "nan" not in finding.solution.lower().split()
        assert "nan" not in finding.description.lower().split()


def test_the_columns_that_were_read_are_recorded():
    result = parse(FIXTURE)
    assert "Control" in result.scan_metadata["columns"]
    assert result.scan_metadata["total_rows"] == 5


def test_a_missing_file_is_an_error_not_a_crash(tmp_path):
    result = parse(tmp_path / "nope.csv")
    assert result.total_count == 0
    assert len(result.errors) == 1


def test_an_unreadable_file_is_an_error_not_a_crash(tmp_path):
    path = tmp_path / "controls.xlsx"
    path.write_bytes(b"not really a spreadsheet")
    result = parse(path)
    assert result.total_count == 0
    assert len(result.errors) == 1


def test_the_scan_is_labelled_as_a_compliance_import():
    result = parse(FIXTURE)
    assert result.scanner_type == "qualys_compliance"
    assert result.scan_metadata["scan_type"] == "compliance"


# ---------------------------------------------------------------------------
# Through the registered ingest module
# ---------------------------------------------------------------------------


def test_the_ingest_module_carries_the_findings_up():
    """The module is what a scan actually runs; the parser is an implementation
    detail of it."""
    import sys

    sys.path.insert(0, str(ROOT / "module_framework"))
    from file_modules.qualys_compliance_ingest import QualysComplianceIngest

    report = QualysComplianceIngest().ingest_report(FIXTURE, {})
    assert len(report.findings) == 5
    assert report.errors == []


def test_the_ingest_module_carries_a_mismatch_warning_up(export):
    """A warning that stops at the parser is a warning nobody sees."""
    import sys

    sys.path.insert(0, str(ROOT / "module_framework"))
    from file_modules.qualys_compliance_ingest import QualysComplianceIngest

    report = QualysComplianceIngest().ingest_report(export("Foo,Bar\n1,2\n"), {})
    assert report.findings == []
    assert report.warnings
