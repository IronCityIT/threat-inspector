"""Which parser reads a client's upload.

Every ingested byte goes through `get_parser`. It decides, from an optional
caller-supplied `scanner_type` and then from the file itself, which parser runs
— and the wrong choice does not error, it just produces the wrong answer. It
sat at 75% coverage.

`scanner_type` is exposed as a query parameter on both upload endpoints, and it
was treated as a *suggestion*. Measured through the API against a
vulnerability-scan CSV:

    scanner_type=zap    -> 200, 8 findings   hint discarded, Nessus ran anyway
    scanner_type=bogus  -> 200, 8 findings   typo discarded
    scanner_type=QUALYS -> 200, 0 findings   honoured, wrong format, empty result

The first two ignore what the caller said without a word. The third is the
"corrupt upload reported as a clean, empty ingest" failure this product keeps
finding, reachable from a query string.

An explicit `scanner_type` is the caller *asserting* what the file is, so a
false assertion is now refused rather than worked around. The third case is
different and stays: Qualys genuinely can read a `.csv`, so the caller got what
they asked for — and the ingest is graded `degraded`, not `ok`, because nothing
in it was recognised.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from threat_inspector.parsers import (
    KNOWN_SCANNER_TYPES,
    PARSER_REGISTRY,
    SUPPORTED_FORMATS,
    get_parser,
    parse_file,
)

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "examples" / "file-ingest-selftest" / "nessus-export.csv"

NESSUS_CSV = b"Plugin ID,Name,Risk\n42873,Weak cipher,Medium\n"


@pytest.fixture
def scan_file(tmp_path):
    def write(name: str, body: bytes = NESSUS_CSV) -> Path:
        path = tmp_path / name
        path.write_bytes(body)
        return path

    return write


def parser_name(path: Path, scanner_type: str | None = None) -> str:
    parser = get_parser(path, scanner_type)
    return type(parser).__name__ if parser else "None"


# ---------------------------------------------------------------------------
# An explicit scanner_type is an assertion, not a suggestion
# ---------------------------------------------------------------------------


def test_an_explicit_type_is_honoured(scan_file):
    assert parser_name(scan_file("scan.csv"), "qualys") == "QualysParser"
    assert parser_name(scan_file("scan.csv"), "nessus") == "NessusParser"


def test_an_unknown_type_is_refused_rather_than_ignored(scan_file):
    """It used to fall through to auto-detection, so a typo looked like it
    worked and something else parsed the file."""
    with pytest.raises(ValueError) as excinfo:
        get_parser(scan_file("scan.csv"), "bogus")
    assert "bogus" in str(excinfo.value)


def test_the_refusal_names_the_types_that_do_exist(scan_file):
    with pytest.raises(ValueError) as excinfo:
        get_parser(scan_file("scan.csv"), "bogus")
    for known in KNOWN_SCANNER_TYPES:
        assert known in str(excinfo.value)


def test_a_type_that_cannot_read_this_file_is_refused(scan_file):
    """The caller said ZAP. ZAP reads XML and JSON. Quietly parsing their CSV
    as something else discards what they told us."""
    with pytest.raises(ValueError) as excinfo:
        get_parser(scan_file("scan.csv"), "zap")
    message = str(excinfo.value)
    assert ".csv" in message
    assert ".xml" in message and ".json" in message


def test_the_mismatch_refusal_names_the_extensions_that_would_work(scan_file):
    with pytest.raises(ValueError) as excinfo:
        get_parser(scan_file("scan.csv"), "nmap")
    assert ".nmap" in str(excinfo.value)


@pytest.mark.parametrize("spelling", ["nessus", "NESSUS", "Nessus", "  nessus  "])
def test_a_type_is_matched_however_it_is_spelled(scan_file, spelling):
    assert parser_name(scan_file("scan.csv"), spelling) == "NessusParser"


def test_an_empty_type_falls_back_to_auto_detection(scan_file):
    """Empty is "not supplied", not "a type that does not exist"."""
    assert parser_name(scan_file("scan.csv"), "") == "NessusParser"


def test_the_compliance_export_type_is_addressable(scan_file):
    assert parser_name(scan_file("controls.csv"), "qualys_compliance") == ("QualysComplianceParser")


def test_the_known_types_come_from_the_registry():
    """A new parser must not be addressable in one place and not the other."""
    assert set(KNOWN_SCANNER_TYPES) == {p.SCANNER_TYPE for p in PARSER_REGISTRY}


# ---------------------------------------------------------------------------
# Auto-detection, when the caller asserts nothing
# ---------------------------------------------------------------------------


def test_a_nessus_export_is_detected_by_its_extension(scan_file):
    assert parser_name(scan_file("scan.nessus", b"<NessusClientData_v2/>")) == "NessusParser"


def test_a_csv_is_detected_from_its_header_not_its_name(scan_file):
    """A file called scan.csv with plugin columns is a vulnerability export."""
    assert parser_name(scan_file("scan.csv")) == "NessusParser"
    assert parser_name(scan_file("export.csv")) == "NessusParser"


def test_a_csv_without_plugin_columns_defaults_to_the_spreadsheet_parser(scan_file):
    assert parser_name(scan_file("scan.csv", b"QID,Title,Severity\n1,x,3\n")) == "QualysParser"


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (b'<?xml version="1.0"?><OWASPZAPReport><site/></OWASPZAPReport>', "ZAPParser"),
        (b'<?xml version="1.0"?><nmaprun><host/></nmaprun>', "NmapParser"),
        (
            b'<?xml version="1.0"?><NessusClientData_v2><ReportHost/></NessusClientData_v2>',
            "NessusParser",
        ),
    ],
)
def test_xml_is_routed_by_its_content(scan_file, body, expected):
    assert parser_name(scan_file("scan.xml", body)) == expected


def test_an_uppercase_extension_is_still_recognised(scan_file):
    assert parser_name(scan_file("SCAN.XML", b"<nmaprun/>")) == "NmapParser"


@pytest.mark.parametrize(
    ("name", "expected"),
    [("scan.json", "ZAPParser"), ("scan.txt", "NmapParser"), ("scan.nmap", "NmapParser")],
)
def test_the_remaining_extensions_route_to_their_parser(scan_file, name, expected):
    assert parser_name(scan_file(name, b"{}")) == expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("qualys-report.csv", "QualysParser"),
        ("qualys-compliance-export.csv", "QualysComplianceParser"),
        ("zap-export.json", "ZAPParser"),
        ("nmap-notes.txt", "NmapParser"),
        ("tenable-export.csv", "NessusParser"),
    ],
)
def test_a_name_that_declares_its_format_is_taken_at_its_word(scan_file, name, expected):
    """The file's own name is treated as the strongest signal available.

    Worth pinning because it BEATS content sniffing: `qualys-report.csv`
    carrying plugin columns is read as a spreadsheet export, not a
    vulnerability export. That is a real way a client's file naming changes
    what they get back — and since the parsers now warn when they read rows and
    recognise nothing, a misnamed file is visible rather than silent.
    """
    assert parser_name(scan_file(name)) == expected


def test_a_misnamed_file_is_read_as_named_and_says_it_recognised_nothing(scan_file):
    """The consequence of the rule above, end to end."""
    result = parse_file(scan_file("qualys-report.csv"))
    assert result.total_count == 0
    assert result.warnings, "reading nothing must not pass for a clean export"


def test_the_compliance_hint_needs_both_words(scan_file):
    """ "qualys" alone is the vulnerability export; "qualys...compliance" is the
    control export. They are different parsers with different outputs."""
    assert parser_name(scan_file("qualys-export.csv")) == "QualysParser"
    assert parser_name(scan_file("qualys-compliance.csv")) == "QualysComplianceParser"


def test_a_directory_named_after_a_scanner_does_not_decide_the_parser(tmp_path):
    """Only the file's own name is a hint. A folder called `qualys/` must not
    change how the files inside it are read."""
    folder = tmp_path / "qualys"
    folder.mkdir()
    path = folder / "scan.csv"
    path.write_bytes(NESSUS_CSV)
    assert parser_name(path) == "NessusParser"


def test_an_unsupported_extension_selects_nothing(scan_file):
    assert get_parser(scan_file("archive.zip", b"PK\x03\x04")) is None


def test_a_file_with_no_extension_selects_nothing(scan_file):
    assert get_parser(scan_file("noext", b"anything")) is None


# ---------------------------------------------------------------------------
# parse_file
# ---------------------------------------------------------------------------


def test_parse_file_reads_a_real_export():
    assert parse_file(FIXTURE).total_count == 8


def test_parse_file_refuses_an_unsupported_file(scan_file):
    with pytest.raises(ValueError) as excinfo:
        parse_file(scan_file("archive.zip", b"PK\x03\x04"))
    assert "No parser available" in str(excinfo.value)


def test_the_refusal_lists_what_can_be_ingested(scan_file):
    with pytest.raises(ValueError) as excinfo:
        parse_file(scan_file("archive.zip", b"PK"))
    for extension in SUPPORTED_FORMATS:
        assert extension in str(excinfo.value)


def test_a_missing_file_is_a_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        parse_file(tmp_path / "nope.csv")


def test_parse_file_propagates_a_false_assertion(scan_file):
    with pytest.raises(ValueError):
        parse_file(scan_file("scan.csv"), "zap")


# ---------------------------------------------------------------------------
# ...and the same over the API, where the parameter is actually exposed
# ---------------------------------------------------------------------------


@pytest.fixture
def api(monkeypatch):
    monkeypatch.setenv("TI_API_TOKENS", "tok-acme:acme")
    monkeypatch.delenv("TI_ALLOW_UNAUTHENTICATED", raising=False)
    for name in [m for m in list(sys.modules) if m.startswith("threat_inspector")]:
        del sys.modules[name]
    sys.path.insert(0, str(ROOT / "src"))
    from threat_inspector.api.main import app

    return TestClient(app)


def upload(api, scanner_type=None):
    url = "/api/v1/scans/upload"
    if scanner_type is not None:
        url += f"?scanner_type={scanner_type}"
    return api.post(
        url,
        headers={"Authorization": "Bearer tok-acme"},
        files={"file": (FIXTURE.name, FIXTURE.read_bytes(), "text/csv")},
    )


def test_an_upload_with_no_assertion_is_auto_detected(api):
    assert upload(api).json()["vulnerabilities_found"] == 8


def test_an_upload_asserting_the_right_type_works(api):
    assert upload(api, "nessus").json()["vulnerabilities_found"] == 8


def test_an_upload_asserting_an_unknown_type_is_a_400(api):
    """Was: 200 with 8 findings, the typo silently discarded."""
    response = upload(api, "bogus")
    assert response.status_code == 400
    assert "unknown scanner_type" in response.json()["detail"]


def test_an_upload_asserting_a_type_that_cannot_read_it_is_a_400(api):
    """Was: 200 with 8 findings, parsed by something the caller did not name."""
    response = upload(api, "zap")
    assert response.status_code == 400
    assert "cannot read" in response.json()["detail"]
