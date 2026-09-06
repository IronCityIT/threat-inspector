"""The two ingestion parsers that had no tests at all.

`test_parser_files.py` covers the network and spreadsheet parsers. The other
two — the vulnerability-scan export parser and the web-application scan export
parser — sat at 37% and 53% line coverage with no direct test, and both are
live client-facing ingestion: `nessus_ingest` and `zap_ingest` are registered
file modules that delegate straight to them, and every byte they read came out
of a file a client uploaded.

Six defects were reproduced against these parsers before the fixes below. Four
of them lose or misgrade client data *silently* — no error, no warning, just a
smaller or wronger report than the scan actually produced:

  1. A BOM on a CSV export (what Windows writes) landed inside the FIRST
     column's name, so lookups of that column missed. With "Name" first —
     the title — every row was skipped as untitled and the whole export
     ingested as ZERO findings, with no error and no warning.
  2. A plugin output over 128 KB in one cell tripped csv's default field cap
     and lost the ENTIRE export.
  3. An API-shaped web report writes the risk as a word ("High"), not a code.
     The code map's default caught it, so a SQL injection was reported to the
     client as informational.
  4. An empty <cvss3_base_score/> shadowed a real v2 score, so the finding
     reached the client with no score at all.
  5. Only the first <cve> of a multi-CVE plugin survived.
  6. Report timestamps are RFC-2822, parsed as ISO-8601 — so every ingested
     XML web report claimed no scan date.

These use the parsers by their internal names deliberately: the white-label
rule covers client-facing surfaces, not the code that implements them.
"""

from __future__ import annotations

import json

import pytest

from threat_inspector.parsers.nessus import NessusParser
from threat_inspector.parsers.zap import ZAPParser

# A vulnerability-scan CSV export in the column order the scanner ships.
CSV_HEADER = "Plugin ID,CVE,CVSS,Risk,Host,Protocol,Port,Name,Synopsis,Solution,Plugin Output"
CSV_ROW = (
    "42873,CVE-2016-2183,5.0,Medium,10.255.255.1,tcp,443,"
    "Medium Strength Cipher Suites,synopsis text,Reconfigure the service,cipher output"
)


def write_bytes(tmp_path, name: str, body: bytes):
    path = tmp_path / name
    path.write_bytes(body)
    return path


def write(tmp_path, name: str, body: str):
    return write_bytes(tmp_path, name, body.encode("utf-8"))


# ---------------------------------------------------------------------------
# Vulnerability scan export — CSV
# ---------------------------------------------------------------------------


def test_a_csv_export_maps_onto_findings(tmp_path):
    result = NessusParser().parse(write(tmp_path, "s.csv", f"{CSV_HEADER}\n{CSV_ROW}\n"))
    assert result.errors == []
    assert result.total_count == 1
    vuln = result.vulnerabilities[0]
    assert vuln.title == "Medium Strength Cipher Suites"
    assert vuln.severity == "medium"
    assert vuln.scanner_id == "42873"
    assert vuln.cve_id == "CVE-2016-2183"
    assert vuln.cvss_score == 5.0
    assert vuln.asset_port == 443
    assert vuln.solution == "Reconfigure the service"


def test_a_byte_order_mark_does_not_swallow_the_first_column(tmp_path):
    """Was: the BOM landed in the first column's NAME, so lookups of it missed.

    Here the first column is "Plugin ID", so the visible loss is the scanner id
    — the field an analyst uses to look the finding up.
    """
    path = write_bytes(tmp_path, "bom.csv", b"\xef\xbb\xbf" + f"{CSV_HEADER}\n{CSV_ROW}\n".encode())
    result = NessusParser().parse(path)
    assert result.total_count == 1
    assert result.vulnerabilities[0].scanner_id == "42873"


def test_a_byte_order_mark_on_a_title_first_export_does_not_lose_every_row(tmp_path):
    """The worst shape of the same bug: zero findings, no error, no warning.

    Column order is user-configurable, and with "Name" first the BOM broke the
    TITLE lookup. `_parse_csv_row` skips a row with no title, so every row was
    dropped and the client received a clean report from a scan that had found
    things. That is the one failure mode a scanner must never have.
    """
    body = (
        "Name,Plugin ID,Risk,Host,Port\nMedium Strength Cipher Suites,42873,Medium,10.0.0.1,443\n"
    )
    path = write_bytes(tmp_path, "bom2.csv", b"\xef\xbb\xbf" + body.encode())
    result = NessusParser().parse(path)
    assert result.total_count == 1
    assert result.vulnerabilities[0].title == "Medium Strength Cipher Suites"


def test_a_plugin_output_larger_than_the_default_field_cap_does_not_lose_the_export(tmp_path):
    """Was: csv's 128 KB field cap raised, the blanket handler caught it, and
    the whole export came back as zero findings plus one error line."""
    huge = "A" * 200_000
    row = f"{CSV_ROW.rsplit(',', 1)[0]},{huge}"
    result = NessusParser().parse(write(tmp_path, "big.csv", f"{CSV_HEADER}\n{row}\n"))
    assert result.errors == []
    assert result.total_count == 1
    assert len(result.vulnerabilities[0].evidence) == 200_000


def test_the_field_cap_is_restored_after_the_read(tmp_path):
    """csv.field_size_limit is process-global — one ingest must not silently
    change the limit every later ingest in the process runs under."""
    import csv

    before = csv.field_size_limit()
    NessusParser().parse(write(tmp_path, "s.csv", f"{CSV_HEADER}\n{CSV_ROW}\n"))
    assert csv.field_size_limit() == before


def test_the_cap_is_restored_even_when_the_read_fails(tmp_path):
    import csv

    before = csv.field_size_limit()
    NessusParser().parse(tmp_path / "does-not-exist.csv")
    assert csv.field_size_limit() == before


def test_a_quoted_newline_inside_a_cell_stays_one_row(tmp_path):
    """Without newline="" on the file handle, a wrapped description splits the
    row and the tail becomes a second, malformed record."""
    body = f'{CSV_HEADER}\n42873,CVE-2016-2183,5.0,Medium,10.0.0.1,tcp,443,Cipher Suites,"line one\nline two",fix,out\n'
    result = NessusParser().parse(write(tmp_path, "wrap.csv", body))
    assert result.total_count == 1
    assert result.vulnerabilities[0].description == "line one\nline two"


def test_an_export_whose_rows_all_vanish_says_so_rather_than_reporting_zero(tmp_path):
    """A confident zero is indistinguishable from a clean scan. Every silent
    column mismatch takes this shape, so it has to be visible."""
    result = NessusParser().parse(write(tmp_path, "odd.csv", "Foo,Bar\n1,2\n3,4\n"))
    assert result.total_count == 0
    assert len(result.warnings) == 1
    assert "2 row(s) read" in result.warnings[0]
    assert "Foo, Bar" in result.warnings[0]


def test_a_header_only_export_is_not_reported_as_a_mismatch(tmp_path):
    """No rows read is a genuinely empty scan, not a broken mapping."""
    result = NessusParser().parse(write(tmp_path, "empty.csv", f"{CSV_HEADER}\n"))
    assert result.total_count == 0
    assert result.warnings == []
    assert result.errors == []


def test_the_columns_that_were_read_are_recorded(tmp_path):
    result = NessusParser().parse(write(tmp_path, "s.csv", f"{CSV_HEADER}\n{CSV_ROW}\n"))
    assert result.scan_metadata["rows_read"] == 1
    assert "Plugin ID" in result.scan_metadata["columns"]


def test_a_missing_csv_is_an_error_not_a_crash(tmp_path):
    result = NessusParser().parse(tmp_path / "nope.csv")
    assert result.total_count == 0
    assert len(result.errors) == 1


# ---------------------------------------------------------------------------
# Vulnerability scan export — XML
# ---------------------------------------------------------------------------


def nessus_xml(report_item: str) -> str:
    return f"""<?xml version="1.0"?>
<NessusClientData_v2>
  <Policy><policyName>Full Audit</policyName></Policy>
  <Report>
    <ReportHost name="10.255.255.1">
      <HostProperties>
        <tag name="host-ip">10.255.255.1</tag>
        <tag name="host-fqdn">host1.selftest.invalid</tag>
        <tag name="operating-system">Linux Kernel 5.15</tag>
        <tag name="HOST_START">Mon Sep  6 10:00:00 2026</tag>
      </HostProperties>
      {report_item}
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""


def test_an_xml_export_maps_onto_findings(tmp_path):
    item = """<ReportItem pluginID="42873" pluginName="Medium Strength Ciphers"
        severity="2" port="443" protocol="tcp" svc_name="https" pluginFamily="General">
        <description>Weak ciphers are enabled.</description>
        <solution>Reconfigure the service.</solution>
        <cve>CVE-2016-2183</cve>
        <cvss3_base_score>7.5</cvss3_base_score>
        <cvss3_vector>AV:N/AC:L</cvss3_vector>
        <plugin_output>observed cipher list</plugin_output>
      </ReportItem>"""
    result = NessusParser().parse(write(tmp_path, "s.nessus", nessus_xml(item)))
    assert result.errors == []
    vuln = result.vulnerabilities[0]
    assert vuln.title == "Medium Strength Ciphers"
    assert vuln.severity == "medium"
    assert vuln.asset_name == "host1.selftest.invalid"
    assert vuln.asset_ip == "10.255.255.1"
    assert vuln.asset_port == 443
    assert vuln.cvss_score == 7.5
    assert vuln.evidence == "observed cipher list"
    assert result.scan_metadata["policy_name"] == "Full Audit"


def test_every_cve_on_a_plugin_survives_not_just_the_first(tmp_path):
    """Was: find() returned one <cve> and the rest vanished — on exactly the
    plugins worth chasing, which are the ones citing several."""
    item = """<ReportItem pluginID="1" pluginName="Multiple Issues" severity="4" port="443">
        <cve>CVE-2021-0001</cve><cve>CVE-2021-0002</cve><cve>CVE-2021-0003</cve>
      </ReportItem>"""
    result = NessusParser().parse(write(tmp_path, "m.nessus", nessus_xml(item)))
    assert result.vulnerabilities[0].cve_id == "CVE-2021-0001, CVE-2021-0002, CVE-2021-0003"


def test_an_empty_v3_score_does_not_shadow_a_real_v2_score(tmp_path):
    """Was: the fallback keyed off the ELEMENT being absent, but the scanner
    emits an empty <cvss3_base_score/> for v2-only plugins — so the finding
    reached the client carrying no score at all."""
    item = """<ReportItem pluginID="1" pluginName="Legacy Finding" severity="3" port="443">
        <cvss3_base_score></cvss3_base_score>
        <cvss_base_score>7.5</cvss_base_score>
      </ReportItem>"""
    result = NessusParser().parse(write(tmp_path, "v2.nessus", nessus_xml(item)))
    assert result.vulnerabilities[0].cvss_score == 7.5


def test_a_v3_score_still_wins_when_it_is_present(tmp_path):
    item = """<ReportItem pluginID="1" pluginName="Scored Both Ways" severity="4" port="443">
        <cvss3_base_score>9.8</cvss3_base_score>
        <cvss_base_score>7.5</cvss_base_score>
      </ReportItem>"""
    result = NessusParser().parse(write(tmp_path, "b.nessus", nessus_xml(item)))
    assert result.vulnerabilities[0].cvss_score == 9.8


def test_an_unparseable_score_falls_through_to_the_next_rather_than_raising(tmp_path):
    item = """<ReportItem pluginID="1" pluginName="Odd Score" severity="3" port="443">
        <cvss3_base_score>N/A</cvss3_base_score>
        <cvss_base_score>6.1</cvss_base_score>
      </ReportItem>"""
    result = NessusParser().parse(write(tmp_path, "n.nessus", nessus_xml(item)))
    assert result.vulnerabilities[0].cvss_score == 6.1


@pytest.mark.parametrize(
    ("code", "expected"),
    [("0", "info"), ("1", "low"), ("2", "medium"), ("3", "high"), ("4", "critical")],
)
def test_each_severity_code_maps_to_its_band(tmp_path, code, expected):
    item = f'<ReportItem pluginID="1" pluginName="Finding" severity="{code}" port="1"/>'
    result = NessusParser().parse(write(tmp_path, f"s{code}.nessus", nessus_xml(item)))
    assert result.vulnerabilities[0].severity == expected


def test_an_item_with_no_plugin_name_is_skipped_not_reported_blank(tmp_path):
    item = '<ReportItem pluginID="1" severity="3" port="443"/>'
    result = NessusParser().parse(write(tmp_path, "x.nessus", nessus_xml(item)))
    assert result.total_count == 0


def test_the_host_start_time_becomes_the_scan_date(tmp_path):
    item = '<ReportItem pluginID="1" pluginName="Finding" severity="1" port="1"/>'
    result = NessusParser().parse(write(tmp_path, "d.nessus", nessus_xml(item)))
    assert result.scan_date is not None
    assert result.scan_date.year == 2026


def test_malformed_vulnerability_xml_is_an_error_not_a_crash(tmp_path):
    result = NessusParser().parse(write(tmp_path, "bad.nessus", "<NessusClientData_v2>"))
    assert result.total_count == 0
    assert len(result.errors) == 1


# ---------------------------------------------------------------------------
# Web-application scan export
# ---------------------------------------------------------------------------

WEB_XML = """<?xml version="1.0"?>
<OWASPZAPReport version="2.14.0" generated="Mon, 6 Sep 2026 10:00:00">
  <site name="http://app.selftest.invalid" host="app.selftest.invalid" port="80">
    <alerts>
      <alertitem>
        <alert>SQL Injection</alert>
        <riskcode>3</riskcode>
        <riskdesc>High (Medium)</riskdesc>
        <pluginid>40018</pluginid>
        <cweid>89</cweid>
        <desc>&lt;p&gt;SQL injection may be possible.&lt;/p&gt;</desc>
        <solution>&lt;p&gt;Use parameterised queries.&lt;/p&gt;</solution>
        <evidence>' OR '1'='1</evidence>
        <instances>
          <instance><uri>http://app.selftest.invalid/login</uri></instance>
          <instance><uri>http://app.selftest.invalid/search</uri></instance>
        </instances>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>
"""


def test_a_web_xml_export_maps_onto_findings(tmp_path):
    result = ZAPParser().parse(write(tmp_path, "z.xml", WEB_XML))
    assert result.errors == []
    vuln = result.vulnerabilities[0]
    assert vuln.title == "SQL Injection"
    assert vuln.severity == "high"
    assert vuln.cwe_id == "89"
    assert vuln.scanner_id == "40018"
    assert vuln.asset_url == "http://app.selftest.invalid/login"
    assert vuln.asset_port == 80
    assert vuln.raw_data["count"] == 2


def test_the_report_timestamp_is_read_not_dropped(tmp_path):
    """Was: the reports stamp themselves in RFC-2822, fromisoformat raised on
    every one, and every ingested report claimed no scan date."""
    result = ZAPParser().parse(write(tmp_path, "z.xml", WEB_XML))
    assert result.scan_date is not None
    assert (result.scan_date.year, result.scan_date.month, result.scan_date.day) == (2026, 9, 6)


def test_an_iso_timestamp_still_works(tmp_path):
    body = WEB_XML.replace(
        'generated="Mon, 6 Sep 2026 10:00:00"', 'generated="2026-09-06T10:00:00"'
    )
    result = ZAPParser().parse(write(tmp_path, "iso.xml", body))
    assert result.scan_date is not None
    assert result.scan_date.year == 2026


def test_an_unreadable_timestamp_is_dropped_rather_than_raising(tmp_path):
    body = WEB_XML.replace('generated="Mon, 6 Sep 2026 10:00:00"', 'generated="whenever"')
    result = ZAPParser().parse(write(tmp_path, "bad.xml", body))
    assert result.scan_date is None
    assert result.total_count == 1  # the findings still land


def test_html_markup_is_stripped_from_client_facing_text(tmp_path):
    vuln = ZAPParser().parse(write(tmp_path, "z.xml", WEB_XML)).vulnerabilities[0]
    assert vuln.description == "SQL injection may be possible."
    assert vuln.solution == "Use parameterised queries."


def test_a_risk_written_as_a_word_is_not_downgraded_to_informational(tmp_path):
    """The defect with the worst consequence in this file.

    The API-shaped export writes `"risk": "High"` and no riskcode. The code map
    knows only the numbers, so every alert fell through to its default and a
    SQL injection was reported to the client as informational — a finding that
    exists, is graded, and is graded wrong.
    """
    body = json.dumps(
        {
            "alerts": [
                {
                    "alert": "SQL Injection",
                    "risk": "High",
                    "desc": "d",
                    "solution": "s",
                    "pluginid": "40018",
                    "cweid": "89",
                }
            ]
        }
    )
    vuln = ZAPParser().parse(write(tmp_path, "api.json", body)).vulnerabilities[0]
    assert vuln.severity == "high"


@pytest.mark.parametrize(
    ("word", "expected"),
    [("High", "high"), ("Medium", "medium"), ("Low", "low"), ("Informational", "info")],
)
def test_each_risk_word_maps_to_its_band(tmp_path, word, expected):
    body = json.dumps({"alerts": [{"alert": "Finding", "risk": word}]})
    result = ZAPParser().parse(write(tmp_path, f"{expected}.json", body))
    assert result.vulnerabilities[0].severity == expected


def test_an_empty_riskcode_defers_to_the_risk_word(tmp_path):
    """An empty riskcode is absent, not risk 0."""
    body = json.dumps({"alerts": [{"alert": "Finding", "riskcode": "", "risk": "High"}]})
    result = ZAPParser().parse(write(tmp_path, "e.json", body))
    assert result.vulnerabilities[0].severity == "high"


def test_a_numeric_riskcode_still_wins(tmp_path):
    body = json.dumps(
        {"site": [{"@name": "http://x", "alerts": [{"alert": "F", "riskcode": "3"}]}]}
    )
    result = ZAPParser().parse(write(tmp_path, "t.json", body))
    assert result.vulnerabilities[0].severity == "high"


def test_a_risk_word_in_the_xml_export_is_also_honoured(tmp_path):
    body = WEB_XML.replace("<riskcode>3</riskcode>", "<risk>High</risk>")
    result = ZAPParser().parse(write(tmp_path, "w.xml", body))
    assert result.vulnerabilities[0].severity == "high"


def test_an_unrecognised_risk_is_informational_rather_than_an_error(tmp_path):
    body = json.dumps({"alerts": [{"alert": "Finding", "risk": "banana"}]})
    result = ZAPParser().parse(write(tmp_path, "u.json", body))
    assert result.vulnerabilities[0].severity == "info"
    assert result.errors == []


def test_the_traditional_json_report_shape_maps_onto_findings(tmp_path):
    body = json.dumps(
        {
            "site": [
                {
                    "@name": "http://app.selftest.invalid",
                    "alerts": [
                        {
                            "alert": "Cross Site Scripting",
                            "riskcode": "3",
                            "desc": "<p>Reflected.</p>",
                            "instances": [{"uri": "http://app.selftest.invalid/q"}],
                            "cweid": "79",
                        }
                    ],
                }
            ]
        }
    )
    result = ZAPParser().parse(write(tmp_path, "trad.json", body))
    vuln = result.vulnerabilities[0]
    assert vuln.title == "Cross Site Scripting"
    assert vuln.severity == "high"
    assert vuln.asset_url == "http://app.selftest.invalid/q"
    assert vuln.description == "Reflected."


def test_an_alert_with_no_title_is_skipped(tmp_path):
    body = json.dumps({"alerts": [{"riskcode": "3", "desc": "no title"}]})
    assert ZAPParser().parse(write(tmp_path, "nt.json", body)).total_count == 0


def test_malformed_web_json_is_an_error_not_a_crash(tmp_path):
    result = ZAPParser().parse(write(tmp_path, "bad.json", "{not json"))
    assert result.total_count == 0
    assert len(result.errors) == 1


def test_malformed_web_xml_is_an_error_not_a_crash(tmp_path):
    result = ZAPParser().parse(write(tmp_path, "bad.xml", "<OWASPZAPReport>"))
    assert result.total_count == 0
    assert len(result.errors) == 1


def test_a_severity_misgrade_would_change_the_reported_totals(tmp_path):
    """Ties the severity fix to the number a client actually reads.

    The report's summary counts by band, so an alert graded info instead of
    high does not just read wrong on its own row — it moves the headline.
    """
    body = json.dumps(
        {
            "alerts": [
                {"alert": "SQL Injection", "risk": "High"},
                {"alert": "Info Leak", "risk": "Low"},
            ]
        }
    )
    result = ZAPParser().parse(write(tmp_path, "counts.json", body))
    assert result.severity_counts["high"] == 1
    assert result.severity_counts["low"] == 1
    assert result.severity_counts["info"] == 0
