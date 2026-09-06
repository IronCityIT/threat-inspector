"""Parsing real export files — the ingestion path for untrusted client uploads.

tests/test_parsers.py covered the registry and severity normalisation only, so
the two parsers that actually read a scan export sat at 12% (network) and 15%
(vulnerability spreadsheet) line coverage. Both are production code: the
`nmap_ingest` and `qualys_ingest` file modules delegate straight to them, and
every byte they see came out of a file a client uploaded.

That makes two things worth pinning here: that the mapping from export to
finding is what we think it is, and that hostile or malformed input is reported
as an error rather than crashing the ingest or reaching out to the network.

These use the parsers by their internal names deliberately — the white-label
rule covers client-facing surfaces, not the code that implements them.
"""

from __future__ import annotations

import pytest

from threat_inspector.parsers.nmap import NmapParser
from threat_inspector.parsers.qualys import QualysParser

# ---------------------------------------------------------------------------
# Network scan export — XML
# ---------------------------------------------------------------------------

XML_WITH_VULN_TABLE = """<?xml version="1.0"?>
<nmaprun version="7.94" args="nmap -sV --script vuln 10.255.255.1" start="1600000000">
  <host>
    <address addr="10.255.255.1" addrtype="ipv4"/>
    <hostnames><hostname name="host1.selftest.invalid"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <service name="https" product="nginx" version="1.18.0"/>
        <script id="vulners" output="CVE-2021-23017 found">
          <table>
            <elem key="title">Resolver off-by-one buffer overflow</elem>
            <elem key="cve">CVE-2021-23017</elem>
            <elem key="cvss">9.4</elem>
            <elem key="solution">Upgrade the web server.</elem>
          </table>
        </script>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def write(tmp_path, name: str, body: str):
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def test_a_vulnerability_table_becomes_a_finding(tmp_path):
    result = NmapParser().parse(write(tmp_path, "scan.xml", XML_WITH_VULN_TABLE))
    assert result.errors == []
    assert len(result.vulnerabilities) == 1

    v = result.vulnerabilities[0]
    assert v.title == "Resolver off-by-one buffer overflow"
    assert v.cve_id == "CVE-2021-23017"
    assert v.cvss_score == 9.4
    assert v.severity == "critical"  # 9.4 -> critical
    assert v.asset_ip == "10.255.255.1"
    assert v.asset_name == "host1.selftest.invalid"  # hostname wins over IP
    assert v.asset_port == 443
    assert v.solution == "Upgrade the web server."
    assert v.raw_data["service"] == "https"
    assert v.raw_data["product"] == "nginx"
    assert v.raw_data["protocol"] == "tcp"


def test_scan_metadata_and_date_are_carried(tmp_path):
    result = NmapParser().parse(write(tmp_path, "scan.xml", XML_WITH_VULN_TABLE))
    assert result.scanner_type == "nmap"
    assert result.scan_metadata["nmap_version"] == "7.94"
    assert result.scan_metadata["format"] == "xml"
    assert result.scan_date is not None


@pytest.mark.parametrize(
    "cvss,expected",
    [("10.0", "critical"), ("9.0", "critical"), ("7.5", "high"), ("4.0", "medium"), ("1.2", "low")],
)
def test_cvss_score_maps_onto_severity_bands(tmp_path, cvss, expected):
    body = XML_WITH_VULN_TABLE.replace('key="cvss">9.4<', f'key="cvss">{cvss}<')
    result = NmapParser().parse(write(tmp_path, "s.xml", body))
    assert result.vulnerabilities[0].severity == expected


def test_a_non_numeric_cvss_falls_back_rather_than_raising(tmp_path):
    body = XML_WITH_VULN_TABLE.replace('key="cvss">9.4<', 'key="cvss">not-a-score<')
    result = NmapParser().parse(write(tmp_path, "s.xml", body))
    assert result.vulnerabilities[0].severity == "medium"


XML_VULN_SCRIPT_NO_TABLE = """<?xml version="1.0"?>
<nmaprun version="7.94">
  <host>
    <address addr="10.255.255.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <service name="microsoft-ds"/>
        <script id="smb-vuln-ms17-010" output="State: VULNERABLE. Remote code execution. CVE-2017-0143"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_a_vuln_script_without_a_table_still_produces_a_finding(tmp_path):
    result = NmapParser().parse(write(tmp_path, "s.xml", XML_VULN_SCRIPT_NO_TABLE))
    assert len(result.vulnerabilities) == 1
    v = result.vulnerabilities[0]
    assert "smb-vuln-ms17-010" in v.title
    assert v.cve_id == "CVE-2017-0143"
    assert v.severity == "critical"  # "remote code execution" in the output
    assert v.asset_port == 445
    assert v.asset_name == "10.255.255.2"  # no hostname, so the IP stands in


def test_a_non_vulnerability_script_is_not_a_finding(tmp_path):
    """A banner grab is not a vulnerability, and must not be reported as one."""
    body = XML_VULN_SCRIPT_NO_TABLE.replace("smb-vuln-ms17-010", "banner")
    result = NmapParser().parse(write(tmp_path, "s.xml", body))
    assert result.vulnerabilities == []


def test_a_non_numeric_port_does_not_break_the_finding(tmp_path):
    body = XML_VULN_SCRIPT_NO_TABLE.replace('portid="445"', 'portid="unknown"')
    result = NmapParser().parse(write(tmp_path, "s.xml", body))
    assert result.vulnerabilities[0].asset_port is None


def test_a_host_with_no_ports_yields_nothing_and_no_error(tmp_path):
    body = '<?xml version="1.0"?><nmaprun version="7.94"><host>'
    body += '<address addr="10.255.255.3" addrtype="ipv4"/></host></nmaprun>'
    result = NmapParser().parse(write(tmp_path, "s.xml", body))
    assert result.vulnerabilities == []
    assert result.errors == []


# ---------------------------------------------------------------------------
# Malformed and hostile XML
# ---------------------------------------------------------------------------


def test_malformed_xml_is_an_error_not_a_crash(tmp_path):
    result = NmapParser().parse(write(tmp_path, "s.xml", "<nmaprun><host>truncated"))
    assert result.vulnerabilities == []
    assert result.errors and "parse error" in result.errors[0].lower()


def test_an_empty_file_is_an_error_not_a_crash(tmp_path):
    result = NmapParser().parse(write(tmp_path, "s.xml", ""))
    assert result.vulnerabilities == []
    assert result.errors


def test_an_external_entity_is_refused(tmp_path):
    """XXE: the parser must not read a local file on the ingest host.

    ElementTree refuses external entities, and this pins that — swapping in a
    parser that resolves them would turn an uploaded export into arbitrary
    local file disclosure.
    """
    body = (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>\n'
        '<nmaprun version="7.94"><host><address addr="&xxe;" addrtype="ipv4"/></host></nmaprun>\n'
    )
    result = NmapParser().parse(write(tmp_path, "xxe.xml", body))
    assert result.vulnerabilities == []
    assert result.errors and "external entity" in result.errors[0].lower()


def test_nested_entity_expansion_is_contained(tmp_path):
    """Billion laughs: an upload must not be able to exhaust ingest memory."""
    body = (
        '<?xml version="1.0"?>\n<!DOCTYPE nmaprun [\n'
        '<!ENTITY a "aaaaaaaaaa">\n'
        '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">\n'
        '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">\n'
        '<!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">\n'
        '<!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">\n'
        '<!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">\n]>\n'
        '<nmaprun version="7.94"><host><address addr="&f;"/></host></nmaprun>\n'
    )
    result = NmapParser().parse(write(tmp_path, "boom.xml", body))
    # Either it refuses the entities or it expands them harmlessly; what must
    # not happen is a hang or an unhandled exception reaching the caller.
    assert result.vulnerabilities == []


# ---------------------------------------------------------------------------
# Network scan export — text format
# ---------------------------------------------------------------------------

TXT_SCAN = """Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.255.255.4
Host is up (0.00021s latency).
PORT    STATE SERVICE
445/tcp open  microsoft-ds
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1
|     References: CVE-2017-0143

Nmap done: 1 IP address scanned
"""


def test_the_text_format_reports_a_vulnerable_marker(tmp_path):
    result = NmapParser().parse(write(tmp_path, "scan.txt", TXT_SCAN))
    assert result.scan_metadata["format"] == "txt"
    assert len(result.vulnerabilities) >= 1
    v = result.vulnerabilities[0]
    assert v.severity == "high"
    assert v.cve_id == "CVE-2017-0143"
    assert v.asset_ip == "10.255.255.4"
    assert v.scanner_id == "nmap-vuln-script"


def test_a_clean_text_scan_reports_nothing(tmp_path):
    clean = "Nmap scan report for 10.255.255.5\n80/tcp open http\nNmap done\n"
    result = NmapParser().parse(write(tmp_path, "clean.txt", clean))
    assert result.vulnerabilities == []
    assert result.errors == []


def test_a_hostname_target_is_not_recorded_as_an_ip(tmp_path):
    body = TXT_SCAN.replace("10.255.255.4", "host.selftest.invalid")
    result = NmapParser().parse(write(tmp_path, "scan.txt", body))
    v = result.vulnerabilities[0]
    assert v.asset_name == "host.selftest.invalid"
    assert v.asset_ip == ""


def test_a_missing_file_is_an_error_not_a_crash(tmp_path):
    result = NmapParser().parse(tmp_path / "does-not-exist.txt")
    assert result.vulnerabilities == []
    assert result.errors


# ---------------------------------------------------------------------------
# Vulnerability spreadsheet export — CSV
# ---------------------------------------------------------------------------

QUALYS_CSV = """QID,Vulnerability Title,Severity,Description,DNS,IP,Port,CVE ID,CVSS Score,Solution,Results
38657,Deprecated TLS protocol negotiated,High,The endpoint negotiates TLS 1.0.,\
host2.selftest.invalid,10.255.255.6,443,CVE-2011-3389,7.4,Disable TLS 1.0.,TLSv1 accepted
11827,HTTP security header missing,Low,No Strict-Transport-Security header.,\
host2.selftest.invalid,10.255.255.6,80,,3.1,Add the header.,header absent
"""


def test_a_spreadsheet_export_maps_onto_findings(tmp_path):
    result = QualysParser().parse(write(tmp_path, "export.csv", QUALYS_CSV))
    assert result.errors == []
    assert len(result.vulnerabilities) == 2

    high = result.vulnerabilities[0]
    assert high.title == "Deprecated TLS protocol negotiated"
    assert high.severity == "high"
    assert high.scanner_severity == "High"  # the vendor's own wording is kept
    assert high.asset_name == "host2.selftest.invalid"
    assert high.asset_ip == "10.255.255.6"
    assert high.asset_port == 443
    assert high.cve_id == "CVE-2011-3389"
    assert high.cvss_score == 7.4
    assert high.solution == "Disable TLS 1.0."
    assert high.evidence == "TLSv1 accepted"
    assert high.scanner_id == "38657"


def test_row_metadata_records_what_was_read(tmp_path):
    result = QualysParser().parse(write(tmp_path, "export.csv", QUALYS_CSV))
    assert result.scanner_type == "qualys"
    assert result.scan_metadata["total_rows"] == 2
    assert "Vulnerability Title" in result.scan_metadata["columns"]


def test_alternative_column_spellings_are_recognised(tmp_path):
    """Exports vary; the mapping table exists so the caller does not have to."""
    body = (
        "Title,Risk,IP Address,Remediation\nWeak cipher suite,Critical,10.255.255.7,Reconfigure.\n"
    )
    result = QualysParser().parse(write(tmp_path, "alt.csv", body))
    assert len(result.vulnerabilities) == 1
    v = result.vulnerabilities[0]
    assert v.title == "Weak cipher suite"
    assert v.severity == "critical"
    assert v.asset_ip == "10.255.255.7"
    assert v.solution == "Reconfigure."


def test_column_matching_is_case_insensitive(tmp_path):
    body = "title,severity\nSomething,Medium\n"
    result = QualysParser().parse(write(tmp_path, "lower.csv", body))
    assert result.vulnerabilities[0].severity == "medium"


def test_a_row_with_no_title_is_skipped_not_reported_blank(tmp_path):
    body = QUALYS_CSV + "99999,,Low,No title at all,h,10.255.255.6,80,,1.0,x,y\n"
    result = QualysParser().parse(write(tmp_path, "export.csv", body))
    assert len(result.vulnerabilities) == 2
    assert all(v.title for v in result.vulnerabilities)


def test_blank_optional_cells_become_empty_rather_than_the_string_nan(tmp_path):
    """pandas turns a blank cell into NaN; 'nan' must never reach a report."""
    result = QualysParser().parse(write(tmp_path, "export.csv", QUALYS_CSV))
    low = result.vulnerabilities[1]
    assert low.cve_id == ""
    assert "nan" not in low.to_dict().values()


def test_a_non_numeric_score_or_port_does_not_lose_the_row(tmp_path):
    body = "Title,Severity,CVSS Score,Port\nOdd row,High,not-a-score,not-a-port\n"
    result = QualysParser().parse(write(tmp_path, "odd.csv", body))
    assert len(result.vulnerabilities) == 1
    assert result.vulnerabilities[0].cvss_score is None
    assert result.vulnerabilities[0].asset_port is None


def test_a_header_only_export_yields_nothing_and_no_error(tmp_path):
    result = QualysParser().parse(write(tmp_path, "empty.csv", "Title,Severity\n"))
    assert result.vulnerabilities == []
    assert result.errors == []
    assert result.scan_metadata["total_rows"] == 0


def test_an_unreadable_spreadsheet_is_an_error_not_a_crash(tmp_path):
    path = tmp_path / "corrupt.xlsx"
    path.write_bytes(b"this is definitely not a spreadsheet")
    result = QualysParser().parse(path)
    assert result.vulnerabilities == []
    assert result.errors and "failed to parse" in result.errors[0].lower()


def test_a_missing_spreadsheet_is_an_error_not_a_crash(tmp_path):
    result = QualysParser().parse(tmp_path / "nope.csv")
    assert result.vulnerabilities == []
    assert result.errors


def test_a_score_from_a_script_table_is_a_number_not_text(tmp_path):
    """`cvss_score` is declared `float | None` and the table cell is text.

    It used to be assigned raw, and nothing noticed until the report formatted
    it with `:.1f` and raised. Pinned at the parser so the type is right at the
    source rather than patched at each consumer.
    """
    result = NmapParser().parse(write(tmp_path, "s.xml", XML_WITH_VULN_TABLE))
    assert isinstance(result.vulnerabilities[0].cvss_score, float)


def test_a_parsed_export_can_actually_be_reported(tmp_path):
    """The regression this closes: report generation raised ValueError.

    A network-scan export carrying a CVSS score made POST /api/v1/reports/
    generate fail for that client, with no report produced at all.
    """
    from threat_inspector.reports.html import generate_html_report

    result = NmapParser().parse(write(tmp_path, "s.xml", XML_WITH_VULN_TABLE))
    out = generate_html_report(result.vulnerabilities, tmp_path / "r.html", client_name="Acme")
    assert "9.4" in out.read_text(encoding="utf-8")
