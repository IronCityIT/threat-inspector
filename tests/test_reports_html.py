"""The HTML report is the deliverable a client actually opens.

It had no tests at all (0% coverage) and it built its markup by f-string
interpolation, escaping some values and not others. Everything it renders is
third-party text: `client_name` and `project_name` arrive in the API request
body for POST /api/v1/reports/generate, and a finding's severity, port and
compliance mappings come out of the scan file a client uploaded. Six of those
interpolation sites were unescaped, so a crafted scan export — or just a hostile
client name — put arbitrary markup into a report a consultant then opens.

Reproduced before it was changed:

    severity='high"><script>alert(1)</script>'  -> verbatim in the output
    client_name='<script>alert("client")</script>' -> verbatim in <title>

These tests pin every interpolation site, not just the ones that were broken, so
a future edit that adds a field cannot quietly reintroduce the hole.
"""

from __future__ import annotations

import re

import pytest

from threat_inspector.parsers.base import ParsedVulnerability
from threat_inspector.reports.html import (
    _as_count,
    _escape_html,
    _severity_class,
    generate_html_report,
)

# One payload per HTML context, each with a distinct marker so a failure names
# the exact field that leaked.
SCRIPT = "<script>alert(1)</script>"
ATTR_BREAK = 'x"><img src=y onerror=alert(2)>'


def vuln(**overrides) -> ParsedVulnerability:
    """A minimal valid finding, with fields overridden per test."""
    fields = {
        "title": "Outdated component",
        "severity": "high",
        "description": "A component is out of date.",
        "asset_ip": "10.255.255.1",
        "solution": "Upgrade it.",
    }
    fields.update(overrides)
    return ParsedVulnerability(**fields)


def render(tmp_path, vulns=None, **kwargs) -> str:
    """Generate a report and hand back its markup."""
    out = generate_html_report(
        vulnerabilities=vulns if vulns is not None else [vuln()],
        output_path=tmp_path / "report.html",
        **kwargs,
    )
    return out.read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# It still produces a report
# --------------------------------------------------------------------------


def test_writes_a_file_and_returns_its_path(tmp_path):
    out = generate_html_report([vuln()], tmp_path / "nested" / "r.html", client_name="Acme")
    assert out.exists()
    assert out == tmp_path / "nested" / "r.html"


def test_parent_directory_is_created(tmp_path):
    generate_html_report([vuln()], tmp_path / "a" / "b" / "c" / "r.html")
    assert (tmp_path / "a" / "b" / "c" / "r.html").exists()


def test_report_is_well_formed_and_carries_the_finding(tmp_path):
    html = render(tmp_path, client_name="Acme Corp", project_name="Q3 Assessment")
    assert html.startswith("<!DOCTYPE html>")
    assert html.rstrip().endswith("</html>")
    assert "Acme Corp" in html
    assert "Q3 Assessment" in html
    assert "Outdated component" in html
    assert "Upgrade it." in html


def test_empty_finding_list_still_renders(tmp_path):
    html = render(tmp_path, vulns=[])
    assert "<!DOCTYPE html>" in html
    assert "No critical vulnerabilities were identified" in html


def test_findings_are_ordered_most_severe_first(tmp_path):
    html = render(
        tmp_path,
        vulns=[
            vuln(title="LOW-ONE", severity="low"),
            vuln(title="CRIT-ONE", severity="critical"),
            vuln(title="MED-ONE", severity="medium"),
        ],
    )
    order = [m for m in re.findall(r"(CRIT-ONE|MED-ONE|LOW-ONE)", html)]
    assert order[:3] == ["CRIT-ONE", "MED-ONE", "LOW-ONE"]


def test_unknown_severity_sorts_last_rather_than_raising(tmp_path):
    html = render(
        tmp_path,
        vulns=[
            vuln(title="WEIRD", severity="catastrophic"),
            vuln(title="CRIT", severity="critical"),
        ],
    )
    assert html.index("CRIT") < html.index("WEIRD")


def test_summary_counts_are_derived_when_not_supplied(tmp_path):
    html = render(
        tmp_path,
        vulns=[
            vuln(severity="critical"),
            vuln(severity="critical"),
            vuln(severity="high"),
            vuln(severity="info"),
        ],
    )
    assert "Immediate attention is required" in html
    assert "for 2 critical vulnerabilities" in html


def test_supplied_summary_is_used(tmp_path):
    html = render(
        tmp_path,
        summary={
            "total_vulnerabilities": 99,
            "critical_count": 7,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
        },
    )
    assert ">99<" in html
    assert "for 7 critical vulnerabilities" in html


def test_remediation_and_compliance_can_be_switched_off(tmp_path):
    v = vuln(
        solution="Patch the server.",
        raw_data={"compliance_mappings": [{"framework": "PCI", "requirement": "6.2"}]},
    )
    on = render(tmp_path, vulns=[v], include_remediation=True, include_compliance=True)
    assert "Patch the server." in on
    assert "PCI-6.2" in on

    off = render(tmp_path, vulns=[v], include_remediation=False, include_compliance=False)
    assert "Patch the server." not in off
    assert "PCI-6.2" not in off


def test_only_the_first_fifty_findings_reach_the_summary_table(tmp_path):
    vulns = [vuln(title=f"FIND-{i:03d}", severity="low") for i in range(60)]
    html = render(tmp_path, vulns=vulns)
    table = html.split("<h2>Vulnerability Summary</h2>")[1].split("</table>")[0]
    assert "FIND-000" in table
    assert "FIND-059" not in table
    # Every finding still appears in the detailed section below.
    assert "FIND-059" in html


def test_long_titles_are_truncated_in_the_summary_table(tmp_path):
    html = render(tmp_path, vulns=[vuln(title="T" * 200)])
    table = html.split("<h2>Vulnerability Summary</h2>")[1].split("</table>")[0]
    assert "T" * 80 + "..." in table


# --------------------------------------------------------------------------
# Injection — one test per interpolation site
# --------------------------------------------------------------------------


def test_client_name_is_escaped(tmp_path):
    html = render(tmp_path, client_name=SCRIPT)
    assert SCRIPT not in html
    assert "&lt;script&gt;" in html


def test_project_name_is_escaped(tmp_path):
    html = render(tmp_path, client_name="Acme", project_name=SCRIPT)
    assert SCRIPT not in html


def test_company_name_is_escaped(tmp_path):
    html = render(tmp_path, company_name=SCRIPT)
    assert SCRIPT not in html


def test_finding_severity_is_escaped(tmp_path):
    html = render(tmp_path, vulns=[vuln(severity=SCRIPT)])
    assert SCRIPT not in html


def test_finding_severity_cannot_break_out_of_a_class_attribute(tmp_path):
    html = render(tmp_path, vulns=[vuln(severity=ATTR_BREAK)])
    assert "<img src=y" not in html
    # An unrecognised severity resolves to a known class instead of being
    # interpolated into the attribute.
    assert 'class="vuln-detail info"' in html


def test_asset_port_is_escaped(tmp_path):
    html = render(tmp_path, vulns=[vuln(asset_port=ATTR_BREAK)])
    assert "<img src=y" not in html


def test_compliance_tags_are_escaped(tmp_path):
    html = render(
        tmp_path,
        vulns=[vuln(raw_data={"compliance_mappings": [{"framework": SCRIPT, "requirement": "1"}]})],
    )
    assert SCRIPT not in html


def test_title_description_solution_cve_and_asset_are_escaped(tmp_path):
    html = render(
        tmp_path,
        vulns=[
            vuln(
                title=SCRIPT,
                description=SCRIPT,
                solution=SCRIPT,
                cve_id=SCRIPT,
                asset_ip=SCRIPT,
                asset_name=SCRIPT,
            )
        ],
    )
    assert SCRIPT not in html


def test_no_field_of_a_fully_hostile_finding_reaches_the_document(tmp_path):
    """The belt-and-braces case: every string field carries a payload at once."""
    hostile = ParsedVulnerability(
        title=SCRIPT,
        severity=ATTR_BREAK,
        description=SCRIPT,
        asset_name=SCRIPT,
        asset_ip=SCRIPT,
        asset_port=ATTR_BREAK,
        asset_url=SCRIPT,
        cve_id=SCRIPT,
        cwe_id=SCRIPT,
        cvss_vector=SCRIPT,
        scanner_id=SCRIPT,
        solution=SCRIPT,
        evidence=SCRIPT,
        raw_data={"compliance_mappings": [{"framework": SCRIPT, "requirement": ATTR_BREAK}]},
    )
    html = render(
        tmp_path, vulns=[hostile], client_name=SCRIPT, project_name=SCRIPT, company_name=SCRIPT
    )
    # The payload text may well appear — escaped, as inert content. What must
    # not appear is a live tag, or either payload verbatim.
    assert "<script" not in html
    assert "<img" not in html
    assert SCRIPT not in html
    assert ATTR_BREAK not in html


def test_newlines_in_remediation_become_breaks_but_markup_does_not(tmp_path):
    html = render(tmp_path, vulns=[vuln(solution="Step one\n<script>alert(1)</script>")])
    assert "<br>" in html
    assert SCRIPT not in html


def test_a_hostile_summary_count_cannot_inject(tmp_path):
    html = render(
        tmp_path,
        summary={
            "total_vulnerabilities": SCRIPT,
            "critical_count": SCRIPT,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
        },
    )
    assert SCRIPT not in html


# --------------------------------------------------------------------------
# The helpers, directly
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("critical", "critical"),
        ("HIGH", "high"),
        ("  medium  ", "medium"),
        ("low", "low"),
        ("info", "info"),
        ("catastrophic", "info"),
        ("", "info"),
        (None, "info"),
        ('high"><script>', "info"),
    ],
)
def test_severity_class_resolves_against_the_known_set(raw, expected):
    assert _severity_class(raw) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [(5, 5), ("7", 7), (None, 0), ("not-a-number", 0), (3.9, 3), ([], 0), (True, 0), ({}, 0)],
)
def test_as_count_coerces_or_falls_back_to_zero(raw, expected):
    assert _as_count(raw) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("<", "&lt;"),
        (">", "&gt;"),
        ('"', "&quot;"),
        ("'", "&#x27;"),
        ("&", "&amp;"),
        ("", ""),
        (None, ""),
        (443, "443"),
    ],
)
def test_escape_html_covers_every_dangerous_character(raw, expected):
    assert _escape_html(raw) == expected


def test_escape_html_escapes_ampersands_before_entities():
    """`&` must be replaced first or `<` becomes `&amp;lt;`."""
    assert _escape_html("<a & b>") == "&lt;a &amp; b&gt;"
