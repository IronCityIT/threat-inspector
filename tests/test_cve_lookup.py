"""Correlating exposed service versions with known CVEs.

`cve_lookup` turns scanner output into per-CVE findings with CVSS-derived
severities. Both halves of that are consequential: a CVE that does not survive
parsing is a known vulnerability missing from a client's report, and a severity
derived wrongly is a client triaging the wrong thing first. It sat at 75%
coverage.

**A CVE the scanner reported without a score was dropped entirely.**

The pattern required a score — `(CVE-\\d{4}-\\d{4,7})\\s+([\\d.]+)` — so anything
not followed by a number matched nothing:

    CVE-2021-0001  https://vulners.com/cve/CVE-2021-0001   -> no finding
    CVE-2021-0004  n/a  https://...                        -> no finding

A published CVE affecting a client's host disappearing from their report
because the scanner did not attach a number is the wrong trade in every
direction.

**And a CVE on two services was reported once, with no indication of either.**

De-duplication was per CVE across the whole host. The same CVE genuinely can
affect two services — one on 22, another on 443 — and collapsing them lost the
second occurrence *and* left the survivor saying nothing about which service it
was about. The findings carried no port at all.

Measured on one realistic scan of a host with two services:

    before: 3 findings    after: 5 findings, each naming its port and service
"""

from __future__ import annotations

import pytest
from modules.cve_lookup import UNSCORED_SEVERITY, _severity_for, parse_cves

TARGET = "10.255.255.1"

# One host, two services, and a CVE that appears under both.
TWO_SERVICES = """Nmap scan report for 10.255.255.1
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
| vulners:
|   cpe:/a:openbsd:openssh:8.2p1:
|       CVE-2020-15778  6.8     https://vulners.com/cve/CVE-2020-15778
|       CVE-2021-41617  4.4     https://vulners.com/cve/CVE-2021-41617
443/tcp open https   nginx 1.18.0
| vulners:
|   cpe:/a:nginx:nginx:1.18.0:
|       CVE-2021-23017  9.4     https://vulners.com/cve/CVE-2021-23017
|_      CVE-2020-15778  6.8     https://vulners.com/cve/CVE-2020-15778
"""


def by_cve(raw: str) -> dict[str, list]:
    findings: dict[str, list] = {}
    for finding in parse_cves(raw, TARGET):
        findings.setdefault(finding.evidence["cve"], []).append(finding)
    return findings


# ---------------------------------------------------------------------------
# A CVE without a score is still a CVE
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        "|       CVE-2021-0001  https://vulners.com/cve/CVE-2021-0001",
        "|       CVE-2021-0001",
        "|       CVE-2021-0001  n/a  https://vulners.com/cve/CVE-2021-0001",
    ],
)
def test_a_cve_the_scanner_did_not_score_is_still_reported(line):
    """The regression. Every one of these produced nothing at all."""
    findings = parse_cves(line, TARGET)
    assert len(findings) == 1
    assert findings[0].evidence["cve"] == "CVE-2021-0001"


def test_an_unscored_cve_records_that_no_score_was_reported():
    finding = parse_cves("CVE-2021-0001 https://x", TARGET)[0]
    assert finding.evidence["cvss"] is None
    assert finding.evidence["cvss_reported"] is False


def test_an_unscored_cve_is_not_filed_as_informational():
    """ "info" reads as "not a problem" and would hide a real CVE from anyone
    triaging medium-and-above, which is most people."""
    finding = parse_cves("CVE-2021-0001 https://x", TARGET)[0]
    assert finding.severity == UNSCORED_SEVERITY
    assert finding.severity != "info"


def test_an_unscored_cve_says_its_severity_is_a_placeholder():
    """Showing a severity without saying it was not measured is the same
    problem in reverse — a guess presented as a finding."""
    finding = parse_cves("CVE-2021-0001 https://x", TARGET)[0]
    assert "no CVSS score" in finding.detail
    assert "placeholder" in finding.detail


def test_a_scored_cve_does_not_claim_to_be_a_placeholder():
    finding = parse_cves("CVE-2021-3156 9.8 https://x", TARGET)[0]
    assert finding.evidence["cvss_reported"] is True
    assert "placeholder" not in finding.detail


# ---------------------------------------------------------------------------
# Which service is affected
# ---------------------------------------------------------------------------


def test_the_same_cve_on_two_services_is_two_findings():
    """It used to be one, with no indication of either service."""
    assert len(by_cve(TWO_SERVICES)["CVE-2020-15778"]) == 2


def test_each_finding_names_the_service_it_was_found_under():
    findings = by_cve(TWO_SERVICES)["CVE-2020-15778"]
    located = {(f.evidence["port"], f.evidence["service"]) for f in findings}
    assert located == {(22, "ssh"), (443, "https")}


def test_the_protocol_is_recorded():
    assert by_cve(TWO_SERVICES)["CVE-2021-23017"][0].evidence["protocol"] == "tcp"


def test_the_detail_names_the_port_a_reader_should_look_at():
    finding = by_cve(TWO_SERVICES)["CVE-2021-23017"][0]
    assert "443/tcp" in finding.detail


def test_a_cve_repeated_under_one_service_is_reported_once():
    raw = (
        "22/tcp open ssh OpenSSH 8.2p1\n"
        "|  CVE-2020-15778 6.8 https://x\n"
        "|  CVE-2020-15778 6.8 https://x\n"
    )
    assert len(parse_cves(raw, TARGET)) == 1


def test_output_with_no_port_lines_still_produces_findings():
    """Not every scanner emits a port table above the CVE list."""
    findings = parse_cves("  CVE-2021-3156  9.8  https://x", TARGET)
    assert len(findings) == 1
    assert findings[0].evidence["port"] is None


def test_a_closed_port_does_not_become_the_context():
    """Only an `open` service starts a block; a filtered one is not a service."""
    raw = "80/tcp filtered http\n22/tcp open ssh OpenSSH\n|  CVE-2021-3156 9.8 https://x\n"
    assert parse_cves(raw, TARGET)[0].evidence["port"] == 22


def test_udp_services_are_recognised():
    raw = "161/udp open snmp\n|  CVE-2021-3156 9.8 https://x\n"
    finding = parse_cves(raw, TARGET)[0]
    assert (finding.evidence["port"], finding.evidence["protocol"]) == (161, "udp")


# ---------------------------------------------------------------------------
# Score to severity — the CVSS v3 bands
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (10.0, "critical"),
        (9.0, "critical"),
        (8.9, "high"),
        (7.0, "high"),
        (6.9, "medium"),
        (4.0, "medium"),
        (3.9, "low"),
        (0.1, "low"),
        (0.0, "info"),
    ],
)
def test_the_bands_match_the_cvss_v3_ranges(score, expected):
    """Critical 9.0-10.0, High 7.0-8.9, Medium 4.0-6.9, Low 0.1-3.9, None 0.0."""
    assert _severity_for(score) == expected


def test_an_absent_score_takes_the_placeholder_severity():
    assert _severity_for(None) == UNSCORED_SEVERITY


@pytest.mark.parametrize(
    ("line", "expected_score"),
    [
        ("CVE-2021-3156 9.8 https://x", 9.8),
        ("CVE-2021-3156\t7.5\thttps://x", 7.5),
        ("|       CVE-2021-3156  10.0    https://x", 10.0),
        ("CVE-2021-3156 7 https://x", 7.0),
    ],
)
def test_a_score_is_read_however_the_line_is_spaced(line, expected_score):
    assert parse_cves(line, TARGET)[0].evidence["cvss"] == expected_score


def test_a_zero_score_is_informational_not_a_placeholder():
    """CVSS 0.0 genuinely means "None". That is a measurement, not a gap."""
    finding = parse_cves("CVE-2021-3156 0.0 https://x", TARGET)[0]
    assert finding.severity == "info"
    assert finding.evidence["cvss_reported"] is True


# ---------------------------------------------------------------------------
# What is not a CVE
# ---------------------------------------------------------------------------


def test_a_line_with_no_cve_produces_nothing():
    assert parse_cves("22/tcp open ssh OpenSSH 8.2p1\n| vulners:\n", TARGET) == []


def test_empty_output_produces_nothing():
    assert parse_cves("", TARGET) == []


def test_a_non_cve_identifier_is_not_reported_as_one():
    """vulners also lists EXPLOITDB and other identifiers. This module reports
    CVEs; claiming an exploit id is a CVE would be wrong."""
    raw = "|       EXPLOITDB:12345 7.5     https://vulners.com/exploitdb/EXPLOITDB:12345\n"
    assert parse_cves(raw, TARGET) == []


def test_a_malformed_cve_identifier_is_not_matched():
    assert parse_cves("CVE-21-1 9.8 https://x", TARGET) == []


def test_every_finding_is_attributed_to_the_target():
    for finding in parse_cves(TWO_SERVICES, TARGET):
        assert finding.target == TARGET
        assert finding.module == "cve_lookup"


def test_the_realistic_scan_yields_every_cve_it_contains():
    """The end-to-end count, against output shaped like the real thing."""
    findings = parse_cves(TWO_SERVICES, TARGET)
    assert len(findings) == 4
    assert {f.evidence["cve"] for f in findings} == {
        "CVE-2020-15778",
        "CVE-2021-41617",
        "CVE-2021-23017",
    }
