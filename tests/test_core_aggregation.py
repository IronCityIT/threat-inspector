"""Aggregation: what survives when two scans describe the same host.

`core.py` is live product code — `api/main.py` is what the Dockerfile runs, and
`/api/v1/analyze` drives deduplication, remediation enrichment and the summary
a client reads. It sat at 36% line coverage.

Loading a directory of exports exists so that several scanners can cover one
host. That makes the interesting question not "are duplicates removed" but
"which copy survives, and what does the survivor still carry". Three defects
were reproduced here, all of which quietly make a client's report say less than
the scans found:

  1. Deduplication kept whichever copy had the LONGER DESCRIPTION and nothing
     else, so a critical remote code execution with a terse description lost to
     an informational duplicate with a wordy one. The critical, and its CVSS
     score, left the report.
  2. Remediation enrichment REPLACED any scanner solution under 50 characters
     with generic boilerplate — so "Upgrade nginx to 1.18.1 and disable TLS
     1.0." became "Address within 30 days. General Remediation Steps for: ...".
  3. "Assets affected" counted a finding carrying no asset at all as an asset.
"""

from __future__ import annotations

import pytest

from threat_inspector.core import ThreatInspector
from threat_inspector.parsers.base import ParsedVulnerability


def vuln(**kwargs) -> ParsedVulnerability:
    """A finding with sensible defaults; override only what a test is about."""
    base = {
        "title": "Finding",
        "severity": "medium",
        "description": "",
        "asset_ip": "10.255.255.1",
        "asset_port": 443,
    }
    base.update(kwargs)
    return ParsedVulnerability(**base)


def loaded(*vulns) -> ThreatInspector:
    inspector = ThreatInspector()
    inspector._vulnerabilities = list(vulns)
    return inspector


# ---------------------------------------------------------------------------
# Deduplication — which copy survives
# ---------------------------------------------------------------------------


def test_a_duplicate_cannot_talk_a_finding_down():
    """The defect with the worst consequence in this file.

    Two scanners graded the same issue differently. The old rule looked only at
    description length, so the informational copy won and the critical — the
    row the whole report exists to surface — was dropped.
    """
    inspector = loaded(
        vuln(title="Remote Code Execution", severity="critical", description="short"),
        vuln(title="Remote Code Execution", severity="info", description="a far longer write-up"),
    )
    inspector._deduplicate_vulnerabilities()
    assert len(inspector._vulnerabilities) == 1
    assert inspector._vulnerabilities[0].severity == "critical"


def test_the_order_the_copies_arrive_in_does_not_change_the_result():
    """Which export was read first must not decide the client's severity."""
    worse = vuln(title="RCE", severity="critical", description="short")
    milder = vuln(title="RCE", severity="info", description="a far longer write-up")

    for pair in ((worse, milder), (milder, worse)):
        inspector = loaded(*pair)
        inspector._deduplicate_vulnerabilities()
        assert inspector._vulnerabilities[0].severity == "critical"


@pytest.mark.parametrize(
    ("worse", "milder"),
    [
        ("critical", "high"),
        ("high", "medium"),
        ("medium", "low"),
        ("low", "info"),
    ],
)
def test_the_worse_grade_wins_at_every_band(worse, milder):
    inspector = loaded(
        vuln(severity=milder, description="x" * 500),
        vuln(severity=worse, description="x"),
    )
    inspector._deduplicate_vulnerabilities()
    assert inspector._vulnerabilities[0].severity == worse


def test_an_unrecognised_severity_does_not_outrank_a_real_one():
    """An odd severity string must sort after every known band, not ahead of
    "critical" — otherwise a scanner's typo silently promotes a finding."""
    inspector = loaded(
        vuln(severity="critical", description="short"),
        vuln(severity="catastrophic", description="x" * 500),
    )
    inspector._deduplicate_vulnerabilities()
    assert inspector._vulnerabilities[0].severity == "critical"


def test_choosing_a_winner_does_not_cost_a_score_a_cve_or_a_fix():
    """The copies carry different things. Picking one must not discard what
    only the other one had."""
    inspector = loaded(
        vuln(severity="critical", description="terse"),
        vuln(
            severity="info",
            description="wordy",
            cvss_score=9.8,
            cve_id="CVE-2021-44228",
            solution="Upgrade the component.",
            evidence="observed payload",
        ),
    )
    inspector._deduplicate_vulnerabilities()
    kept = inspector._vulnerabilities[0]
    assert kept.severity == "critical"
    assert kept.cvss_score == 9.8
    assert kept.cve_id == "CVE-2021-44228"
    assert kept.solution == "Upgrade the component."
    assert kept.evidence == "observed payload"


def test_a_field_the_winner_already_has_is_not_overwritten():
    inspector = loaded(
        vuln(severity="critical", description="the critical's own description", cve_id="CVE-1"),
        vuln(severity="info", description="the informational one's", cve_id="CVE-2"),
    )
    inspector._deduplicate_vulnerabilities()
    kept = inspector._vulnerabilities[0]
    assert kept.description == "the critical's own description"
    assert kept.cve_id == "CVE-1"


def test_the_richer_copy_wins_when_severity_is_equal():
    inspector = loaded(
        vuln(severity="high", description="short"),
        vuln(severity="high", description="a considerably longer description"),
    )
    inspector._deduplicate_vulnerabilities()
    assert inspector._vulnerabilities[0].description == "a considerably longer description"


def test_a_scored_copy_beats_an_unscored_one_of_the_same_severity():
    inspector = loaded(
        vuln(severity="high", description="x" * 500),
        vuln(severity="high", description="x", cvss_score=8.1),
    )
    inspector._deduplicate_vulnerabilities()
    assert inspector._vulnerabilities[0].cvss_score == 8.1


def test_titles_differing_only_in_capitalisation_are_one_finding():
    inspector = loaded(
        vuln(title="SQL Injection", severity="high"),
        vuln(title="sql injection", severity="high"),
    )
    inspector._deduplicate_vulnerabilities()
    assert len(inspector._vulnerabilities) == 1


def test_the_same_issue_on_different_ports_stays_two_findings():
    inspector = loaded(
        vuln(title="Weak Cipher", asset_port=443),
        vuln(title="Weak Cipher", asset_port=8443),
    )
    inspector._deduplicate_vulnerabilities()
    assert len(inspector._vulnerabilities) == 2


def test_the_same_issue_on_different_hosts_stays_two_findings():
    inspector = loaded(
        vuln(title="Weak Cipher", asset_ip="10.255.255.1"),
        vuln(title="Weak Cipher", asset_ip="10.255.255.2"),
    )
    inspector._deduplicate_vulnerabilities()
    assert len(inspector._vulnerabilities) == 2


def test_distinct_findings_keep_the_order_they_were_read_in():
    inspector = loaded(
        vuln(title="First", severity="low"),
        vuln(title="Second", severity="low", asset_port=80),
        vuln(title="Third", severity="low", asset_port=22),
    )
    inspector._deduplicate_vulnerabilities()
    assert [v.title for v in inspector._vulnerabilities] == ["First", "Second", "Third"]


def test_field_identical_copies_collapse_to_exactly_one():
    """The old rebuild filtered the output list with `!=`, and
    ParsedVulnerability is a plain dataclass — so that compared by VALUE and
    could drop copies it was never asked to touch."""
    inspector = loaded(vuln(title="A"), vuln(title="A"), vuln(title="A"))
    inspector._deduplicate_vulnerabilities()
    assert len(inspector._vulnerabilities) == 1


def test_a_large_duplicate_set_does_not_degrade_quadratically():
    """The old branch rescanned the whole output list on every replacement."""
    inspector = loaded(
        *[vuln(title="A", severity="high", description="x" * i) for i in range(1, 2001)]
    )
    inspector._deduplicate_vulnerabilities()
    assert len(inspector._vulnerabilities) == 1


def test_deduplication_of_nothing_is_not_an_error():
    inspector = loaded()
    inspector._deduplicate_vulnerabilities()
    assert inspector._vulnerabilities == []


# ---------------------------------------------------------------------------
# Remediation enrichment — the scanner's own advice
# ---------------------------------------------------------------------------


def test_a_short_specific_fix_from_the_scanner_is_not_replaced_by_boilerplate():
    """Was: any solution under 50 characters was overwritten wholesale.

    Length is not a proxy for quality — the most precise fix is usually the
    shortest sentence on the page.
    """
    fix = "Upgrade nginx to 1.18.1 and disable TLS 1.0."
    inspector = loaded(vuln(title="Weak Cipher", solution=fix))
    inspector._enrich_remediation()
    assert inspector._vulnerabilities[0].solution == fix


def test_a_long_solution_from_the_scanner_is_also_kept():
    fix = "Reconfigure the service. " * 10
    inspector = loaded(vuln(title="Weak Cipher", solution=fix))
    inspector._enrich_remediation()
    assert inspector._vulnerabilities[0].solution == fix


def test_a_finding_with_no_solution_still_gets_guidance():
    """Filling a genuine blank is the whole point of enrichment."""
    inspector = loaded(vuln(title="Weak Cipher", severity="medium", solution=""))
    inspector._enrich_remediation()
    assert inspector._vulnerabilities[0].solution.strip() != ""


def test_a_whitespace_only_solution_counts_as_no_solution():
    inspector = loaded(vuln(title="Weak Cipher", solution="   \n "))
    inspector._enrich_remediation()
    assert inspector._vulnerabilities[0].solution.strip() != ""


# ---------------------------------------------------------------------------
# The summary a client reads
# ---------------------------------------------------------------------------


def test_a_finding_with_no_asset_is_not_counted_as_an_asset():
    """Was: "assets affected" reported 2 for one host plus one host-less
    finding. It is a number a client reads and acts on."""
    inspector = loaded(
        vuln(title="A", asset_ip="10.255.255.1"),
        vuln(title="B", asset_ip="", asset_name="", asset_port=None),
    )
    assert inspector.get_summary()["assets_affected"] == 1


def test_assets_are_counted_once_however_many_findings_they_carry():
    inspector = loaded(
        vuln(title="A", asset_ip="10.255.255.1", asset_port=80),
        vuln(title="B", asset_ip="10.255.255.1", asset_port=443),
        vuln(title="C", asset_ip="10.255.255.2"),
    )
    assert inspector.get_summary()["assets_affected"] == 2


def test_an_asset_named_but_not_addressed_still_counts():
    inspector = loaded(vuln(title="A", asset_ip="", asset_name="host.selftest.invalid"))
    assert inspector.get_summary()["assets_affected"] == 1


def test_the_severity_breakdown_matches_the_findings():
    inspector = loaded(
        vuln(title="A", severity="critical"),
        vuln(title="B", severity="critical", asset_port=80),
        vuln(title="C", severity="low", asset_port=22),
    )
    summary = inspector.get_summary()
    assert summary["total_vulnerabilities"] == 3
    assert summary["critical_count"] == 2
    assert summary["low_count"] == 1
    assert summary["high_count"] == 0
    assert summary["severity_breakdown"]["critical"] == 2


def test_an_empty_analysis_summarises_as_zero_rather_than_failing():
    summary = loaded().get_summary()
    assert summary["total_vulnerabilities"] == 0
    assert summary["assets_affected"] == 0
    assert summary["critical_count"] == 0


# ---------------------------------------------------------------------------
# The whole analyse pass, as the API drives it
# ---------------------------------------------------------------------------


def test_the_summary_after_analyse_reflects_the_deduplicated_severities():
    """Ties all three fixes to the number the client is shown.

    `/api/v1/analyze` returns exactly this. Under the old rules the critical
    was replaced by its informational duplicate, so `critical_count` was 0 and
    `info_count` was 1 for a scan that had found a critical.
    """
    inspector = loaded(
        vuln(title="Remote Code Execution", severity="critical", description="short"),
        vuln(title="Remote Code Execution", severity="info", description="a longer write-up"),
    )
    summary = inspector.analyze(enrich_remediation=False, map_compliance=False)
    assert summary["total_vulnerabilities"] == 1
    assert summary["critical_count"] == 1
    assert summary["info_count"] == 0


def test_analyse_can_be_asked_not_to_deduplicate():
    inspector = loaded(
        vuln(title="A", severity="high"),
        vuln(title="A", severity="high"),
    )
    summary = inspector.analyze(deduplicate=False, enrich_remediation=False, map_compliance=False)
    assert summary["total_vulnerabilities"] == 2


def test_compliance_mappings_are_attached_to_each_finding():
    inspector = loaded(vuln(title="Weak Cipher", severity="medium"))
    inspector.analyze(enrich_remediation=False, map_compliance=True)
    assert "compliance_mappings" in inspector._vulnerabilities[0].raw_data


# ---------------------------------------------------------------------------
# Filtering, as /api/v1/vulnerabilities drives it
# ---------------------------------------------------------------------------


def test_findings_come_back_worst_first():
    inspector = loaded(
        vuln(title="A", severity="low"),
        vuln(title="B", severity="critical", asset_port=80),
        vuln(title="C", severity="medium", asset_port=22),
    )
    assert [v.severity for v in inspector.get_vulnerabilities()] == [
        "critical",
        "medium",
        "low",
    ]


def test_filtering_by_severity_is_case_insensitive():
    inspector = loaded(
        vuln(title="A", severity="critical"),
        vuln(title="B", severity="low", asset_port=80),
    )
    assert len(inspector.get_vulnerabilities(severity="CRITICAL")) == 1


def test_filtering_by_asset_matches_a_substring_of_ip_or_name():
    inspector = loaded(
        vuln(title="A", asset_ip="10.255.255.1"),
        vuln(title="B", asset_ip="", asset_name="host.selftest.invalid"),
    )
    assert len(inspector.get_vulnerabilities(asset="255.255")) == 1
    assert len(inspector.get_vulnerabilities(asset="selftest")) == 1


def test_a_limit_returns_the_most_severe_not_an_arbitrary_slice():
    inspector = loaded(
        vuln(title="A", severity="low"),
        vuln(title="B", severity="critical", asset_port=80),
        vuln(title="C", severity="high", asset_port=22),
    )
    assert [v.severity for v in inspector.get_vulnerabilities(limit=2)] == ["critical", "high"]
