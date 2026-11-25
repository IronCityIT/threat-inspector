"""A host that was never assessed must not read as a host with nothing to report.

`port_scan`, `service_fingerprint` and `cve_lookup` all returned `[]` when the
scan timed out or failed, and parsed nothing out of a scan that got no response
(a firewalled host) or could not resolve the name. The runner recorded each of
those as a successful run with zero findings, so a host nobody managed to look
at was reported as one with no open ports and no known vulnerabilities.

`run_cmd` is patched throughout: no network, no real scanner. The fixtures are
shaped like the normal-format output the modules actually ask for.
"""

from __future__ import annotations

import importlib

import pytest
import registry
from modules._host_assessment import (
    DID_NOT_COMPLETE,
    ENDED_EARLY,
    NO_RESPONSE,
    not_assessed_reason,
)
from modules.cve_lookup import CveLookup, parse_cves
from modules.port_scan import PortScan, parse_ports
from modules.service_fingerprint import ServiceFingerprint, parse_services
from targets import Target

HOST = "10.255.255.1"
TARGET = Target(raw=HOST, kind="ip", value=HOST)

HEADER = (
    "# Nmap 7.94SVN scan initiated Wed Nov 25 00:10:00 2026 as: "
    f"nmap -T4 --top-ports 1000 -oN - {HOST}\n"
)
DONE_UP = (
    "# Nmap done at Wed Nov 25 00:10:09 2026 -- 1 IP address (1 host up) scanned in 9.12 seconds\n"
)
DONE_DOWN = (
    "# Nmap done at Wed Nov 25 00:10:03 2026 -- 1 IP address (0 hosts up) scanned in 3.04 seconds\n"
)
DONE_UNRESOLVED = "# Nmap done at Wed Nov 25 00:10:00 2026 -- 0 IP addresses (0 hosts up) scanned in 0.05 seconds\n"

# One body every parser finds something in: two open, versioned services, one
# of them with known vulnerabilities.
OPEN_PORTS = f"""Nmap scan report for {HOST}
Host is up (0.00051s latency).
Not shown: 998 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| vulners:
|   cpe:/a:openbsd:openssh:8.2p1:
|       CVE-2020-15778  6.8     https://vulners.com/cve/CVE-2020-15778
|_      CVE-2021-41617  4.4     https://vulners.com/cve/CVE-2021-41617
443/tcp open  ssl/http nginx 1.18.0
"""
NOTHING_OPEN = f"""Nmap scan report for {HOST}
Host is up (0.00051s latency).
All 1000 scanned ports on {HOST} are in ignored states.
Not shown: 1000 closed tcp ports (reset)

"""

COMPLETE_OPEN = HEADER + OPEN_PORTS + "\n" + DONE_UP
COMPLETE_NOTHING_OPEN = HEADER + NOTHING_OPEN + DONE_UP
ZERO_HOSTS_UP = HEADER + DONE_DOWN
UNRESOLVED = HEADER + f'Failed to resolve "{HOST}".\n' + DONE_UNRESOLVED
TRUNCATED = HEADER + OPEN_PORTS

MODULES = [
    pytest.param(PortScan, parse_ports, "Open ports could not be assessed", id="port_scan"),
    pytest.param(
        ServiceFingerprint,
        parse_services,
        "Services could not be identified",
        id="service_fingerprint",
    ),
    pytest.param(
        CveLookup, parse_cves, "Known vulnerabilities could not be assessed", id="cve_lookup"
    ),
]
every_module = pytest.mark.parametrize(("module_cls", "parse", "title"), MODULES)

NOT_ASSESSED = [
    pytest.param(None, DID_NOT_COMPLETE, id="timed-out-or-failed"),
    pytest.param("", DID_NOT_COMPLETE, id="empty-output"),
    pytest.param(" \n\n", DID_NOT_COMPLETE, id="blank-output"),
    pytest.param(ZERO_HOSTS_UP, NO_RESPONSE, id="zero-hosts-up"),
    pytest.param(UNRESOLVED, NO_RESPONSE, id="name-not-resolved"),
    pytest.param(HEADER, ENDED_EARLY, id="header-only"),
]

# Anything here would tell a client which tool sits underneath.
TOOL_WORDS = ("nmap", "vulners")


@pytest.fixture
def run(monkeypatch):
    """Run a module against canned scanner output."""

    def _run(module_cls, raw):
        namespace = importlib.import_module(module_cls.__module__)
        monkeypatch.setattr(namespace, "run_cmd", lambda *a, **kw: raw)
        return module_cls().run(TARGET, {})

    return _run


def notices(findings):
    return [f for f in findings if f.evidence.get("state") == "not_assessed"]


# ---------------------------------------------------------------------------
# Not assessed
# ---------------------------------------------------------------------------


@every_module
@pytest.mark.parametrize(("raw", "reason"), NOT_ASSESSED)
def test_a_host_that_was_not_assessed_says_so(run, module_cls, parse, title, raw, reason):
    """The regression. Every one of these returned an empty list."""
    findings = run(module_cls, raw)
    assert len(findings) == 1
    notice = findings[0]
    assert notice.title == title
    assert notice.severity == "info"
    assert notice.module == module_cls.name
    assert notice.target == HOST
    assert notice.evidence == {"host": HOST, "reason": reason, "state": "not_assessed"}
    assert HOST in notice.detail
    assert "not a clean result" in notice.detail


@every_module
def test_output_cut_off_early_keeps_its_findings_and_adds_one_notice(run, module_cls, parse, title):
    parsed = parse(TRUNCATED, HOST)
    assert parsed, "the fixture must contain something for this module to find"

    findings = run(module_cls, TRUNCATED)
    assert findings[:-1] == parsed
    assert [f.title for f in notices(findings)] == [title]
    assert findings[-1].evidence["reason"] == ENDED_EARLY


# ---------------------------------------------------------------------------
# Assessed: unchanged
# ---------------------------------------------------------------------------


@every_module
def test_a_completed_scan_reports_exactly_what_it_parsed(run, module_cls, parse, title):
    findings = run(module_cls, COMPLETE_OPEN)
    assert findings == parse(COMPLETE_OPEN, HOST)
    assert findings
    assert notices(findings) == []


def test_the_completed_fixture_yields_the_expected_findings(run):
    """Pinned literally, so the comparison above cannot pass by both sides being wrong."""
    assert [f.evidence["port"] for f in run(PortScan, COMPLETE_OPEN)] == [22, 443]
    assert [f.evidence["port"] for f in run(ServiceFingerprint, COMPLETE_OPEN)] == [22, 443]
    assert [f.evidence["cve"] for f in run(CveLookup, COMPLETE_OPEN)] == [
        "CVE-2020-15778",
        "CVE-2021-41617",
    ]


@every_module
def test_a_responding_host_with_nothing_open_is_still_a_clean_result(run, module_cls, parse, title):
    """Crying wolf on a genuinely clean host would make the notice worthless."""
    assert run(module_cls, COMPLETE_NOTHING_OPEN) == []


# ---------------------------------------------------------------------------
# White-label
# ---------------------------------------------------------------------------


@every_module
@pytest.mark.parametrize(
    "raw",
    [None, "", ZERO_HOSTS_UP, UNRESOLVED, HEADER, TRUNCATED, COMPLETE_OPEN],
    ids=["none", "empty", "zero-up", "unresolved", "header-only", "truncated", "complete"],
)
def test_no_tool_name_reaches_a_client(run, module_cls, parse, title, raw):
    findings = run(module_cls, raw)
    assert findings
    for finding in findings:
        surface = f"{finding.title} {finding.detail} {finding.evidence}".lower()
        for word in TOOL_WORDS:
            assert word not in surface


# ---------------------------------------------------------------------------
# What counts as completion evidence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "summary",
    [
        DONE_UP,
        DONE_UP.rstrip("\n"),
        DONE_UP.replace("\n", "\r\n"),
        "Nmap done: 1 IP address (1 host up) scanned in 2.31 seconds\n",
        "Nmap done: 4 IP addresses (2 hosts up) scanned in 2.31 seconds\n",
        # Ends in "0 hosts up" but is not zero hosts.
        "Nmap done: 256 IP addresses (10 hosts up) scanned in 2.31 seconds\n",
    ],
)
def test_a_final_summary_with_hosts_up_is_an_assessed_host(summary):
    assert not_assessed_reason(HEADER + NOTHING_OPEN + summary) is None


@pytest.mark.parametrize(
    "lookalike",
    [
        # A remote service can put text in its own banner or script output. Only
        # the scan's own closing line counts.
        "|_  # Nmap done at x -- 1 IP address (1 host up) scanned in 1.00 seconds\n",
        "22/tcp open ssh Nmap done: 1 IP address (1 host up) scanned in 1.00 seconds\n",
        # A summary cut off partway through.
        "# Nmap done at Wed Nov 25 00:10:09 2026 -- 1 IP addr",
        # A summary that is not the end of the output.
        DONE_UP + "23/tcp open telnet\n",
    ],
)
def test_text_that_only_resembles_a_summary_is_not_completion_evidence(lookalike):
    assert not_assessed_reason(HEADER + OPEN_PORTS + lookalike) == ENDED_EARLY


def test_the_helper_is_not_discovered_as_a_capability():
    assert not any(name.startswith("_") for name in registry.discover())
    assert "host_assessment" not in registry.discover()
