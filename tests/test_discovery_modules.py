"""The last three scan modules without direct tests.

`subdomain_enum`, `service_fingerprint` and `web_vuln_scan` each turn a
scanner's raw output into findings a client reads. One of the three had a real
defect; the other two turned out to be right, and this file pins why, because
the reason one of them looks wrong is a deliberate division of labour that a
future change could easily undo by accident.

**subdomain_enum claimed things that were not subdomains.**

Every non-empty line became a finding. Measured:

    [INF] Enumerating subdomains for acme.com  ->  reported as a subdomain
    evil.example.net                           ->  reported as acme.com's

The first is scanner chatter claimed as a discovered asset. The second is worse:
a host that is not the client's, attributed to the client's attack surface. On a
security report, naming someone else's domain as part of your estate is worse
than naming nothing.

**service_fingerprint reports only services carrying a version — correctly.**

It parses 3 of 6 open services on a realistic scan, which looks like data loss
until you check: `port_scan` reports all 6, and it runs in every group
`service_fingerprint` does (standard, deep). The division is intentional and
already asserted in tests/test_modules.py. Nothing is lost, and the tests below
pin the pairing so a change to either module cannot quietly break it.
"""

from __future__ import annotations

import pytest
import registry
from modules.port_scan import parse_ports
from modules.service_fingerprint import parse_services
from modules.subdomain_enum import parse_subdomains
from modules.web_vuln_scan import parse_findings as parse_web

DOMAIN = "acme.selftest.invalid"

# One host, six open services, three of which nmap could not version.
SIX_SERVICES = """Nmap scan report for 10.255.255.1
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http
443/tcp  open  ssl/http nginx 1.18.0
3306/tcp open  mysql?
8080/tcp open  http-proxy
161/udp  open  snmp     SNMPv1 server
"""


def subdomains(raw: str, domain: str = DOMAIN) -> set[str]:
    return {
        f.evidence["subdomain"] for f in parse_subdomains(raw, domain) if "subdomain" in f.evidence
    }


def skipped_notice(raw: str, domain: str = DOMAIN):
    return next((f for f in parse_subdomains(raw, domain) if "skipped_lines" in f.evidence), None)


# ---------------------------------------------------------------------------
# A subdomain has to be a subdomain
# ---------------------------------------------------------------------------


def test_scanner_chatter_is_not_a_discovered_asset():
    """The regression. This line was reported as a subdomain."""
    raw = f"[INF] Enumerating subdomains for {DOMAIN}\nwww.{DOMAIN}\n"
    assert subdomains(raw) == {f"www.{DOMAIN}"}


def test_a_host_that_is_not_the_clients_is_not_their_attack_surface():
    """Naming someone else's domain as part of a client's estate is worse than
    naming nothing."""
    assert subdomains(f"www.{DOMAIN}\nevil.example.net\n") == {f"www.{DOMAIN}"}


def test_a_lookalike_domain_is_not_in_scope():
    """`evil-acme...` must not pass for a subdomain of `acme...` — the check is
    on a dot boundary, not a bare suffix."""
    assert subdomains(f"evil-{DOMAIN}\n") == set()


def test_the_domain_itself_is_part_of_its_own_attack_surface():
    assert subdomains(f"{DOMAIN}\n") == {DOMAIN}


def test_a_deep_subdomain_is_in_scope():
    assert subdomains(f"a.b.c.{DOMAIN}\n") == {f"a.b.c.{DOMAIN}"}


@pytest.mark.parametrize(
    "line",
    ["not a hostname", "-leading.hyphen.com", "http://www." + DOMAIN, "10.0.0.1", "*." + DOMAIN],
)
def test_malformed_output_is_not_reported_as_a_host(line):
    assert subdomains(f"{line}\n") == set()


def test_discovery_is_case_insensitive_and_deduplicated():
    raw = f"WWW.{DOMAIN.upper()}\nwww.{DOMAIN}\n  www.{DOMAIN}  \n"
    assert subdomains(raw) == {f"www.{DOMAIN}"}


def test_a_trailing_dot_is_the_same_host():
    assert subdomains(f"www.{DOMAIN}.\nwww.{DOMAIN}\n") == {f"www.{DOMAIN}"}


def test_blank_lines_are_neither_reported_nor_counted_as_skipped():
    assert skipped_notice(f"\n\nwww.{DOMAIN}\n\n") is None


# ---------------------------------------------------------------------------
# ...and what was dropped has to be visible
# ---------------------------------------------------------------------------


def test_output_that_was_not_a_subdomain_is_reported_as_skipped():
    """Dropping silently would hide a scanner that has started emitting
    something we do not understand — including another client's domain."""
    notice = skipped_notice(f"www.{DOMAIN}\nevil.example.net\n[INF] chatter\n")
    assert notice is not None
    assert notice.evidence["skipped_lines"] == 2
    assert notice.severity == "info"


def test_the_skip_notice_names_the_domain_that_was_scanned():
    notice = skipped_notice("evil.example.net\n")
    assert DOMAIN in notice.detail


def test_a_clean_run_produces_no_skip_notice():
    """Crying wolf on every scan would make the notice worthless."""
    assert skipped_notice(f"www.{DOMAIN}\napi.{DOMAIN}\n") is None


def test_the_skip_notice_does_not_repeat_the_rejected_text():
    """The rejected line can be another client's hostname or raw scanner output.
    The count is what a reader needs."""
    notice = skipped_notice("evil.example.net\n")
    assert "evil.example.net" not in notice.detail


def test_every_finding_is_attributed_to_the_scanned_domain():
    for finding in parse_subdomains(f"www.{DOMAIN}\nnonsense\n", DOMAIN):
        assert finding.target == DOMAIN
        assert finding.module == "subdomain_enum"


def test_empty_output_produces_nothing_at_all():
    assert parse_subdomains("", DOMAIN) == []


# ---------------------------------------------------------------------------
# service_fingerprint and port_scan are a pair
# ---------------------------------------------------------------------------


def test_fingerprinting_reports_only_the_services_it_could_version():
    """Looks like data loss on its own — see the next test for why it is not."""
    versioned = {f.evidence["port"] for f in parse_services(SIX_SERVICES, "10.255.255.1")}
    assert versioned == {22, 443, 161}


def test_port_scan_reports_every_open_service_including_unversioned_ones():
    """The other half of the pair. Nothing a client has is unreported."""
    found = {f.evidence["port"] for f in parse_ports(SIX_SERVICES, "10.255.255.1")}
    assert found == {22, 80, 443, 3306, 8080, 161}


def test_the_pairing_holds_in_every_group_that_runs_fingerprinting():
    """If service_fingerprint ever ran without port_scan, the services it cannot
    version would go unreported. This pins that it cannot."""
    discovered = registry.discover()
    fingerprint_groups = set(discovered["service_fingerprint"].groups)
    port_scan_groups = set(discovered["port_scan"].groups)
    assert fingerprint_groups <= port_scan_groups


def test_a_versioned_service_carries_its_version_and_service_name():
    finding = next(
        f for f in parse_services(SIX_SERVICES, "10.255.255.1") if f.evidence["port"] == 22
    )
    assert finding.evidence["service"] == "ssh"
    assert finding.evidence["version"].startswith("OpenSSH 8.2p1")
    assert finding.evidence["protocol"] == "tcp"


def test_udp_services_are_fingerprinted_too():
    finding = next(
        f for f in parse_services(SIX_SERVICES, "10.255.255.1") if f.evidence["port"] == 161
    )
    assert finding.evidence["protocol"] == "udp"


def test_fingerprints_are_informational_not_findings_against_the_client():
    """Knowing what runs on a port is not itself a vulnerability."""
    assert all(f.severity == "info" for f in parse_services(SIX_SERVICES, "10.255.255.1"))


def test_a_closed_or_filtered_port_is_not_fingerprinted():
    raw = "22/tcp closed ssh OpenSSH 8.2p1\n80/tcp filtered http Apache 2.4\n"
    assert parse_services(raw, "10.255.255.1") == []


# ---------------------------------------------------------------------------
# web_vuln_scan
# ---------------------------------------------------------------------------


def test_a_web_finding_keeps_its_severity_and_location():
    raw = (
        '{"template-id":"xss","info":{"name":"Reflected XSS","severity":"high"},'
        '"matched-at":"http://app.selftest.invalid/q"}'
    )
    finding = parse_web(raw, "http://app.selftest.invalid")[0]
    assert finding.severity == "high"
    assert finding.title == "Reflected XSS"
    assert finding.evidence["matched_at"] == "http://app.selftest.invalid/q"
    assert finding.evidence["template"] == "xss"


@pytest.mark.parametrize("severity", ["info", "low", "medium", "high", "critical"])
def test_every_severity_the_scanner_emits_is_carried_through(severity):
    raw = f'{{"info":{{"name":"F","severity":"{severity}"}},"template-id":"t"}}'
    assert parse_web(raw, "http://x")[0].severity == severity


def test_a_severity_is_read_whatever_its_case():
    raw = '{"info":{"name":"F","severity":"HIGH"},"template-id":"t"}'
    assert parse_web(raw, "http://x")[0].severity == "high"


def test_a_malformed_line_does_not_sink_the_rest():
    raw = 'not json\n{"info":{"name":"Real","severity":"high"},"template-id":"t"}\n{"broken":\n'
    findings = parse_web(raw, "http://x")
    assert [f.title for f in findings] == ["Real"]


def test_a_finding_with_no_name_still_reports_something():
    """An unnamed finding is still a finding; dropping it would lose it."""
    assert parse_web('{"info":{"severity":"high"}}', "http://x")[0].title


def test_empty_output_produces_nothing():
    assert parse_web("", "http://x") == []
