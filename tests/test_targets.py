"""Target parsing, validation, and the two security guards that live there.

targets.py is the only place a caller-supplied string becomes something a module
will connect to, so the scheme allowlist and the local-address guard are tested
here rather than in each module.
"""

from __future__ import annotations

import pytest
from targets import ALLOWED_SCHEMES, Target, TargetError, parse_targets, parse_targets_report

# ---- classification -----------------------------------------------------


@pytest.mark.parametrize(
    ("token", "kind", "value"),
    [
        ("example.com", "domain", "example.com"),
        ("EXAMPLE.COM", "domain", "example.com"),
        ("myhost", "hostname", "myhost"),
        ("10.0.0.5", "ip", "10.0.0.5"),
        ("https://app.example.com/x", "url", "https://app.example.com/x"),
        ("http://app.example.com", "url", "http://app.example.com"),
    ],
)
def test_classifies_each_target_shape(token, kind, value):
    got = parse_targets([token])
    assert got == [Target(raw=token, kind=kind, value=value)]


def test_cidr_expands_to_host_addresses():
    got = parse_targets(["192.168.1.0/30"])
    assert [t.value for t in got] == ["192.168.1.1", "192.168.1.2"]
    assert {t.kind for t in got} == {"ip"}


def test_single_host_cidr_still_yields_the_address():
    """/32 has no .hosts(); it must not silently resolve to zero targets."""
    assert [t.value for t in parse_targets(["192.168.1.7/32"])] == ["192.168.1.7"]


def test_targets_are_deduped_across_sources():
    got = parse_targets(["example.com,example.com", "EXAMPLE.com"])
    assert len(got) == 1


def test_reads_targets_file_and_strips_comments(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("# a comment\nexample.com  # trailing\n\n10.0.0.1\n")
    got = parse_targets(files=[str(f)])
    assert [t.value for t in got] == ["example.com", "10.0.0.1"]


def test_missing_targets_file_is_an_error_not_a_crash():
    report = parse_targets_report(files=["/nonexistent/targets.txt"])
    assert report.targets == []
    assert any("targets.txt" in e for e in report.errors)


# ---- guard: scheme allowlist -------------------------------------------


@pytest.mark.parametrize(
    "token",
    [
        "file://localhost/etc/passwd",
        "ftp://example.com/a",
        "gopher://example.com/x",
        "://",
    ],
)
def test_non_http_schemes_are_refused(token):
    """Modules hand target.value straight to urllib, which also speaks file://."""
    report = parse_targets_report([token])
    assert report.targets == []
    assert report.errors


def test_allowed_schemes_are_exactly_http_and_https():
    assert set(ALLOWED_SCHEMES) == {"http", "https"}


def test_scheme_like_junk_is_not_accepted_as_a_hostname():
    """'javascript:alert(1)' used to classify as a perfectly good hostname."""
    report = parse_targets_report(["javascript:alert(1)"])
    assert report.targets == []


# ---- guard: loopback and link-local ------------------------------------


@pytest.mark.parametrize(
    "token",
    [
        "169.254.169.254",
        "http://169.254.169.254/latest/meta-data/",
        "127.0.0.1",
        "http://127.0.0.1/",
        "https://[::1]/",
        "localhost",
    ],
)
def test_local_and_metadata_targets_are_blocked_by_default(token):
    report = parse_targets_report([token])
    assert report.targets == [], f"{token} should be refused without --allow-local"
    assert report.errors


@pytest.mark.parametrize("token", ["127.0.0.1", "localhost", "http://169.254.169.254/"])
def test_allow_local_opts_back_in(token):
    report = parse_targets_report([token], allow_local=True)
    assert len(report.targets) == 1
    assert report.errors == []


def test_rfc1918_is_still_scannable():
    """Scanning a client's internal range is the product's actual job."""
    for token in ("192.168.1.10", "10.1.2.3", "172.16.0.1"):
        assert len(parse_targets([token])) == 1


# ---- error reporting ----------------------------------------------------


def test_one_bad_token_does_not_discard_the_good_ones():
    report = parse_targets_report(["example.com,10.0.0.0/99,10.0.0.1"])
    assert [t.value for t in report.targets] == ["example.com", "10.0.0.1"]
    assert len(report.errors) == 1


def test_bad_cidr_reports_a_reason_rather_than_raising_from_ipaddress():
    report = parse_targets_report(["10.0.0.0/99"])
    assert "not a valid network range" in report.errors[0]


def test_strict_form_raises_target_error_not_a_bare_value_error():
    with pytest.raises(TargetError):
        parse_targets(["10.0.0.0/99"])


# ---- guard: every spelling the resolver accepts ------------------------
#
# getaddrinfo() hands inet_aton() spellings straight to connect(): decimal
# ("2852039166"), hex ("0x7f000001"), octal ("0177.0.0.1") and short dotted
# ("127.1") forms all reach the same address as the dotted quad, and an
# IPv4-mapped IPv6 literal reaches its inner IPv4 address on a dual-stack socket.
# A guard that only recognises the dotted quad is no guard: http://0x7f000001/
# was fetched from 127.0.0.1 with no --allow-local.


@pytest.mark.parametrize(
    "token",
    [
        "0x7f000001",  # hex, 127.0.0.1
        "2130706433",  # decimal, 127.0.0.1
        "127.1",  # short dotted, 127.0.0.1
        "0177.0.0.1",  # octal first octet, 127.0.0.1
        "2852039166",  # decimal, 169.254.169.254 — the metadata endpoint
        "0xa9fea9fe",  # hex, 169.254.169.254
        "http://0x7f000001/",
        "http://127.1:8080/",
        "http://2852039166/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://[::ffff:127.0.0.1]/",
        "::ffff:127.0.0.1",
        "0.0.0.0",  # the unspecified address connects to the local machine
        "http://0.0.0.0:8080/",
        "::",
        "https://[::]/",
    ],
)
def test_every_spelling_of_a_local_address_is_blocked_by_default(token):
    report = parse_targets_report([token])
    assert report.targets == [], f"{token} should be refused without --allow-local"
    assert len(report.errors) == 1
    assert "--allow-local" in report.errors[0]


@pytest.mark.parametrize(
    ("token", "value"),
    [
        ("0x7f000001", "127.0.0.1"),
        ("2130706433", "127.0.0.1"),
        ("127.1", "127.0.0.1"),
        ("0177.0.0.1", "127.0.0.1"),
        ("0.0.0.0", "0.0.0.0"),
    ],
)
def test_allow_local_admits_alternate_spellings_as_the_canonical_ip(token, value):
    """Opted in, an alternate spelling is reported as the address it denotes."""
    report = parse_targets_report([token], allow_local=True)
    assert report.errors == []
    assert report.targets == [Target(raw=token, kind="ip", value=value)]


@pytest.mark.parametrize(
    ("token", "value"),
    [
        ("0xc0a80101", "192.168.1.1"),
        ("3232235777", "192.168.1.1"),
        ("10.1", "10.0.0.1"),
    ],
)
def test_alternate_spellings_of_a_scannable_address_classify_as_that_ip(token, value):
    """The canonical form goes to the scanner, so what it scans is what is reported."""
    assert parse_targets([token]) == [Target(raw=token, kind="ip", value=value)]


@pytest.mark.parametrize("token", ["1e10", "0b1", "123abc", "host1", "0x"])
def test_names_that_merely_look_numeric_are_still_hostnames(token):
    """inet_aton() accepts none of these, and neither would the resolver as literals."""
    assert parse_targets([token]) == [Target(raw=token, kind="hostname", value=token)]


def test_an_ipv4_mapped_scannable_address_is_still_scannable():
    assert len(parse_targets(["::ffff:192.168.1.1"])) == 1


# ---- range size ----------------------------------------------------------
#
# Expansion is eager: every address becomes a Target before a single module
# runs. Unbounded, that is a hang (2001:db8::/64 never returned; a scan job
# would sit for its full timeout with no output) or an out-of-memory (a /8 is
# sixteen million objects). The parser refuses a range wider than a /16 up front
# and says so, rather than trying and never answering.


def test_the_range_limit_is_a_v4_slash_16():
    from targets import MAX_RANGE_ADDRESSES

    assert MAX_RANGE_ADDRESSES == 65_536


@pytest.mark.parametrize(
    "token",
    [
        "10.0.0.0/8",
        "10.0.0.0/15",
        "2001:db8::/64",
        "2001:db8::/32",
        "2001:db8::/111",
    ],
)
def test_a_range_wider_than_the_limit_is_refused_immediately_with_its_size(token):
    import time

    started = time.monotonic()
    report = parse_targets_report([token])
    assert time.monotonic() - started < 1.0, "refusal must not depend on expanding the range"
    assert report.targets == []
    assert len(report.errors) == 1
    err = report.errors[0]
    assert token in err
    assert "65,536" in err, err
    assert "split" in err.lower(), err


@pytest.mark.parametrize(
    ("token", "count"),
    [
        ("10.0.0.0/16", 65_534),  # network and broadcast excluded, as before
        ("2001:db8::/112", 65_535),  # v6 has no broadcast; only the subnet-router anycast goes
        ("192.168.0.0/24", 254),
    ],
)
def test_a_range_at_or_under_the_limit_still_expands_in_full(token, count):
    assert len(parse_targets([token])) == count


def test_a_refused_range_does_not_discard_the_other_targets():
    report = parse_targets_report(["example.com,10.0.0.0/8,10.0.0.1"])
    assert [t.value for t in report.targets] == ["example.com", "10.0.0.1"]
    assert len(report.errors) == 1


# ---- guard: the name forms of the local machine ---------------------------


@pytest.mark.parametrize(
    "token", ["http://localhost/", "https://LOCALHOST:8443/admin", "http://ip6-localhost/"]
)
def test_a_url_naming_the_local_machine_is_blocked_by_default(token):
    report = parse_targets_report([token])
    assert report.targets == []
    assert len(report.errors) == 1
    assert "--allow-local" in report.errors[0]


def test_a_url_with_no_host_is_refused_with_a_reason():
    report = parse_targets_report(["http:///just/a/path"])
    assert report.targets == []
    assert report.errors == ["'http:///just/a/path' is not a usable URL: no host"]
