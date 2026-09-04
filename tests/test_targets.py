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
