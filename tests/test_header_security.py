"""Security headers: present is not the same as working.

The presence-only check graded a hardening header by whether its NAME appeared
in the response. That let two things through, both of which a client would read
as a pass:

  1. A header set to a value that does nothing. `Strict-Transport-Security:
     max-age=0` switches HSTS off; `X-Content-Type-Options: enabled` is ignored
     outright, because a browser accepts only the exact token `nosniff`. Both
     counted as protected. A header that is present and inert is arguably worse
     than one that is absent — it survives an audit that greps for the name.
  2. A target that could not be reached at all. `run()` returned an empty list,
     which in the report is indistinguishable from a site with every header
     correctly set. The scan's health counters do not catch it either: they
     track module EXCEPTIONS, and nothing raised.

The listener tests use real sockets on 127.0.0.1, against a server the test
process starts and owns. Nothing here touches a third party.
"""

from __future__ import annotations

import http.server
import socket
import threading

import pytest
from modules.header_security_check import HeaderSecurityCheck, evaluate_headers
from targets import Target

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}

TARGET = "acme.selftest.invalid"


def evaluate(overrides: dict | None = None, drop: tuple[str, ...] = ()):
    headers = dict(GOOD_HEADERS)
    for name in drop:
        headers.pop(name)
    headers.update(overrides or {})
    return evaluate_headers(headers, TARGET)


def only(findings):
    assert len(findings) == 1, f"expected exactly one finding, got {len(findings)}"
    return findings[0]


# ---------------------------------------------------------------------------
# A correctly configured response
# ---------------------------------------------------------------------------


def test_a_fully_hardened_response_produces_nothing():
    assert evaluate() == []


def test_header_names_are_matched_case_insensitively():
    shouty = {name.upper(): value for name, value in GOOD_HEADERS.items()}
    assert evaluate_headers(shouty, TARGET) == []


# ---------------------------------------------------------------------------
# Missing headers — the behaviour that already worked
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "expected_severity"),
    [
        ("Strict-Transport-Security", "medium"),
        ("Content-Security-Policy", "medium"),
        ("X-Frame-Options", "low"),
        ("X-Content-Type-Options", "low"),
        ("Referrer-Policy", "low"),
    ],
)
def test_each_missing_header_is_flagged_at_its_severity(header, expected_severity):
    finding = only(evaluate(drop=(header,)))
    assert finding.evidence["header"] == header.lower()
    assert finding.evidence["state"] == "missing"
    assert finding.severity == expected_severity


def test_a_bare_response_flags_every_expected_header():
    assert len(evaluate_headers({}, TARGET)) == len(GOOD_HEADERS)


# ---------------------------------------------------------------------------
# Present but inert — what the check used to call a pass
# ---------------------------------------------------------------------------


def test_hsts_with_max_age_zero_is_not_protection():
    """max-age=0 does not merely fail to help — it clears any stored policy."""
    finding = only(evaluate({"Strict-Transport-Security": "max-age=0"}))
    assert finding.evidence["state"] == "ineffective"
    assert finding.evidence["value"] == "max-age=0"
    assert "switches HSTS off" in finding.detail


def test_hsts_with_no_max_age_at_all_is_flagged():
    assert (
        only(evaluate({"Strict-Transport-Security": "includeSubDomains"})).evidence["state"]
        == "ineffective"
    )


def test_hsts_with_an_unparseable_max_age_is_flagged():
    assert (
        only(evaluate({"Strict-Transport-Security": "max-age=forever"})).evidence["state"]
        == "ineffective"
    )


def test_a_short_but_real_max_age_is_left_alone():
    """Duration is a policy judgement, not a fact. The check reports facts.

    This also pins the case tests/test_modules.py has always asserted.
    """
    assert evaluate({"Strict-Transport-Security": "max-age=1"}) == []


def test_hsts_directives_are_read_case_insensitively():
    assert evaluate({"Strict-Transport-Security": "MAX-AGE=31536000"}) == []


@pytest.mark.parametrize("value", ["DENY", "SAMEORIGIN", "sameorigin", " deny "])
def test_the_framing_values_browsers_honour_are_accepted(value):
    assert evaluate({"X-Frame-Options": value}) == []


def test_an_unrecognised_framing_value_gives_no_protection():
    finding = only(evaluate({"X-Frame-Options": "ALLOWALL"}))
    assert finding.evidence["state"] == "ineffective"
    assert "not a recognised value" in finding.detail


def test_allow_from_is_flagged_as_obsolete():
    finding = only(evaluate({"X-Frame-Options": "ALLOW-FROM https://example.invalid"}))
    assert "obsolete" in finding.detail


def test_content_type_options_must_be_exactly_nosniff():
    finding = only(evaluate({"X-Content-Type-Options": "enabled"}))
    assert finding.evidence["state"] == "ineffective"
    assert "not 'nosniff'" in finding.detail


def test_nosniff_is_accepted_whatever_its_casing():
    assert evaluate({"X-Content-Type-Options": "NoSniff"}) == []


def test_an_unsafe_referrer_policy_is_flagged():
    finding = only(evaluate({"Referrer-Policy": "unsafe-url"}))
    assert "full URL" in finding.detail


def test_an_unsafe_referrer_policy_is_found_among_several_tokens():
    assert only(evaluate({"Referrer-Policy": "no-referrer, unsafe-url"})).evidence["state"] == (
        "ineffective"
    )


def test_an_empty_referrer_policy_is_flagged():
    assert only(evaluate({"Referrer-Policy": "   "})).evidence["state"] == "ineffective"


def test_a_safe_referrer_policy_passes():
    assert evaluate({"Referrer-Policy": "strict-origin-when-cross-origin"}) == []


@pytest.mark.parametrize("token", ["'unsafe-inline'", "'unsafe-eval'"])
def test_a_policy_that_re_allows_injected_script_is_flagged(token):
    finding = only(evaluate({"Content-Security-Policy": f"default-src 'self'; script-src {token}"}))
    assert finding.evidence["state"] == "ineffective"
    assert token in finding.detail


def test_a_policy_naming_both_weaknesses_reports_both():
    finding = only(
        evaluate(
            {"Content-Security-Policy": "script-src 'unsafe-inline' 'unsafe-eval'"},
        )
    )
    assert "'unsafe-inline'" in finding.detail
    assert "'unsafe-eval'" in finding.detail


def test_a_restrictive_policy_passes():
    assert evaluate({"Content-Security-Policy": "default-src 'none'; script-src 'self'"}) == []


def test_an_ineffective_header_records_the_value_that_was_seen():
    """A reader has to be able to check the judgement without rescanning."""
    finding = only(evaluate({"X-Frame-Options": "ALLOWALL"}))
    assert finding.evidence["value"] == "ALLOWALL"
    assert finding.evidence["reason"]


def test_missing_and_ineffective_headers_are_reported_together():
    findings = evaluate({"X-Frame-Options": "ALLOWALL"}, drop=("Referrer-Policy",))
    states = {f.evidence["header"]: f.evidence["state"] for f in findings}
    assert states == {"x-frame-options": "ineffective", "referrer-policy": "missing"}


# ---------------------------------------------------------------------------
# Reaching the host at all
# ---------------------------------------------------------------------------


class Server(http.server.BaseHTTPRequestHandler):
    """Answers HEAD with whatever headers the test asked for."""

    headers_to_send: dict[str, str] = {}
    status = 200

    def do_HEAD(self):  # noqa: N802  (BaseHTTPRequestHandler's own naming)
        self.send_response(type(self).status)
        for name, value in type(self).headers_to_send.items():
            self.send_header(name, value)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def listener():
    servers = []

    def start(headers: dict[str, str], status: int = 200) -> str:
        Server.headers_to_send = headers
        Server.status = status
        srv = http.server.HTTPServer(("127.0.0.1", 0), Server)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}"

    yield start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def url_target(url: str) -> Target:
    return Target(raw=url, kind="url", value=url)


def test_a_live_host_is_graded_on_what_it_actually_sent(listener):
    url = listener({"X-Frame-Options": "ALLOWALL"})
    findings = HeaderSecurityCheck().run(url_target(url), {})
    states = {f.evidence["header"]: f.evidence["state"] for f in findings}
    assert states["x-frame-options"] == "ineffective"
    assert states["strict-transport-security"] == "missing"


def test_a_fully_hardened_live_host_produces_nothing(listener):
    url = listener(GOOD_HEADERS)
    assert HeaderSecurityCheck().run(url_target(url), {}) == []


def test_an_unreachable_host_is_reported_as_not_assessed_not_as_clean():
    """Was: an empty list, which reads exactly like a perfectly hardened site."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing is listening here now

    findings = HeaderSecurityCheck().run(url_target(f"http://127.0.0.1:{port}"), {})
    finding = only(findings)
    assert finding.evidence["state"] == "not_assessed"
    assert finding.severity == "info"
    assert "not a finding of good configuration" in finding.detail


def test_an_error_response_is_reported_as_not_assessed(listener):
    """Grading the headers of a 500 page says nothing about the application,
    so http_head withholds them — and that must not read as a pass either."""
    url = listener({}, status=500)
    assert only(HeaderSecurityCheck().run(url_target(url), {})).evidence["state"] == "not_assessed"


def test_the_not_assessed_finding_names_the_url_that_was_tried(listener):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    url = f"http://127.0.0.1:{port}"
    assert only(HeaderSecurityCheck().run(url_target(url), {})).evidence["url"] == url
