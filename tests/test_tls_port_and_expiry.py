"""Transport security: the grade belongs to one port, and "expired" means expired.

Two things the module told clients that were not true:

  * The external grading service only ever grades port 443, and it was asked
    about the bare hostname whatever port was inspected. A client who scanned
    https://host:8443 was handed the port-443 grade as if it were theirs.
  * timedelta.days is 0 for anything under 24 hours, and 0 was worded "has
    expired". run() only reaches that wording for a certificate that has just
    passed verification, so a working certificate was reported as expired.

Nothing here touches the network: the handshake and the outbound fetch are both
stubbed in the module under test.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest
from modules import tls_cert_check
from modules._util import TlsInspection
from modules.tls_cert_check import TlsCertCheck
from targets import Target

HOST = "host.selftest.invalid"
GRADE_BODY = '{"endpoints":[{"grade":"A+"}]}'


def target(value: str, kind: str = "url") -> Target:
    return Target(raw=value, kind=kind, value=value)


def verified(remaining: timedelta) -> TlsInspection:
    """A handshake that verified a certificate with this long left to run."""
    expiry = datetime.now(timezone.utc) + remaining
    not_after = expiry.strftime("%b %d %H:%M:%S %Y GMT")
    return TlsInspection(reachable=True, verified=True, cert={"notAfter": not_after})


HEALTHY = verified(timedelta(days=200, hours=1))
UNTRUSTED = TlsInspection(reachable=True, verified=False, reason="self-signed certificate")
UNREACHABLE = TlsInspection(reachable=False, verified=False, error="connection refused")


@pytest.fixture
def scan(monkeypatch):
    """Run the module against a stubbed handshake and a grading reply of A+.

    Returns (findings, ports inspected, URLs requested).
    """

    def run(tgt: Target, inspection: TlsInspection = HEALTHY):
        ports: list[int] = []
        requested: list[str] = []

        def fake_inspect(host, port=443, **_):
            assert host == HOST
            ports.append(port)
            return inspection

        def fake_get(url, **_):
            requested.append(url)
            return GRADE_BODY

        monkeypatch.setattr(tls_cert_check, "inspect_tls", fake_inspect)
        monkeypatch.setattr(tls_cert_check, "http_get", fake_get)
        return TlsCertCheck().run(tgt, {}), ports, requested

    return run


def grades(findings) -> list[str]:
    return [f.evidence["grade"] for f in findings if "grade" in f.evidence]


# ---------------------------------------------------------------------------
# The grade is for port 443 and no other
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("port", [8443, 80, 4443])
def test_another_port_is_never_credited_with_the_port_443_grade(scan, port):
    findings, ports, requested = scan(target(f"https://{HOST}:{port}"))

    assert ports == [port]
    assert requested == [], "the grading service must not be asked about another port"
    assert grades(findings) == []
    assert len(findings) == 1
    assert findings[0].evidence["transport_grade"] == "not_assessed"
    # The marker is added to the stored evidence, not swapped in for it.
    assert findings[0].evidence["days_until_expiry"] == 200


@pytest.mark.parametrize(
    ("inspection", "title", "kept"),
    [
        (
            UNREACHABLE,
            "Transport security could not be assessed",
            {"host": HOST, "port": 8443, "error": "connection refused", "state": "not_assessed"},
        ),
        (
            UNTRUSTED,
            "Certificate failed validation",
            {"verification_error": "self-signed certificate"},
        ),
    ],
)
def test_a_failed_inspection_on_another_port_is_still_exactly_one_finding(
    scan, inspection, title, kept
):
    findings, _, requested = scan(target(f"https://{HOST}:8443"), inspection)

    assert requested == []
    assert [f.title for f in findings] == [title]
    assert findings[0].evidence == {**kept, "transport_grade": "not_assessed"}


@pytest.mark.parametrize(
    "tgt",
    [
        target(f"https://{HOST}"),
        target(f"https://{HOST}:443"),
        target(f"https://{HOST}:443/login"),
        target(HOST, kind="domain"),
    ],
    ids=["no-port", "explicit-443", "explicit-443-path", "bare-domain"],
)
def test_port_443_is_still_graded_and_the_request_names_only_the_host(scan, tgt):
    findings, ports, requested = scan(tgt)

    assert ports == [443]
    assert grades(findings) == ["A+"]
    assert len(requested) == 1
    assert parse_qs(urlparse(requested[0]).query)["host"] == [HOST]
    assert all("transport_grade" not in f.evidence for f in findings)


@pytest.mark.parametrize("inspection", [UNREACHABLE, UNTRUSTED], ids=["unreachable", "untrusted"])
def test_port_443_is_graded_even_when_the_certificate_could_not_be_verified(scan, inspection):
    findings, _, _ = scan(target(f"https://{HOST}"), inspection)
    assert len(findings) == 2
    assert grades(findings) == ["A+"]


# ---------------------------------------------------------------------------
# "Expired" is only said of a certificate that has expired
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("port", [443, 8443])
def test_a_certificate_with_hours_left_is_expiring_not_expired(scan, port):
    findings, _, _ = scan(target(f"https://{HOST}:{port}"), verified(timedelta(hours=5)))
    finding = findings[0]

    assert finding.severity == "critical"
    assert "expires within 24 hours" in finding.detail
    assert "expired" not in finding.detail.lower()
    # Stored results are keyed on these; they do not change.
    assert finding.title == "Certificate expiry: 0 day(s) remaining"
    assert finding.evidence["days_until_expiry"] == 0


def test_a_certificate_hours_past_its_expiry_has_expired(scan):
    findings, _, _ = scan(target(f"https://{HOST}:8443"), verified(timedelta(hours=-5)))

    assert findings[0].severity == "critical"
    assert "has expired" in findings[0].detail
    assert findings[0].evidence["days_until_expiry"] == -1


@pytest.mark.parametrize(
    ("days", "severity"),
    [(10, "high"), (25, "medium"), (200, "info")],
)
def test_the_other_expiry_bands_are_unchanged(scan, days, severity):
    # An hour over, so the whole-day count cannot tick down mid-test.
    findings, _, _ = scan(target(f"https://{HOST}:8443"), verified(timedelta(days=days, hours=1)))

    assert findings[0].severity == severity
    assert findings[0].title == f"Certificate expiry: {days} day(s) remaining"
    assert findings[0].evidence["days_until_expiry"] == days
