"""Transport security: a certificate that fails validation is a finding.

`fetch_cert` validated the peer with a default context and returned None on any
failure. That one None had to stand for "host unreachable", "not serving TLS"
and "certificate rejected" alike — and `run()` read it as "no expiry finding".

So an EXPIRED certificate on a live host produced **nothing**. Measured against
a real listener before the change:

    expired certificate, live TLS listener -> fetch_cert() -> None -> 0 findings

Nothing is also what a perfectly healthy host reports. The module was silent
about the single condition it exists to catch, and the same silence covered a
self-signed certificate, a hostname mismatch and an untrusted issuer — every
certificate failure a browser refuses outright.

The certificate tests here stand up a real TLS listener on 127.0.0.1 with a
certificate this test issued from a throwaway CA of its own, and trust that CA
through SSL_CERT_FILE for the duration. Nothing here touches a third party, and
the grading API is never called — `run()` is exercised with the outbound fetch
stubbed out, because a test must not send a hostname to a third-party service.
"""

from __future__ import annotations

import http.server
import shutil
import socket
import ssl
import subprocess
import threading

import pytest
from modules import tls_cert_check
from modules._util import inspect_tls
from modules.tls_cert_check import (
    TlsCertCheck,
    _port,
    cert_finding,
    grade_finding,
    grade_findings,
    unreachable_finding,
    untrusted_finding,
)
from targets import Target

HOST = "127.0.0.1"

CA_CONFIG = """\
[ca]
default_ca = CA_default
[CA_default]
dir = .
database = $dir/index.txt
new_certs_dir = $dir/newcerts
serial = $dir/serial
default_md = sha256
policy = policy_any
email_in_dn = no
rand_serial = no
unique_subject = no
copy_extensions = copy
[policy_any]
commonName = supplied
[req]
distinguished_name = dn
[dn]
"""


@pytest.fixture(scope="module")
def ca(tmp_path_factory):
    """A throwaway certificate authority that can issue back-dated leaves.

    `openssl req -x509` cannot back-date, so an EXPIRED certificate — the case
    that matters most here — has to be issued by a CA with explicit
    -startdate/-enddate. Generated with the openssl CLI rather than the
    `cryptography` package: that package is only ever pulled in transitively,
    and a test must not depend on a library the project does not declare.

    Module-scoped: an RSA key costs seconds and every test can share the CA.
    """
    if shutil.which("openssl") is None:
        pytest.skip("openssl not available — cannot issue test certificates")

    root = tmp_path_factory.mktemp("ca")
    (root / "newcerts").mkdir()
    (root / "index.txt").touch()
    (root / "serial").write_text("01\n")
    (root / "ca.cnf").write_text(CA_CONFIG)

    def run(args):
        subprocess.run(args, cwd=root, check=True, capture_output=True)

    run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            "cakey.pem",
            "-out",
            "cacert.pem",
            "-days",
            "3650",
            "-nodes",
            "-subj",
            "/CN=Selftest CA",
        ]
    )

    issued: dict[tuple, tuple[str, str]] = {}

    def issue(name: str, san: str, startdate: str, enddate: str) -> tuple[str, str]:
        """Issue a leaf; returns (cert_path, key_path)."""
        key_cache = (name, san, startdate, enddate)
        if key_cache in issued:
            return issued[key_cache]
        run(
            [
                "openssl",
                "req",
                "-newkey",
                "rsa:2048",
                "-keyout",
                f"{name}key.pem",
                "-out",
                f"{name}.csr",
                "-nodes",
                "-subj",
                "/CN=127.0.0.1",
                "-addext",
                f"subjectAltName={san}",
            ]
        )
        run(
            [
                "openssl",
                "ca",
                "-config",
                "ca.cnf",
                "-batch",
                "-in",
                f"{name}.csr",
                "-out",
                f"{name}cert.pem",
                "-cert",
                "cacert.pem",
                "-keyfile",
                "cakey.pem",
                "-startdate",
                startdate,
                "-enddate",
                enddate,
                "-notext",
            ]
        )
        issued[key_cache] = (str(root / f"{name}cert.pem"), str(root / f"{name}key.pem"))
        return issued[key_cache]

    return {"root": str(root), "bundle": str(root / "cacert.pem"), "issue": issue}


@pytest.fixture
def trust_the_ca(ca, monkeypatch):
    """Make the throwaway CA the trust store for `ssl.create_default_context()`.

    create_default_context() honours SSL_CERT_FILE when it loads default certs,
    so this is what lets a CA-issued leaf reach the EXPIRY failure rather than
    stopping at "self-signed".
    """
    monkeypatch.setenv("SSL_CERT_FILE", ca["bundle"])
    return ca


class Handler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):  # noqa: N802  (BaseHTTPRequestHandler's own naming)
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def tls_listener():
    """Serve TLS on loopback with a given certificate; yields the port."""
    servers = []

    def start(cert_path: str, key_path: str) -> int:
        srv = http.server.HTTPServer((HOST, 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return srv.server_address[1]

    yield start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def closed_port() -> int:
    sock = socket.socket()
    sock.bind((HOST, 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


# ---------------------------------------------------------------------------
# The handshake, against real listeners
# ---------------------------------------------------------------------------


def test_an_expired_certificate_is_reported_as_expired(trust_the_ca, tls_listener):
    """The regression. Was: 0 findings against a live listener."""
    cert, key = trust_the_ca["issue"]("expired", f"IP:{HOST}", "20200101000000Z", "20200201000000Z")
    result = inspect_tls(HOST, port=tls_listener(cert, key))

    assert result.reachable is True
    assert result.verified is False
    assert "expired" in result.reason.lower()

    finding = untrusted_finding(result.reason, HOST)[0]
    assert finding.severity == "critical"
    assert finding.evidence["verification_error"] == result.reason


def test_a_certificate_that_is_not_yet_valid_is_reported(trust_the_ca, tls_listener):
    cert, key = trust_the_ca["issue"]("future", f"IP:{HOST}", "20900101000000Z", "20900201000000Z")
    result = inspect_tls(HOST, port=tls_listener(cert, key))
    assert result.reachable is True
    assert result.verified is False
    assert untrusted_finding(result.reason, HOST)[0].severity == "high"


def test_a_certificate_for_another_host_is_reported(trust_the_ca, tls_listener):
    cert, key = trust_the_ca["issue"](
        "mismatch", "DNS:other.selftest.invalid", "20200101000000Z", "20900101000000Z"
    )
    result = inspect_tls(HOST, port=tls_listener(cert, key))
    assert result.reachable is True
    assert result.verified is False
    assert untrusted_finding(result.reason, HOST) != []


def test_a_self_signed_certificate_is_reported(tls_listener, tmp_path):
    """No CA trusted here, so the leaf is untrusted on its own terms."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl not available")
    cert, key = str(tmp_path / "c.pem"), str(tmp_path / "k.pem")
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key,
            "-out",
            cert,
            "-days",
            "30",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            f"subjectAltName=IP:{HOST}",
        ],
        check=True,
        capture_output=True,
    )
    result = inspect_tls(HOST, port=tls_listener(cert, key))
    assert result.reachable is True
    assert result.verified is False
    assert untrusted_finding(result.reason, HOST)[0].severity == "high"


def test_a_valid_certificate_verifies_and_yields_its_expiry(trust_the_ca, tls_listener):
    cert, key = trust_the_ca["issue"]("valid", f"IP:{HOST}", "20200101000000Z", "20900101000000Z")
    result = inspect_tls(HOST, port=tls_listener(cert, key))
    assert result.reachable is True
    assert result.verified is True
    assert result.cert is not None
    assert result.cert.get("notAfter")


def test_nothing_listening_is_unreachable_not_untrusted():
    result = inspect_tls(HOST, port=closed_port())
    assert result.reachable is False
    assert result.verified is False
    assert result.error


# ---------------------------------------------------------------------------
# The module, end to end — with the third-party grading call stubbed out
# ---------------------------------------------------------------------------


@pytest.fixture
def no_grading_api(monkeypatch):
    """A test must never send a hostname to a third-party service."""
    monkeypatch.setattr(tls_cert_check, "http_get", lambda *a, **k: None)


def url_target(port: int) -> Target:
    value = f"https://{HOST}:{port}"
    return Target(raw=value, kind="url", value=value)


def test_the_module_reports_an_expired_certificate(trust_the_ca, tls_listener, no_grading_api):
    """Was: zero findings for a certificate that expired in 2020."""
    cert, key = trust_the_ca["issue"]("expired", f"IP:{HOST}", "20200101000000Z", "20200201000000Z")
    findings = TlsCertCheck().run(url_target(tls_listener(cert, key)), {})
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].title == "Certificate failed validation"


def test_the_module_reports_a_healthy_certificate(trust_the_ca, tls_listener, no_grading_api):
    cert, key = trust_the_ca["issue"]("valid", f"IP:{HOST}", "20200101000000Z", "20900101000000Z")
    findings = TlsCertCheck().run(url_target(tls_listener(cert, key)), {})
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].evidence["days_until_expiry"] > 0


def test_the_module_says_when_it_could_not_assess_rather_than_staying_silent(no_grading_api):
    findings = TlsCertCheck().run(url_target(closed_port()), {})
    assert len(findings) == 1
    assert findings[0].evidence["state"] == "not_assessed"
    assert findings[0].severity == "info"
    assert "not a finding of good configuration" in findings[0].detail


def test_a_url_target_is_inspected_on_its_own_port(trust_the_ca, tls_listener, no_grading_api):
    """urlparse().hostname drops the port, so an https://host:8443 target used
    to be inspected on 443 — a different service from the one named."""
    cert, key = trust_the_ca["issue"]("valid", f"IP:{HOST}", "20200101000000Z", "20900101000000Z")
    port = tls_listener(cert, key)
    findings = TlsCertCheck().run(url_target(port), {})
    assert findings[0].severity == "info"  # reached the listener, not port 443


# ---------------------------------------------------------------------------
# Port selection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "kind", "expected"),
    [
        ("https://host.selftest.invalid:8443/x", "url", 8443),
        ("https://host.selftest.invalid/x", "url", 443),
        ("http://host.selftest.invalid", "url", 443),
        ("host.selftest.invalid", "hostname", 443),
    ],
)
def test_the_port_comes_from_the_target_when_it_names_one(value, kind, expected):
    assert _port(Target(raw=value, kind=kind, value=value)) == expected


# ---------------------------------------------------------------------------
# Mapping a verification message to a finding
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("certificate has expired", "critical"),
        ("certificate revoked", "critical"),
        ("certificate is not yet valid", "high"),
        ("Hostname mismatch, certificate is not valid for '127.0.0.1'", "high"),
        ("self-signed certificate", "high"),
        ("self signed certificate in certificate chain", "high"),
        ("unable to get local issuer certificate", "high"),
        ("something openssl has not said before", "high"),
    ],
)
def test_each_verification_failure_maps_to_a_severity(reason, expected):
    assert untrusted_finding(reason, HOST)[0].severity == expected


def test_the_raw_verification_message_is_kept_as_evidence():
    """A reader has to be able to check the judgement."""
    finding = untrusted_finding("certificate has expired", HOST)[0]
    assert finding.evidence["verification_error"] == "certificate has expired"
    assert "certificate has expired" in finding.detail


def test_no_reason_means_no_finding():
    assert untrusted_finding("", HOST) == []


def test_the_unreachable_finding_names_the_endpoint_it_tried():
    finding = unreachable_finding(HOST, 8443, "connection refused")[0]
    assert finding.evidence == {
        "host": HOST,
        "port": 8443,
        "error": "connection refused",
        "state": "not_assessed",
    }


# ---------------------------------------------------------------------------
# Grading every endpoint
# ---------------------------------------------------------------------------


def test_every_endpoint_is_graded_not_only_the_first():
    """Was: endpoints[0] alone. A name resolving to several addresses is graded
    per address, and one node left on an old configuration is exactly the
    finding worth having."""
    body = '{"endpoints":[{"grade":"A+"},{"grade":"F"},{"grade":"B"}]}'
    findings = grade_findings(body, HOST)
    assert [f.evidence["grade"] for f in findings] == ["A+", "F", "B"]
    assert [f.severity for f in findings] == ["info", "high", "info"]


def test_an_endpoint_still_being_analysed_is_skipped_not_invented():
    """The grading API is asynchronous — no grade yet is the normal first state."""
    body = '{"endpoints":[{"statusMessage":"In progress"},{"grade":"F"}]}'
    findings = grade_findings(body, HOST)
    assert len(findings) == 1
    assert findings[0].evidence["grade"] == "F"


def test_a_response_with_no_endpoints_yields_nothing():
    assert grade_findings('{"status":"IN_PROGRESS"}', HOST) == []


def test_malformed_grading_json_is_not_a_crash():
    assert grade_findings("not json", HOST) == []


def test_an_unexpected_endpoints_shape_is_not_a_crash():
    assert grade_findings('{"endpoints":"nope"}', HOST) == []
    assert grade_findings('{"endpoints":[null,"x"]}', HOST) == []


@pytest.mark.parametrize("grade", ["C", "D", "E", "F", "T", "M", "f"])
def test_a_weak_grade_is_high_severity(grade):
    assert grade_finding(grade, HOST)[0].severity == "high"


@pytest.mark.parametrize("grade", ["A+", "A", "A-", "B"])
def test_a_passing_grade_is_informational(grade):
    assert grade_finding(grade, HOST)[0].severity == "info"


def test_no_grade_means_no_finding():
    assert grade_finding(None, HOST) == []
    assert grade_finding("", HOST) == []


# ---------------------------------------------------------------------------
# Expiry banding (kept from the existing suite, made explicit)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("days", "expected"),
    [(-1, "critical"), (0, "critical"), (10, "high"), (25, "medium"), (200, "info")],
)
def test_days_until_expiry_bands(days, expected):
    assert cert_finding(days, HOST)[0].severity == expected


def test_an_unknown_expiry_yields_no_finding():
    assert cert_finding(None, HOST) == []
