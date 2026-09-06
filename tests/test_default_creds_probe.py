"""Does the exposed-management-interface check actually find one?

The pure `evaluate()` mapping was well covered, but nothing exercised how the
module reaches a host — and that was where it was broken. `_to_base_url` built
one `https://{value}` for every non-URL target, so against an `ip` target:

  * a self-signed certificate (an IP has no name to match, so validation fails)
    made urlopen raise, which the probe reports as "no HTTP response";
  * a plain-HTTP panel was never tried at all.

Both returned **zero findings** against a management interface answering 401.
Reproduced against real listeners before the change:

    HTTPS self-signed, bare IP  -> 0 findings
    HTTP only, bare IP          -> 0 findings
    explicit http:// URL        -> 2 findings   (the only shape that worked)

Appliances on an internal range are the population most likely to still hold
default credentials, and they are precisely the hosts that answer on a bare IP
behind a self-signed certificate. CLAUDE.md calls those internal ranges the
product's actual job.

These tests use real sockets on 127.0.0.1, against listeners the test process
starts and owns. Nothing here touches a third party.
"""

from __future__ import annotations

import http.server
import shutil
import socket
import ssl
import subprocess
import threading

import pytest
from modules.default_creds_check import DefaultCredsCheck, _candidate_bases
from targets import Target

# Paths the fake appliance answers 401 on; everything else is a 404.
GUARDED = ("/admin", "/console")


class Appliance(http.server.BaseHTTPRequestHandler):
    """A management interface that is present and asking for credentials."""

    requests: list[str] = []

    def do_HEAD(self):  # noqa: N802  (BaseHTTPRequestHandler's own naming)
        type(self).requests.append(self.path)
        if self.path.rstrip("/") in GUARDED or self.path == "/":
            self.send_response(401 if self.path.rstrip("/") in GUARDED else 200)
        else:
            self.send_response(404)
        self.end_headers()

    def log_message(self, *args):
        pass  # keep the test output readable


@pytest.fixture
def appliance():
    """Start a listener on loopback; yields a factory for (host:port, requests)."""
    servers = []

    def start(tls_cert=None):
        Appliance.requests = []
        srv = http.server.HTTPServer(("127.0.0.1", 0), Appliance)
        if tls_cert is not None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(tls_cert[0], tls_cert[1])
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"127.0.0.1:{srv.server_address[1]}"

    yield start
    for srv in servers:
        srv.shutdown()
        srv.server_close()


@pytest.fixture(scope="module")
def self_signed(tmp_path_factory):
    """A self-signed certificate, as an appliance would present.

    Generated with openssl rather than the `cryptography` package: that package
    is only ever pulled in transitively here, and a test must not depend on a
    library the project does not declare.

    Module-scoped because generating an RSA key costs ~2s and the certificate is
    read-only — every test in this file can share one.
    """
    if shutil.which("openssl") is None:
        pytest.skip("openssl not available — cannot generate a self-signed cert")
    tmp_path = tmp_path_factory.mktemp("tls")
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=appliance.selftest.invalid",
        ],
        check=True,
        capture_output=True,
    )
    return str(cert), str(key)


def ip_target(hostport: str) -> Target:
    return Target(raw=hostport, kind="ip", value=hostport)


# ---------------------------------------------------------------------------
# The regression: a bare IP now gets probed properly
# ---------------------------------------------------------------------------


def test_a_plain_http_panel_on_a_bare_ip_is_found(appliance):
    """Was 0 findings: only https:// was ever tried."""
    findings = DefaultCredsCheck().run(ip_target(appliance()), {})
    assert {f.evidence["path"] for f in findings} == set(GUARDED)
    assert all(f.evidence["status"] == 401 for f in findings)


def test_a_self_signed_https_panel_on_a_bare_ip_is_found(appliance, self_signed):
    """Was 0 findings: validation fails on an IP, and the failure looked like silence."""
    findings = DefaultCredsCheck().run(ip_target(appliance(tls_cert=self_signed)), {})
    assert {f.evidence["path"] for f in findings} == set(GUARDED)


def test_evidence_says_which_scheme_answered_and_whether_tls_was_validated(appliance, self_signed):
    """A reader must be able to tell an unvalidated probe from a validated one."""
    http_findings = DefaultCredsCheck().run(ip_target(appliance()), {})
    assert http_findings[0].evidence["scheme"] == "http"
    assert http_findings[0].evidence["tls_verified"] is True  # no TLS to validate

    https_findings = DefaultCredsCheck().run(ip_target(appliance(tls_cert=self_signed)), {})
    assert https_findings[0].evidence["scheme"] == "https"
    assert https_findings[0].evidence["tls_verified"] is False


def test_an_explicit_url_target_still_works(appliance):
    """The one shape that worked before must keep working."""
    hostport = appliance()
    target = Target(raw="x", kind="url", value=f"http://{hostport}")
    findings = DefaultCredsCheck().run(target, {})
    assert {f.evidence["path"] for f in findings} == set(GUARDED)


def test_a_host_with_nothing_listening_yields_no_findings():
    """Absence of a web surface is still absence — not a finding, not a crash."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing is listening here now
    assert DefaultCredsCheck().run(ip_target(f"127.0.0.1:{port}"), {}) == []


def test_the_base_is_resolved_with_one_request_not_one_per_path(appliance):
    """Nine admin paths must not mean nine scheme negotiations.

    The base is settled once against "/", then every path is probed on it. This
    pins the request count so a future edit cannot quietly triple the traffic
    this module sends at a client's host.
    """
    DefaultCredsCheck().run(ip_target(appliance()), {})
    root_probes = [p for p in Appliance.requests if p == "/"]
    assert len(root_probes) == 1
    assert len(Appliance.requests) == 1 + 9  # the root probe, then nine paths


# ---------------------------------------------------------------------------
# Candidate ordering, without the network
# ---------------------------------------------------------------------------


def test_validated_https_is_tried_before_anything_else():
    candidates = _candidate_bases(Target(raw="h", kind="hostname", value="host.selftest.invalid"))
    assert candidates == [
        ("https://host.selftest.invalid", True),
        ("https://host.selftest.invalid", False),
        ("http://host.selftest.invalid", True),
    ]


def test_an_explicit_url_keeps_its_scheme_and_is_not_downgraded():
    """A caller who said https:// must never be probed over http://."""
    candidates = _candidate_bases(
        Target(raw="u", kind="url", value="https://host.selftest.invalid")
    )
    assert candidates == [("https://host.selftest.invalid", True)]
    assert not any(base.startswith("http://") for base, _ in candidates)


def test_an_explicit_http_url_is_not_silently_upgraded():
    candidates = _candidate_bases(Target(raw="u", kind="url", value="http://host.selftest.invalid"))
    assert candidates == [("http://host.selftest.invalid", True)]


def test_a_trailing_slash_on_a_url_target_is_not_doubled():
    candidates = _candidate_bases(
        Target(raw="u", kind="url", value="http://host.selftest.invalid/")
    )
    assert candidates == [("http://host.selftest.invalid", True)]
