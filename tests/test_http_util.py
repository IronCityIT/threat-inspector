"""The shared HTTP helpers, exercised against a REAL local HTTP server.

Nothing here is mocked: a threaded http.server serves the status codes under
test on loopback, and the helpers make actual socket connections to it. Mocking
urlopen would have hidden the exact defect these tests exist to pin down —
urlopen RAISES HTTPError for 4xx/5xx, which is why the old `except URLError`
collapsed "401 Unauthorized" into "host unreachable".
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from modules._util import ALLOWED_SCHEMES, http_get, http_head, http_probe

# path -> status the stub server answers with
ROUTES = {
    "/ok": 200,
    "/admin": 401,
    "/manager": 403,
    "/missing": 404,
    "/gone": 410,
    "/broken": 500,
    "/moved": 302,
}


class Handler(BaseHTTPRequestHandler):
    def _respond(self, body: bytes = b""):
        status = ROUTES.get(self.path, 404)
        self.send_response(status)
        self.send_header("X-Probe-Path", self.path)
        self.send_header("Content-Length", str(len(body)))
        if status == 302:
            self.send_header("Location", "/ok")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_HEAD(self):  # noqa: N802 — BaseHTTPRequestHandler's required spelling
        self._respond()

    def do_GET(self):  # noqa: N802
        self._respond(b"hello")

    def log_message(self, *args):
        pass  # keep the test output clean


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    host, port = srv.server_address[:2]
    yield f"http://{host}:{port}"
    srv.shutdown()
    srv.server_close()


# ---- http_probe preserves the status ------------------------------------


@pytest.mark.parametrize(("path", "expected"), [(p, s) for p, s in ROUTES.items() if s != 302])
def test_probe_reports_the_real_status(server, path, expected):
    probe = http_probe(f"{server}{path}", timeout=5)
    assert probe is not None, f"{path} produced no probe at all"
    assert probe.status == expected


def test_probe_sees_auth_challenges_that_http_head_discards(server):
    """The exact defect: a 401 admin panel was indistinguishable from no host."""
    assert http_probe(f"{server}/admin", timeout=5).status == 401
    assert http_head(f"{server}/admin", timeout=5) is None


def test_probe_returns_none_when_there_is_no_http_response_at_all():
    # Port 1 on loopback: connection refused, so there is no status to report.
    assert http_probe("http://127.0.0.1:1/", timeout=5) is None


def test_probe_carries_headers_on_an_error_response(server):
    probe = http_probe(f"{server}/admin", timeout=5)
    assert probe.headers is not None
    assert probe.headers["x-probe-path"] == "/admin"


def test_head_still_returns_headers_for_a_success(server):
    headers = http_head(f"{server}/ok", timeout=5)
    assert headers is not None
    assert headers["x-probe-path"] == "/ok"


def test_get_reads_a_body(server):
    assert http_get(f"{server}/ok", timeout=5) == "hello"


# ---- scheme guard (defence in depth) ------------------------------------


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/a", "gopher://x/1"])
def test_non_http_schemes_are_refused_by_the_fetch_helpers(url):
    """targets.py guards the entry point; modules also build URLs themselves."""
    assert http_probe(url) is None
    assert http_head(url) is None
    assert http_get(url) is None


def test_allowed_schemes_are_exactly_http_and_https():
    assert set(ALLOWED_SCHEMES) == {"http", "https"}
