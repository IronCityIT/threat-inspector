"""
_util.py — shared helpers for scan modules (NOT a ScanModule itself).

Modules shell out to external scanners or hit HTTP/TLS endpoints. These helpers
guarantee graceful degradation: a missing tool, a timeout, or an unreachable
target returns an empty/None result instead of a traceback (the old monolith's
"tracebacks on bad input" was a called-out rough edge). One place to get this right.
"""

from __future__ import annotations

import logging
import shutil
import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

log = logging.getLogger("icit.scan.util")

# Defence in depth. targets.py already refuses non-http(s) targets, but modules
# also build URLs themselves (base + "/admin"), so the fetch helpers re-check
# rather than trusting their caller. urllib speaks file:// and ftp:// too.
ALLOWED_SCHEMES = ("http", "https")


def _is_fetchable(url: str) -> bool:
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme in ALLOWED_SCHEMES:
        return True
    log.warning("refusing to fetch %r: scheme %r is not http/https", url, scheme)
    return False


def tool_available(name: str) -> bool:
    """True if an external CLI scanner is on PATH."""
    return shutil.which(name) is not None


def run_cmd(cmd: list[str], timeout: int = 120, input_text: str | None = None) -> str | None:
    """Run a command; return stdout, or None on missing tool / error / timeout.

    Never raises — callers treat None as "capability unavailable, no findings".
    """
    if not tool_available(cmd[0]):
        return None
    try:
        proc = subprocess.run(  # noqa: S603  (fixed argv, no shell)
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return proc.stdout


def http_head(url: str, timeout: int = 15) -> dict[str, str] | None:
    """Fetch response headers for a URL. Returns a lowercased-key dict, or None.

    Headers are returned only for a SUCCESSFUL response (status < 400), which is
    the contract header_security_check depends on: grading the security headers
    of a 401 error page says nothing about the application behind it.

    None therefore means "no usable response", which lumps 401 in with an
    unreachable host. When the STATUS itself is the signal — an admin panel that
    answers 401 is very much there — use http_probe() instead.
    """
    probe = http_probe(url, timeout=timeout)
    if probe is None or probe.headers is None or probe.status >= 400:
        return None
    return probe.headers


@dataclass(frozen=True)
class HttpProbe:
    """What a single HEAD told us: the status, and headers when we got them."""

    status: int
    headers: dict[str, str] | None = None


def http_probe(url: str, timeout: int = 15) -> HttpProbe | None:
    """HEAD a URL and report the STATUS, including 4xx and 5xx.

    urlopen raises HTTPError (a URLError subclass) for any non-2xx/3xx, so a
    plain `except URLError: return None` collapses "401 Unauthorized" and
    "host unreachable" into the same answer. That distinction is the entire
    signal for an exposed management interface, so it is preserved here.

    Returns None only when there was no HTTP response at all (DNS failure,
    refused connection, timeout, TLS error).
    """
    if not _is_fetchable(url):
        return None
    req = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (scheme checked)
            return HttpProbe(
                status=int(resp.status), headers={k.lower(): v for k, v in resp.headers.items()}
            )
    except urllib.error.HTTPError as e:
        # A real HTTP response, just not a successful one.
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else None
        return HttpProbe(status=int(e.code), headers=headers)
    except (urllib.error.URLError, OSError, ValueError) as e:
        log.debug("no HTTP response from %s: %s", url, e)
        return None


def http_get(url: str, timeout: int = 15) -> str | None:
    """Fetch a URL body as text. Returns None on any error."""
    if not _is_fetchable(url):
        return None
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (scheme checked)
            data: bytes = resp.read()
            return data.decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, ValueError) as e:
        log.debug("GET %s failed: %s", url, e)
        return None


def fetch_cert(host: str, port: int = 443, timeout: int = 15) -> dict | None:
    """Return the peer TLS certificate dict (as from getpeercert()), or None."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return ssock.getpeercert()
    except (OSError, ssl.SSLError, ValueError):
        return None
