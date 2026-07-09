"""
_util.py — shared helpers for scan modules (NOT a ScanModule itself).

Modules shell out to external scanners or hit HTTP/TLS endpoints. These helpers
guarantee graceful degradation: a missing tool, a timeout, or an unreachable
target returns an empty/None result instead of a traceback (the old monolith's
"tracebacks on bad input" was a called-out rough edge). One place to get this right.
"""
from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import urllib.error
import urllib.request


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
    """Fetch response headers for a URL. Returns a lowercased-key dict, or None."""
    req = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (http(s) only below)
            return {k.lower(): v for k, v in resp.headers.items()}
    except (urllib.error.URLError, OSError, ValueError):
        return None


def http_get(url: str, timeout: int = 15) -> str | None:
    """Fetch a URL body as text. Returns None on any error."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
            data: bytes = resp.read()
            return data.decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, ValueError):
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
