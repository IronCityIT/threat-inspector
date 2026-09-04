"""
targets.py — normalize and validate scan targets.

Accepts single values, comma lists, or files. Classifies each into a kind
(ip, url, domain, hostname), expands CIDR to individual IPs, dedupes, and
validates. This is what fixes "enter in ips urls etc" — one parser, every tool.

Two hard rules live here, because this is the only place a caller-supplied string
becomes something a module will connect to:

  * URL targets are restricted to http/https. Modules hand target.value straight
    to urllib, which also speaks file://, ftp:// and (via handlers) more. A
    `file://localhost/etc/passwd` target used to classify as a perfectly valid
    URL and would have been fetched as a local file read.
  * Loopback and link-local addresses are rejected unless explicitly allowed.
    169.254.169.254 is the cloud instance-metadata endpoint; a scan running on a
    hosted runner must not be steerable into reading its own credentials.
    RFC1918 space is deliberately still allowed — scanning a client's internal
    range is the product's actual job.

Bad input yields a TargetError carrying a human-readable reason, never a bare
library traceback. parse_targets_report() collects those per token so one typo in
a 500-line targets file does not discard the other 499.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import cast
from urllib.parse import urlparse

# ip_network is generic over its address family; naming the union keeps the guard
# signatures concrete (a bare _BaseAddress exposes neither is_loopback nor
# is_link_local, which are the two properties the guard exists to read).
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Schemes a scan module may be pointed at. Anything else is refused outright.
ALLOWED_SCHEMES = ("http", "https")

# Hostnames that resolve to the local machine. Blocked with the loopback range.
_LOCAL_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}


class TargetError(ValueError):
    """A target could not be parsed or is not permitted. Carries a clear reason."""


@dataclass(frozen=True)
class Target:
    raw: str  # what the user typed
    kind: str  # one of: ip, url, domain, hostname
    value: str  # normalized value (ip string, url, or host)


@dataclass
class TargetReport:
    """Result of parsing a batch: what resolved, and why anything did not."""

    targets: list[Target] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _check_ip(ip: IPAddress, token: str, allow_local: bool) -> None:
    if allow_local:
        return
    if ip.is_loopback:
        raise TargetError(f"{token!r} is a loopback address; pass --allow-local to scan it")
    if ip.is_link_local:
        raise TargetError(
            f"{token!r} is link-local (this range holds the cloud instance-metadata "
            "endpoint); pass --allow-local to scan it"
        )


def _check_url(token: str, allow_local: bool) -> Target:
    parsed = urlparse(token)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise TargetError(
            f"{token!r} uses unsupported scheme {scheme or '(none)'!r}; "
            f"only {'/'.join(ALLOWED_SCHEMES)} targets are scanned"
        )
    host = parsed.hostname
    if not host:
        raise TargetError(f"{token!r} is not a usable URL: no host")
    if not allow_local and host.lower() in _LOCAL_HOSTNAMES:
        raise TargetError(f"{token!r} points at the local machine; pass --allow-local to scan it")
    # Parse first, check second. TargetError subclasses ValueError, so wrapping
    # the _check_ip call in `except ValueError` would swallow the very rejection
    # it is there to raise — which is exactly how a metadata-endpoint URL slipped
    # through the first cut of this guard.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None  # a name, not a literal IP — nothing more to check here
    if literal is not None:
        _check_ip(literal, token, allow_local)
    return Target(raw=token, kind="url", value=token)


def _classify(token: str, allow_local: bool = False) -> list[Target]:
    token = token.strip()
    if not token:
        return []

    # URL (has a scheme)
    if "://" in token:
        return [_check_url(token, allow_local)]

    # CIDR -> expand to host IPs
    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError as e:
            raise TargetError(f"{token!r} is not a valid network range: {e}") from e
        # .hosts() is empty for a single-address network (/32, /128), which must
        # still resolve to that one address rather than to nothing at all.
        hosts: list[IPAddress] = list(net.hosts()) or [cast(IPAddress, net.network_address)]
        for ip in hosts:
            _check_ip(ip, token, allow_local)
        return [Target(raw=token, kind="ip", value=str(ip)) for ip in hosts]

    # Bare IP
    try:
        ip = ipaddress.ip_address(token)
    except ValueError:
        pass
    else:
        _check_ip(ip, token, allow_local)
        return [Target(raw=token, kind="ip", value=str(ip))]

    # A bare scheme-less token must still look like a host, not a URL fragment
    # or a stray shell argument. "javascript:alert(1)" used to sail through as a
    # perfectly good "hostname".
    if any(c in token for c in " \t/?#@:\\"):
        raise TargetError(f"{token!r} is not a valid IP, CIDR, URL, domain or hostname")

    lowered = token.lower()
    if not allow_local and lowered in _LOCAL_HOSTNAMES:
        raise TargetError(f"{token!r} points at the local machine; pass --allow-local to scan it")

    # Domain vs hostname: a dotted name with a TLD-ish last label = domain
    if "." in token and not token.endswith("."):
        return [Target(raw=token, kind="domain", value=lowered)]

    return [Target(raw=token, kind="hostname", value=lowered)]


def _tokenize(values: list[str] | None, files: list[str] | None) -> tuple[list[str], list[str]]:
    """Flatten inline values and target files into tokens, plus any read errors."""
    tokens: list[str] = []
    errors: list[str] = []
    for v in values or []:
        tokens.extend(part for part in v.split(",") if part.strip())
    for path in files or []:
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.split("#", 1)[0].strip()  # strip comments
                    if line:
                        tokens.append(line)
        except OSError as e:
            errors.append(f"--targets-file {path}: {e.strerror or e}")
    return tokens, errors


def parse_targets_report(
    values: list[str] | None = None,
    files: list[str] | None = None,
    allow_local: bool = False,
) -> TargetReport:
    """Parse from inline values and/or files, collecting per-token failures.

    One bad token does not sink the batch: it is recorded in `errors` and the
    remaining targets still resolve. The caller decides whether to proceed.
    """
    tokens, errors = _tokenize(values, files)

    report = TargetReport(errors=errors)
    seen: set[tuple[str, str]] = set()
    for tok in tokens:
        try:
            classified = _classify(tok, allow_local)
        except TargetError as e:
            report.errors.append(str(e))
            continue
        for t in classified:
            key = (t.kind, t.value)
            if key not in seen:
                seen.add(key)
                report.targets.append(t)
    return report


def parse_targets(
    values: list[str] | None = None,
    files: list[str] | None = None,
    allow_local: bool = False,
) -> list[Target]:
    """Strict form: returns Targets, raises TargetError on the first bad token."""
    report = parse_targets_report(values, files, allow_local)
    if report.errors:
        raise TargetError(report.errors[0])
    return report.targets
