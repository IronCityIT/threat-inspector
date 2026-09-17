"""
targets.py — normalize and validate scan targets.

Accepts single values, comma lists, or files. Classifies each into a kind
(ip, url, domain, hostname), expands CIDR to individual IPs, dedupes, and
validates. This is what fixes "enter in ips urls etc" — one parser, every tool.

The hard rules live here, because this is the only place a caller-supplied string
becomes something a module will connect to:

  * URL targets are restricted to http/https. Modules hand target.value straight
    to urllib, which also speaks file://, ftp:// and (via handlers) more. A
    `file://localhost/etc/passwd` target used to classify as a perfectly valid
    URL and would have been fetched as a local file read.
  * Loopback, link-local and unspecified addresses are rejected unless explicitly
    allowed. 169.254.169.254 is the cloud instance-metadata endpoint; a scan
    running on a hosted runner must not be steerable into reading its own
    credentials. 0.0.0.0 and :: connect to the local machine. RFC1918 space is
    deliberately still allowed — scanning a client's internal range is the
    product's actual job.
  * The guard recognises every spelling the resolver does, not just the dotted
    quad. getaddrinfo() hands inet_aton() forms straight to connect(), so
    "0x7f000001", "2130706433", "127.1" and "0177.0.0.1" all reach 127.0.0.1,
    and an IPv4-mapped IPv6 literal ("::ffff:127.0.0.1") reaches its inner
    address on a dual-stack socket. Those spellings are canonicalised to the
    address they denote before the guard runs, so what is checked is what is
    scanned.
  * A range wider than a /16 is refused before expansion. Expansion is eager —
    every address becomes a Target before a module runs — so an unbounded range
    is a hang (2001:db8::/64 never returns) or an out-of-memory (a /8 is sixteen
    million objects). The refusal says how to proceed instead of trying and
    never answering.

Bad input yields a TargetError carrying a human-readable reason, never a bare
library traceback. parse_targets_report() collects those per token so one typo in
a 500-line targets file does not discard the other 499.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import cast
from urllib.parse import urlparse

# ip_network is generic over its address family; naming the union keeps the guard
# signatures concrete (a bare _BaseAddress exposes neither is_loopback nor
# is_link_local nor is_unspecified, the properties the guard exists to read).
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Schemes a scan module may be pointed at. Anything else is refused outright.
ALLOWED_SCHEMES = ("http", "https")

# Hostnames that resolve to the local machine. Blocked with the loopback range.
_LOCAL_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}

# Widest range a single token may expand to: one IPv4 /16. Anything larger is
# refused up front (see the module docstring).
MAX_RANGE_ADDRESSES = 65_536

# Only tokens made of these characters are offered to inet_aton(). It is a gate,
# not the parser: glibc's inet_aton() tolerates trailing junk after whitespace,
# and a hostname like "web-1" must never be handed to it at all.
_ATON_CANDIDATE = re.compile(r"[0-9a-fA-FxX.]+")


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


def _ip_literal(host: str) -> IPAddress | None:
    """The address `host` denotes as a literal, or None if it is a name.

    Beyond the dotted quad and RFC 4291 forms ipaddress knows, this accepts the
    inet_aton() spellings the resolver treats as literals: decimal, hex, octal
    and short dotted forms. Every such token is canonicalised, so the guard and
    the scanner agree on which address is meant.
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    if not _ATON_CANDIDATE.fullmatch(host):
        return None
    try:
        packed = socket.inet_aton(host)
    except OSError:
        return None  # looks numeric but is not an address: "1e10", "0x", "123abc"
    return ipaddress.IPv4Address(packed)


def _check_ip(ip: IPAddress, token: str, allow_local: bool) -> None:
    if allow_local:
        return
    # An IPv4-mapped IPv6 literal reaches its inner address, and on 3.12
    # ::ffff:127.0.0.1 does not report is_loopback — judge the inner address.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_unspecified:
        raise TargetError(
            f"{token!r} is the unspecified address, which connects to the local "
            "machine; pass --allow-local to scan it"
        )
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
    literal = _ip_literal(host)
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
        if net.num_addresses > MAX_RANGE_ADDRESSES:
            raise TargetError(
                f"{token!r} spans {net.num_addresses:,} addresses; a single range "
                f"may expand to at most {MAX_RANGE_ADDRESSES:,} (an IPv4 /16). "
                "Split it into smaller ranges or list the hosts in a targets file."
            )
        # .hosts() is empty for a single-address network (/32, /128), which must
        # still resolve to that one address rather than to nothing at all.
        hosts: list[IPAddress] = list(net.hosts()) or [cast(IPAddress, net.network_address)]
        for ip in hosts:
            _check_ip(ip, token, allow_local)
        return [Target(raw=token, kind="ip", value=str(ip)) for ip in hosts]

    # Bare IP, in any spelling the resolver would treat as a literal
    literal = _ip_literal(token)
    if literal is not None:
        _check_ip(literal, token, allow_local)
        return [Target(raw=token, kind="ip", value=str(literal))]

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
