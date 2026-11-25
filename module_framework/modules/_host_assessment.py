"""
_host_assessment.py — was the host actually scanned? (NOT a ScanModule itself).

A scan that timed out, failed, got no response or could not resolve the name
parses to zero findings, which in a report is identical to a clean host. The
port, service and known-vulnerability checks share this one decision so that
"nothing found" is only ever said about a host that was really looked at.
"""

from __future__ import annotations

import re

from base import Finding

DID_NOT_COMPLETE = "did not complete"
NO_RESPONSE = "no response"
ENDED_EARLY = "ended early"

# Client-facing: never name the scanner or quote its output here.
_EXPLANATIONS = {
    DID_NOT_COMPLETE: "The scan of {host} did not complete",
    NO_RESPONSE: "{host} did not respond, or its name could not be resolved",
    ENDED_EARLY: "The scan of {host} ended early and any results listed for it are incomplete",
}

# nmap's closing line, in its file form (what `-oN -` prints) and its
# interactive form:
#   # Nmap done at Wed Nov 25 00:10:09 2026 -- 1 IP address (1 host up) scanned in 9.12 seconds
#   Nmap done: 1 IP address (1 host up) scanned in 9.12 seconds
# Matched against the last line only: service banners and script output are
# chosen by the remote host and must not be able to pass for it.
_SUMMARY_RE = re.compile(
    r"(?:# Nmap done at .+ -- |Nmap done: )\d+ IP address(?:es)? \((\d+) hosts? up\) scanned in "
)


def not_assessed_reason(raw: str | None) -> str | None:
    """Why this output does not show an assessed host, or None if it does."""
    text = (raw or "").strip()
    if not text:
        return DID_NOT_COMPLETE
    summary = _SUMMARY_RE.match(text.rsplit("\n", 1)[-1])
    if summary is None:
        return ENDED_EARLY
    if int(summary.group(1)) == 0:
        return NO_RESPONSE
    return None


def not_assessed_findings(
    raw: str | None, *, module: str, host: str, title: str, subject: str
) -> list[Finding]:
    """One info finding if the host was not assessed, otherwise nothing.

    `subject` is what went unexamined, e.g. "open ports".
    """
    reason = not_assessed_reason(raw)
    if reason is None:
        return []
    return [
        Finding(
            module=module,
            target=host,
            severity="info",
            title=title,
            detail=(
                f"{_EXPLANATIONS[reason].format(host=host)}, so its {subject} could not be "
                "assessed. This is not a clean result."
            ),
            evidence={"host": host, "reason": reason, "state": "not_assessed"},
        )
    ]
