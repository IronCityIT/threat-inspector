"""
base.py — the contract every module implements.

Two module TYPES, both first-class, both returning the same Finding:

  ScanModule.run(target, ctx)   — ACTIVE capabilities. Given a live target
                                  (ip, url, domain, hostname), reach out and probe.
  FileModule.ingest(file, ctx)  — PASSIVE capabilities. Given an uploaded scan
                                  export on disk, parse it into findings.

Same shape everywhere: a name, a client-safe description, the inputs it handles,
the groups it belongs to. Port existing Claude-generated logic into these — one
module per capability, no monoliths. Never bend run(target, ctx) to swallow a
file: file ingestion is its own contract (ingest) so neither side is compromised.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

    from targets import Target

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Finding:
    module: str
    target: str
    severity: str  # one of SEVERITIES
    title: str
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity!r}, use one of {SEVERITIES}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ScanModule(ABC):
    # Set these on each subclass.
    name: str = ""  # short id, e.g. "port_scan"
    description: str = ""  # human-readable, client-safe (white-labeled)
    target_kinds: tuple[str, ...] = ("ip", "url", "domain", "hostname")
    groups: tuple[str, ...] = ("standard",)  # e.g. ("quick","standard","deep")

    def applies_to(self, kind: str) -> bool:
        return kind in self.target_kinds

    @abstractmethod
    def run(self, target: Target, ctx: dict[str, Any]) -> list[Finding]:
        """Execute against one target. Return a list of Findings (may be empty)."""
        raise NotImplementedError


class FileModule(ABC):
    """Ingests an uploaded scan export and normalizes it into Findings.

    The passive counterpart to ScanModule. There is no live target — the input is
    a file already on disk (a vendor scan export the client uploaded). Each subclass
    wraps exactly one export format, so module selection ("ingest only these") stays
    meaningful and maps 1:1 to the dashboard, same as the active scanners.
    """

    # Set these on each subclass.
    name: str = ""  # short id, e.g. "qualys_ingest"
    description: str = ""  # human-readable, client-safe (white-labeled)
    extensions: tuple[str, ...] = ()  # lowercased, with dot: (".xml", ".csv")
    groups: tuple[str, ...] = ("ingest",)  # e.g. ("ingest","deep")

    def accepts(self, path: Path) -> bool:
        """True if this module can, by extension, handle the file. When several
        modules accept the same extension the runtime disambiguates by content."""
        return path.suffix.lower() in self.extensions

    @abstractmethod
    def ingest(self, file: Path, ctx: dict[str, Any]) -> list[Finding]:
        """Parse one file into a list of Findings (may be empty)."""
        raise NotImplementedError
