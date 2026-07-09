"""
base.py — the contract every module implements.

Every capability in every ICIT tool is a ScanModule. Same shape everywhere:
a name, a description, the target kinds it handles, the groups it belongs to,
and a run() that returns Findings. Port existing Claude-generated scan logic
into these — one module per capability, no monoliths.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from targets import Target

SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Finding:
    module: str
    target: str
    severity: str            # one of SEVERITIES
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
    name: str = ""                 # short id, e.g. "port_scan"
    description: str = ""          # human-readable, client-safe (white-labeled)
    target_kinds: tuple[str, ...] = ("ip", "url", "domain", "hostname")
    groups: tuple[str, ...] = ("standard",)   # e.g. ("quick","standard","deep")

    def applies_to(self, kind: str) -> bool:
        return kind in self.target_kinds

    @abstractmethod
    def run(self, target: Target, ctx: dict[str, Any]) -> list[Finding]:
        """Execute against one target. Return a list of Findings (may be empty)."""
        raise NotImplementedError
