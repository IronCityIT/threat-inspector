"""
example_recon.py — reference module (network-free) proving the pattern.

Delete this when porting a real tool. Each real capability from the existing
Claude-generated code becomes a module shaped exactly like this.
"""
from __future__ import annotations
from typing import Any
from base import Finding, ScanModule


class TargetProfile(ScanModule):
    name = "target_profile"
    description = "Classifies and profiles the supplied target."
    target_kinds = ("ip", "url", "domain", "hostname")
    groups = ("quick", "standard", "deep")

    def run(self, target, ctx: dict[str, Any]) -> list[Finding]:
        return [Finding(
            module=self.name,
            target=target.value,
            severity="info",
            title=f"{target.kind} target profiled",
            detail=f"Normalized {target.raw!r} -> {target.value!r} ({target.kind}).",
            evidence={"kind": target.kind, "raw": target.raw},
        )]
