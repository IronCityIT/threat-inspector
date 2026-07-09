"""
_base.py — shared ingest behaviour for parser-backed FileModules.

Every FileModule here follows the same three lines: run the wrapped parser over
the file, convert, return. This mixin captures that so each concrete module is
just a declaration (which parser, which extensions, how it's branded).

It is a plain mixin, NOT a FileModule subclass, so registry discovery never picks
it up on its own — only the concrete `(ParserFileModule, FileModule)` classes are
real modules.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._convert import to_findings

if TYPE_CHECKING:
    from pathlib import Path

    from base import Finding

    from threat_inspector.parsers.base import BaseParser


class ParserFileModule:
    """Mix in ahead of FileModule: `class QualysIngest(ParserFileModule, FileModule)`."""

    name: str                   # provided by the FileModule half
    PARSER: type[BaseParser]    # set on each concrete subclass

    def ingest(self, file: Path, ctx: dict[str, Any]) -> list[Finding]:
        result = self.PARSER().parse(file)
        return to_findings(self.name, result)
