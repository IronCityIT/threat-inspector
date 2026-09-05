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

from base import IngestReport

from ._convert import to_findings

if TYPE_CHECKING:
    from pathlib import Path

    from base import Finding

    from threat_inspector.parsers.base import BaseParser


class ParserFileModule:
    """Mix in ahead of FileModule: `class QualysIngest(ParserFileModule, FileModule)`."""

    name: str  # provided by the FileModule half
    PARSER: type[BaseParser]  # set on each concrete subclass

    def ingest(self, file: Path, ctx: dict[str, Any]) -> list[Finding]:
        return self.ingest_report(file, ctx).findings

    def ingest_report(self, file: Path, ctx: dict[str, Any]) -> IngestReport:
        """Carry the parser's own errors/warnings up to the runtime.

        Every parser already records why a file failed (`ParseResult.errors` —
        e.g. "XML parse error: not well-formed ... line 1, column 0"), but
        to_findings() only ever looked at `vulnerabilities`. A corrupt upload
        therefore surfaced as a successful ingest with zero findings, which is
        indistinguishable from a clean scan export.
        """
        result = self.PARSER().parse(file)
        return IngestReport(
            findings=to_findings(self.name, result),
            errors=list(result.errors),
            warnings=list(result.warnings),
        )
