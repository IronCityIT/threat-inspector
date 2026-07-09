"""
zap_ingest.py — ingest web-application scan exports (XML/JSON).

Re-houses ZAPParser. White-labeled: branded as web-application scan ingestion.
"""
from __future__ import annotations

from base import FileModule

from threat_inspector.parsers.zap import ZAPParser

from ._base import ParserFileModule


class ZapIngest(ParserFileModule, FileModule):
    name = "zap_ingest"
    description = "Ingests web-application scan exports (XML/JSON)."
    extensions = (".xml", ".json")
    groups = ("ingest", "deep")
    PARSER = ZAPParser
