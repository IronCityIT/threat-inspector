"""
nessus_ingest.py — ingest vulnerability scan exports (.nessus/CSV).

Re-houses NessusParser. White-labeled: branded as vulnerability scan ingestion.
"""
from __future__ import annotations

from base import FileModule

from threat_inspector.parsers.nessus import NessusParser

from ._base import ParserFileModule


class NessusIngest(ParserFileModule, FileModule):
    name = "nessus_ingest"
    description = "Ingests vulnerability scan exports (.nessus/CSV)."
    extensions = (".nessus", ".csv")
    groups = ("ingest", "deep")
    PARSER = NessusParser
