"""
nmap_ingest.py — ingest network scan exports (XML/TXT/greppable).

Re-houses NmapParser. White-labeled: branded as network scan ingestion.
"""
from __future__ import annotations

from base import FileModule

from threat_inspector.parsers.nmap import NmapParser

from ._base import ParserFileModule


class NmapIngest(ParserFileModule, FileModule):
    name = "nmap_ingest"
    description = "Ingests network scan exports (XML/text)."
    extensions = (".xml", ".txt", ".nmap")
    groups = ("ingest", "deep")
    PARSER = NmapParser
