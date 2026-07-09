"""
qualys_ingest.py — ingest Qualys vulnerability exports (XLSX/XLSM/CSV).

Re-houses QualysParser. White-labeled: the vendor is not named on any client
surface; this is branded as spreadsheet vulnerability-export ingestion.
"""
from __future__ import annotations

from base import FileModule

from threat_inspector.parsers.qualys import QualysParser

from ._base import ParserFileModule


class QualysIngest(ParserFileModule, FileModule):
    name = "qualys_ingest"
    description = "Ingests spreadsheet vulnerability exports (Excel/CSV)."
    extensions = (".xlsx", ".xlsm", ".csv")
    groups = ("ingest", "deep")
    PARSER = QualysParser
