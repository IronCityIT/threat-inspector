"""
qualys_compliance_ingest.py — ingest compliance-control exports (XLSX/XLSM/CSV).

Re-houses QualysComplianceParser (control pass/fail -> severity). White-labeled:
branded as compliance-control export ingestion.
"""
from __future__ import annotations

from base import FileModule

from threat_inspector.parsers.qualys import QualysComplianceParser

from ._base import ParserFileModule


class QualysComplianceIngest(ParserFileModule, FileModule):
    name = "qualys_compliance_ingest"
    description = "Ingests compliance-control exports (Excel/CSV)."
    extensions = (".xlsx", ".xlsm", ".csv")
    groups = ("ingest", "deep")
    PARSER = QualysComplianceParser
