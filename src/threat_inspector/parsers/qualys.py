"""
Parser for Qualys vulnerability scan exports.
Supports XLSX, XLSM, and CSV formats.

pandas is imported lazily, inside the methods that actually read a spreadsheet.
It is by far the heaviest dependency in the tree (~21s of import time on a small
runner), and importing it at module scope made EVERY entry point pay that cost:
`threat_inspector/__init__` imports core, which imports this package, so even
`ingest.py --list-modules` -- which never opens a spreadsheet -- blocked on it.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from .base import BaseParser, ParsedVulnerability, ParseResult

if TYPE_CHECKING:
    import pandas as pd


class QualysParser(BaseParser):
    """Parser for Qualys vulnerability scan files."""

    SCANNER_TYPE = "qualys"
    SUPPORTED_EXTENSIONS = [".xlsx", ".xlsm", ".csv"]

    # Column name mappings (Qualys exports can have varying column names)
    COLUMN_MAPPINGS = {
        "title": ["Vulnerability Title", "Title", "QID Title", "Vuln Title"],
        "severity": ["Severity", "Risk", "Severity Level"],
        "description": ["Description", "Threat", "Details"],
        "asset_name": ["Asset Name", "DNS", "NetBIOS", "Host"],
        "asset_ip": ["Asset IPV4", "IP", "IP Address", "Host IP"],
        "asset_port": ["Port", "Service Port"],
        "cve_id": ["CVE ID", "CVE", "CVEs"],
        "cvss_score": ["CVSS Score", "CVSS", "CVSS Base"],
        "cvss_vector": ["CVSS Vector", "CVSS Base Vector"],
        "solution": ["Solution", "Remediation", "Fix"],
        "evidence": ["Results", "Evidence", "Output"],
        "discovered_at": ["First Detected", "Detection Date", "First Found"],
        "scanner_id": ["QID", "Qualys ID", "Vulnerability ID"],
    }

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a Qualys export file."""
        vulnerabilities = []
        scan_date = None
        metadata: dict[str, Any] = {"source_file": str(file_path)}

        try:
            import pandas as pd

            # Read file based on extension
            if file_path.suffix.lower() in [".xlsx", ".xlsm"]:
                df = pd.read_excel(file_path, engine="openpyxl")
            else:
                # utf-8-sig rather than utf-8, defensively. Exports saved on
                # Windows carry a BOM, and in the stdlib csv module those three
                # bytes land inside the FIRST column's name — which is exactly
                # how the vulnerability-scan CSV parser used to lose whole
                # exports. pandas 3.0.3 strips the BOM on its own, so this is
                # NOT fixing an observed bug here; it removes the dependence on
                # that behaviour and matches the sibling parser. utf-8-sig is
                # identical to utf-8 when there is no BOM.
                df = pd.read_csv(file_path, encoding="utf-8-sig")

            metadata["total_rows"] = len(df)
            metadata["columns"] = list(df.columns)

            # Map columns to standard names
            column_map = self._map_columns(df.columns.tolist())

            for _, row in df.iterrows():
                try:
                    vuln = self._parse_row(row, column_map)
                    if vuln:
                        vulnerabilities.append(vuln)
                except Exception as e:
                    self.add_warning(f"Error parsing row: {e}")

            # An export with data rows that yields nothing is the shape every
            # silent column mismatch takes: the file opened, the rows were read,
            # and each was dropped for want of a recognised title column.
            # Reporting a confident zero there is indistinguishable from a clean
            # scan, so say what was seen instead.
            if len(df) and not vulnerabilities:
                self.add_warning(
                    f"{len(df)} row(s) read but none carried a recognised title column; "
                    f"columns present: {', '.join(str(c) for c in df.columns) or 'none'}"
                )

        except Exception as e:
            self.add_error(f"Failed to parse Qualys file: {e}")

        return ParseResult(
            scanner_type=self.SCANNER_TYPE,
            vulnerabilities=vulnerabilities,
            scan_date=scan_date,
            scan_metadata=metadata,
            errors=self.errors,
            warnings=self.warnings,
        )

    def _map_columns(self, columns: list[str]) -> dict[str, str]:
        """Map actual column names to standard field names."""
        column_map = {}

        for field_name, possible_names in self.COLUMN_MAPPINGS.items():
            for col in columns:
                if col in possible_names or col.lower() in [n.lower() for n in possible_names]:
                    column_map[field_name] = col
                    break

        return column_map

    def _parse_row(self, row: pd.Series, column_map: dict[str, str]) -> ParsedVulnerability | None:
        """Parse a single row into a ParsedVulnerability."""
        import pandas as pd

        def get_value(field: str, default: str = "") -> str:
            if field in column_map:
                val = row.get(column_map[field])
                if pd.notna(val):
                    return str(val).strip()
            return default

        def get_float(field: str) -> float | None:
            if field in column_map:
                val = row.get(column_map[field])
                if pd.notna(val):
                    try:
                        return float(val)
                    except (ValueError, TypeError):
                        pass
            return None

        def get_int(field: str) -> int | None:
            if field in column_map:
                val = row.get(column_map[field])
                if pd.notna(val):
                    try:
                        return int(float(val))
                    except (ValueError, TypeError):
                        pass
            return None

        title = get_value("title")
        if not title:
            return None

        severity_raw = get_value("severity", "info")

        return ParsedVulnerability(
            title=title,
            severity=self.normalize_severity(severity_raw),
            description=get_value("description"),
            asset_name=get_value("asset_name"),
            asset_ip=get_value("asset_ip"),
            asset_port=get_int("asset_port"),
            cve_id=get_value("cve_id"),
            cvss_score=get_float("cvss_score"),
            cvss_vector=get_value("cvss_vector"),
            scanner_id=get_value("scanner_id"),
            scanner_severity=severity_raw,
            solution=get_value("solution"),
            evidence=get_value("evidence"),
            raw_data=row.to_dict(),
        )


def _cell(row, names: tuple[str, ...], default: str = "") -> str:
    """First present, non-empty value among `names`, as a clean string.

    pandas reads an empty cell as NaN and `str(NaN)` is "nan", so reading a cell
    with a bare `str(row.get(...))` puts the literal text "nan" in front of a
    client. Every read here goes through this.
    """
    import pandas as pd

    for name in names:
        if name not in row:
            continue
        value = row.get(name)
        if pd.notna(value):
            text = str(value).strip()
            if text:
                return text
    return default


def _severity_for_status(status: str) -> str:
    """A failed control is a finding; a passed one is a record of a pass."""
    if "fail" in status:
        return "high"
    if "warn" in status:
        return "medium"
    return "info"


def _bucket_for_status(status: str) -> str:
    if "fail" in status:
        return "failed"
    if "warn" in status:
        return "warning"
    return "passed"


class QualysComplianceParser(BaseParser):
    """Parser for compliance control exports.

    Three defects lived here, none of which its sibling above has. This parser
    had no direct tests at all — only routing tests asserting which parser gets
    SELECTED, never what it produces.

    1. Blank cells reached the client as the literal string "nan". pandas reads
       an empty cell as NaN, and `str(NaN)` is "nan", so a control with no
       remediation text was reported with **"nan" as its remediation step**.
       The sibling parser reads through a NaN-aware helper and has a test named
       for exactly this; this one used `str(row.get(...))` directly.

    2. An export whose columns are not recognised FABRICATED findings. The title
       fell back to the literal "Unknown", which is neither empty nor "nan", so
       every row became a finding called "Unknown" at severity info. Worse than
       reporting nothing: it invents rows that were never in the file.

    3. Nothing recorded how many controls passed. Every row becomes a
       ParsedVulnerability, so a 500-control export where 490 passed counts as
       500 findings. The passes are severity "info" and carry their status, so
       no data is dropped by keeping them — but a reader needs the breakdown to
       say "500 controls, 10 failed" rather than "500 findings".
    """

    SCANNER_TYPE = "qualys_compliance"
    SUPPORTED_EXTENSIONS = [".xlsx", ".xlsm", ".csv"]

    # Column the control's name may arrive under, best first.
    TITLE_COLUMNS = ("Control", "Title")

    def parse(self, file_path: Path) -> ParseResult:
        """Parse a compliance control export."""
        vulnerabilities = []
        metadata: dict[str, Any] = {"source_file": str(file_path), "scan_type": "compliance"}
        rows_read = 0
        columns: list[str] = []
        status_counts: dict[str, int] = {"failed": 0, "warning": 0, "passed": 0}

        try:
            import pandas as pd

            if file_path.suffix.lower() in [".xlsx", ".xlsm"]:
                df = pd.read_excel(file_path, engine="openpyxl")
            else:
                # utf-8-sig for the same reason as the sibling parser: defensive
                # against a BOM, identical to utf-8 when there is none.
                df = pd.read_csv(file_path, encoding="utf-8-sig")

            columns = [str(c) for c in df.columns]
            rows_read = len(df)
            metadata["total_rows"] = rows_read
            metadata["columns"] = columns

            for _, row in df.iterrows():
                try:
                    title = _cell(row, self.TITLE_COLUMNS)
                    if not title:
                        # No recognised control name. Skipping is right;
                        # inventing one called "Unknown" was not.
                        continue

                    status = _cell(row, ("Status",)).lower()
                    severity = _severity_for_status(status)
                    status_counts[_bucket_for_status(status)] += 1

                    vulnerabilities.append(
                        ParsedVulnerability(
                            title=title,
                            severity=severity,
                            description=_cell(row, ("Description",)),
                            asset_name=_cell(row, ("Asset Name", "Host")),
                            asset_ip=_cell(row, ("IP", "Asset IP")),
                            solution=_cell(row, ("Remediation", "Solution")),
                            scanner_severity=status,
                            raw_data=row.to_dict(),
                        )
                    )

                except Exception as e:
                    self.add_warning(f"Error parsing compliance row: {e}")

        except Exception as e:
            self.add_error(f"Failed to parse Qualys compliance file: {e}")

        metadata["control_status_counts"] = status_counts

        # Rows read and nothing recognised is the shape a column mismatch takes.
        # It used to produce a finding per row titled "Unknown"; now it produces
        # nothing, so it has to say so.
        if rows_read and not vulnerabilities and not self.errors:
            self.add_warning(
                f"{rows_read} row(s) read but none carried a recognised control column; "
                f"looked for {', '.join(self.TITLE_COLUMNS)}; "
                f"columns present: {', '.join(columns) if columns else 'none'}"
            )

        return ParseResult(
            scanner_type=self.SCANNER_TYPE,
            vulnerabilities=vulnerabilities,
            scan_metadata=metadata,
            errors=self.errors,
            warnings=self.warnings,
        )
