"""
Parser for Qualys vulnerability scan exports.
Supports XLSX, XLSM, and CSV formats.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional
import pandas as pd

from .base import BaseParser, ParseResult, ParsedVulnerability


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
        metadata = {"source_file": str(file_path)}
        
        try:
            # Read file based on extension
            if file_path.suffix.lower() in [".xlsx", ".xlsm"]:
                df = pd.read_excel(file_path, engine="openpyxl")
            else:
                df = pd.read_csv(file_path, encoding="utf-8")
            
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
    
    def _parse_row(self, row: pd.Series, column_map: dict[str, str]) -> Optional[ParsedVulnerability]:
        """Parse a single row into a ParsedVulnerability."""
        
        def get_value(field: str, default: str = "") -> str:
            if field in column_map:
                val = row.get(column_map[field])
                if pd.notna(val):
                    return str(val).strip()
            return default
        
        def get_float(field: str) -> Optional[float]:
            if field in column_map:
                val = row.get(column_map[field])
                if pd.notna(val):
                    try:
                        return float(val)
                    except (ValueError, TypeError):
                        pass
            return None
        
        def get_int(field: str) -> Optional[int]:
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


class QualysComplianceParser(BaseParser):
    """Parser for Qualys compliance scan exports."""
    
    SCANNER_TYPE = "qualys_compliance"
    SUPPORTED_EXTENSIONS = [".xlsx", ".xlsm", ".csv"]
    
    def parse(self, file_path: Path) -> ParseResult:
        """Parse a Qualys compliance export file."""
        vulnerabilities = []
        metadata = {"source_file": str(file_path), "scan_type": "compliance"}
        
        try:
            if file_path.suffix.lower() in [".xlsx", ".xlsm"]:
                df = pd.read_excel(file_path, engine="openpyxl")
            else:
                df = pd.read_csv(file_path, encoding="utf-8")
            
            metadata["total_rows"] = len(df)
            
            for _, row in df.iterrows():
                try:
                    # Compliance findings are treated similarly
                    title = str(row.get("Control", row.get("Title", "Unknown"))).strip()
                    if not title or title == "nan":
                        continue
                    
                    status = str(row.get("Status", "")).lower()
                    # Map compliance status to severity
                    if "fail" in status:
                        severity = "high"
                    elif "warn" in status:
                        severity = "medium"
                    else:
                        severity = "info"
                    
                    vuln = ParsedVulnerability(
                        title=title,
                        severity=severity,
                        description=str(row.get("Description", "")),
                        asset_name=str(row.get("Asset Name", row.get("Host", ""))),
                        asset_ip=str(row.get("IP", row.get("Asset IP", ""))),
                        solution=str(row.get("Remediation", row.get("Solution", ""))),
                        scanner_severity=status,
                        raw_data=row.to_dict(),
                    )
                    vulnerabilities.append(vuln)
                    
                except Exception as e:
                    self.add_warning(f"Error parsing compliance row: {e}")
        
        except Exception as e:
            self.add_error(f"Failed to parse Qualys compliance file: {e}")
        
        return ParseResult(
            scanner_type=self.SCANNER_TYPE,
            vulnerabilities=vulnerabilities,
            scan_metadata=metadata,
            errors=self.errors,
            warnings=self.warnings,
        )
