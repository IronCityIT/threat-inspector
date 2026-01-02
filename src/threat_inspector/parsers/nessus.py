"""
Parser for Nessus vulnerability scan exports.
Supports .nessus (XML) and CSV formats.
"""

import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Optional

from .base import BaseParser, ParseResult, ParsedVulnerability


class NessusParser(BaseParser):
    """Parser for Nessus scan files."""
    
    SCANNER_TYPE = "nessus"
    SUPPORTED_EXTENSIONS = [".nessus", ".csv"]
    
    # Nessus severity mapping
    SEVERITY_MAP = {
        "0": "info",
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "critical",
    }
    
    def parse(self, file_path: Path) -> ParseResult:
        """Parse a Nessus export file."""
        if file_path.suffix.lower() == ".csv":
            return self._parse_csv(file_path)
        return self._parse_nessus(file_path)
    
    def _parse_nessus(self, file_path: Path) -> ParseResult:
        """Parse Nessus XML format (.nessus)."""
        vulnerabilities = []
        scan_date = None
        metadata = {"source_file": str(file_path), "format": "nessus"}
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Get policy info
            policy = root.find(".//Policy")
            if policy is not None:
                policy_name = policy.find("policyName")
                if policy_name is not None:
                    metadata["policy_name"] = policy_name.text
            
            # Parse each report host
            for report_host in root.findall(".//ReportHost"):
                host_name = report_host.get("name", "")
                
                # Get host properties
                host_ip = ""
                host_fqdn = ""
                os_info = ""
                
                for tag in report_host.findall(".//tag"):
                    tag_name = tag.get("name", "")
                    if tag_name == "host-ip":
                        host_ip = tag.text or ""
                    elif tag_name == "host-fqdn":
                        host_fqdn = tag.text or ""
                    elif tag_name == "operating-system":
                        os_info = tag.text or ""
                    elif tag_name == "HOST_START":
                        try:
                            scan_date = datetime.strptime(tag.text, "%a %b %d %H:%M:%S %Y")
                        except (ValueError, TypeError):
                            pass
                
                # Parse report items (vulnerabilities)
                for item in report_host.findall(".//ReportItem"):
                    try:
                        vuln = self._parse_report_item(
                            item, host_name, host_ip, host_fqdn, os_info
                        )
                        if vuln:
                            vulnerabilities.append(vuln)
                    except Exception as e:
                        self.add_warning(f"Error parsing report item: {e}")
        
        except ET.ParseError as e:
            self.add_error(f"XML parse error: {e}")
        except Exception as e:
            self.add_error(f"Failed to parse Nessus file: {e}")
        
        return ParseResult(
            scanner_type=self.SCANNER_TYPE,
            vulnerabilities=vulnerabilities,
            scan_date=scan_date,
            scan_metadata=metadata,
            errors=self.errors,
            warnings=self.warnings,
        )
    
    def _parse_report_item(
        self, item: ET.Element, host_name: str, host_ip: str, 
        host_fqdn: str, os_info: str
    ) -> Optional[ParsedVulnerability]:
        """Parse a single ReportItem from Nessus XML."""
        
        def get_text(tag: str, default: str = "") -> str:
            elem = item.find(tag)
            return elem.text.strip() if elem is not None and elem.text else default
        
        plugin_name = item.get("pluginName", "")
        if not plugin_name:
            return None
        
        severity_num = item.get("severity", "0")
        severity = self.SEVERITY_MAP.get(severity_num, "info")
        
        # Skip informational by default? No, include all
        port = item.get("port", "0")
        protocol = item.get("protocol", "tcp")
        
        # Get CVE(s)
        cve_elem = item.find("cve")
        cve_id = cve_elem.text if cve_elem is not None else ""
        
        # Get CVSS
        cvss_score = None
        cvss_elem = item.find("cvss3_base_score")
        if cvss_elem is None:
            cvss_elem = item.find("cvss_base_score")
        if cvss_elem is not None and cvss_elem.text:
            try:
                cvss_score = float(cvss_elem.text)
            except ValueError:
                pass
        
        return ParsedVulnerability(
            title=plugin_name,
            severity=severity,
            description=get_text("description"),
            asset_name=host_fqdn or host_name,
            asset_ip=host_ip or host_name,
            asset_port=int(port) if port.isdigit() else None,
            cve_id=cve_id,
            cvss_score=cvss_score,
            cvss_vector=get_text("cvss3_vector") or get_text("cvss_vector"),
            scanner_id=item.get("pluginID", ""),
            scanner_severity=f"Severity {severity_num}",
            solution=get_text("solution"),
            evidence=get_text("plugin_output"),
            raw_data={
                "plugin_family": item.get("pluginFamily", ""),
                "protocol": protocol,
                "service": item.get("svc_name", ""),
                "os": os_info,
                "see_also": get_text("see_also"),
                "exploit_available": get_text("exploit_available"),
            },
        )
    
    def _parse_csv(self, file_path: Path) -> ParseResult:
        """Parse Nessus CSV export format."""
        vulnerabilities = []
        metadata = {"source_file": str(file_path), "format": "csv"}
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    try:
                        vuln = self._parse_csv_row(row)
                        if vuln:
                            vulnerabilities.append(vuln)
                    except Exception as e:
                        self.add_warning(f"Error parsing CSV row: {e}")
        
        except Exception as e:
            self.add_error(f"Failed to parse Nessus CSV: {e}")
        
        return ParseResult(
            scanner_type=self.SCANNER_TYPE,
            vulnerabilities=vulnerabilities,
            scan_metadata=metadata,
            errors=self.errors,
            warnings=self.warnings,
        )
    
    def _parse_csv_row(self, row: dict) -> Optional[ParsedVulnerability]:
        """Parse a single row from Nessus CSV."""
        # Handle various column name formats
        title = (
            row.get("Name") or 
            row.get("Plugin Name") or 
            row.get("name") or 
            ""
        ).strip()
        
        if not title:
            return None
        
        # Get severity
        severity_raw = (
            row.get("Risk") or 
            row.get("Severity") or 
            row.get("risk") or 
            "Info"
        )
        severity = self.normalize_severity(severity_raw)
        
        # Get CVSS
        cvss_score = None
        cvss_raw = row.get("CVSS v3.0 Base Score") or row.get("CVSS") or row.get("CVSS v2.0 Base Score")
        if cvss_raw:
            try:
                cvss_score = float(cvss_raw)
            except ValueError:
                pass
        
        # Get port
        port = None
        port_raw = row.get("Port") or row.get("port")
        if port_raw:
            try:
                port = int(port_raw)
            except ValueError:
                pass
        
        return ParsedVulnerability(
            title=title,
            severity=severity,
            description=row.get("Description") or row.get("Synopsis") or "",
            asset_name=row.get("Host") or row.get("DNS Name") or "",
            asset_ip=row.get("IP Address") or row.get("Host") or "",
            asset_port=port,
            cve_id=row.get("CVE") or "",
            cvss_score=cvss_score,
            scanner_id=row.get("Plugin ID") or row.get("Plugin") or "",
            scanner_severity=severity_raw,
            solution=row.get("Solution") or "",
            evidence=row.get("Plugin Output") or "",
            raw_data=dict(row),
        )
