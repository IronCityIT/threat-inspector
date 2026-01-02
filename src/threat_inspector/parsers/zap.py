"""
Parser for OWASP ZAP vulnerability scan exports.
Supports XML and JSON formats.
"""

import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Optional

from .base import BaseParser, ParseResult, ParsedVulnerability


class ZAPParser(BaseParser):
    """Parser for OWASP ZAP scan files."""
    
    SCANNER_TYPE = "zap"
    SUPPORTED_EXTENSIONS = [".xml", ".json"]
    
    # ZAP risk codes to severity mapping
    RISK_CODE_MAP = {
        "0": "info",
        "1": "low",
        "2": "medium",
        "3": "high",
    }
    
    def parse(self, file_path: Path) -> ParseResult:
        """Parse a ZAP export file."""
        if file_path.suffix.lower() == ".json":
            return self._parse_json(file_path)
        return self._parse_xml(file_path)
    
    def _parse_xml(self, file_path: Path) -> ParseResult:
        """Parse ZAP XML format."""
        vulnerabilities = []
        scan_date = None
        metadata = {"source_file": str(file_path), "format": "xml"}
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Get scan metadata
            if root.get("generated"):
                try:
                    scan_date = datetime.fromisoformat(root.get("generated"))
                except ValueError:
                    pass
            
            metadata["zap_version"] = root.get("version", "unknown")
            
            # Parse each site
            for site in root.findall(".//site"):
                site_name = site.get("name", "")
                site_host = site.get("host", "")
                site_port = site.get("port", "")
                
                # Parse alerts
                for alert in site.findall(".//alertitem"):
                    try:
                        vuln = self._parse_alert_xml(alert, site_name, site_host, site_port)
                        if vuln:
                            vulnerabilities.append(vuln)
                    except Exception as e:
                        self.add_warning(f"Error parsing alert: {e}")
        
        except ET.ParseError as e:
            self.add_error(f"XML parse error: {e}")
        except Exception as e:
            self.add_error(f"Failed to parse ZAP XML: {e}")
        
        return ParseResult(
            scanner_type=self.SCANNER_TYPE,
            vulnerabilities=vulnerabilities,
            scan_date=scan_date,
            scan_metadata=metadata,
            errors=self.errors,
            warnings=self.warnings,
        )
    
    def _parse_alert_xml(
        self, alert: ET.Element, site_name: str, site_host: str, site_port: str
    ) -> Optional[ParsedVulnerability]:
        """Parse a single alert element from ZAP XML."""
        
        def get_text(tag: str, default: str = "") -> str:
            elem = alert.find(tag)
            return elem.text.strip() if elem is not None and elem.text else default
        
        title = get_text("alert")
        if not title:
            return None
        
        risk_code = get_text("riskcode", "0")
        severity = self.RISK_CODE_MAP.get(risk_code, "info")
        
        # Get all instances (URLs where this vuln was found)
        instances = []
        for instance in alert.findall(".//instance"):
            uri = instance.find("uri")
            if uri is not None and uri.text:
                instances.append(uri.text)
        
        # Use first instance URL as primary
        primary_url = instances[0] if instances else site_name
        
        # Parse port
        port = None
        if site_port:
            try:
                port = int(site_port)
            except ValueError:
                pass
        
        return ParsedVulnerability(
            title=title,
            severity=severity,
            description=self._clean_html(get_text("desc")),
            asset_name=site_name,
            asset_ip=site_host,
            asset_port=port,
            asset_url=primary_url,
            cwe_id=get_text("cweid"),
            scanner_id=get_text("pluginid"),
            scanner_severity=get_text("riskdesc"),
            solution=self._clean_html(get_text("solution")),
            evidence=get_text("evidence"),
            request=get_text("request"),
            response=get_text("response"),
            raw_data={
                "confidence": get_text("confidence"),
                "count": len(instances),
                "instances": instances[:10],  # Limit stored instances
                "reference": get_text("reference"),
            },
        )
    
    def _parse_json(self, file_path: Path) -> ParseResult:
        """Parse ZAP JSON format."""
        vulnerabilities = []
        scan_date = None
        metadata = {"source_file": str(file_path), "format": "json"}
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Handle different JSON structures
            if isinstance(data, dict):
                if "site" in data:
                    sites = data["site"] if isinstance(data["site"], list) else [data["site"]]
                elif "alerts" in data:
                    sites = [{"alerts": data["alerts"]}]
                else:
                    sites = [data]
            else:
                sites = data
            
            for site in sites:
                site_name = site.get("@name", site.get("name", ""))
                alerts = site.get("alerts", site.get("alert", []))
                
                if not isinstance(alerts, list):
                    alerts = [alerts]
                
                for alert in alerts:
                    try:
                        vuln = self._parse_alert_json(alert, site_name)
                        if vuln:
                            vulnerabilities.append(vuln)
                    except Exception as e:
                        self.add_warning(f"Error parsing JSON alert: {e}")
        
        except json.JSONDecodeError as e:
            self.add_error(f"JSON parse error: {e}")
        except Exception as e:
            self.add_error(f"Failed to parse ZAP JSON: {e}")
        
        return ParseResult(
            scanner_type=self.SCANNER_TYPE,
            vulnerabilities=vulnerabilities,
            scan_date=scan_date,
            scan_metadata=metadata,
            errors=self.errors,
            warnings=self.warnings,
        )
    
    def _parse_alert_json(self, alert: dict, site_name: str) -> Optional[ParsedVulnerability]:
        """Parse a single alert from ZAP JSON."""
        title = alert.get("alert", alert.get("name", ""))
        if not title:
            return None
        
        risk_code = str(alert.get("riskcode", alert.get("risk", "0")))
        severity = self.RISK_CODE_MAP.get(risk_code, "info")
        
        # Get instances
        instances = alert.get("instances", [])
        urls = [i.get("uri", "") for i in instances if i.get("uri")]
        primary_url = urls[0] if urls else alert.get("url", site_name)
        
        return ParsedVulnerability(
            title=title,
            severity=severity,
            description=self._clean_html(alert.get("desc", alert.get("description", ""))),
            asset_name=site_name,
            asset_url=primary_url,
            cwe_id=str(alert.get("cweid", "")),
            scanner_id=str(alert.get("pluginid", alert.get("id", ""))),
            scanner_severity=alert.get("riskdesc", ""),
            solution=self._clean_html(alert.get("solution", "")),
            evidence=alert.get("evidence", ""),
            raw_data={
                "confidence": alert.get("confidence", ""),
                "count": len(instances),
                "reference": alert.get("reference", ""),
            },
        )
    
    @staticmethod
    def _clean_html(text: str) -> str:
        """Remove HTML tags from text."""
        if not text:
            return ""
        import re
        clean = re.sub(r"<[^>]+>", "", text)
        clean = clean.replace("&lt;", "<").replace("&gt;", ">")
        clean = clean.replace("&amp;", "&").replace("&quot;", '"')
        return clean.strip()
