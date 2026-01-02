"""
Parser for Nmap vulnerability scan exports.
Supports XML and TXT formats.
"""

import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Optional

from .base import BaseParser, ParseResult, ParsedVulnerability


class NmapParser(BaseParser):
    """Parser for Nmap scan files."""
    
    SCANNER_TYPE = "nmap"
    SUPPORTED_EXTENSIONS = [".xml", ".txt", ".nmap"]
    
    def parse(self, file_path: Path) -> ParseResult:
        """Parse an Nmap export file."""
        if file_path.suffix.lower() == ".xml":
            return self._parse_xml(file_path)
        return self._parse_txt(file_path)
    
    def _parse_xml(self, file_path: Path) -> ParseResult:
        """Parse Nmap XML format."""
        vulnerabilities = []
        scan_date = None
        metadata = {"source_file": str(file_path), "format": "xml"}
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Get scan metadata
            metadata["nmap_version"] = root.get("version", "unknown")
            metadata["args"] = root.get("args", "")
            
            start_time = root.get("start")
            if start_time:
                try:
                    scan_date = datetime.fromtimestamp(int(start_time))
                except (ValueError, TypeError):
                    pass
            
            # Parse each host
            for host in root.findall(".//host"):
                host_vulns = self._parse_host_xml(host)
                vulnerabilities.extend(host_vulns)
        
        except ET.ParseError as e:
            self.add_error(f"XML parse error: {e}")
        except Exception as e:
            self.add_error(f"Failed to parse Nmap XML: {e}")
        
        return ParseResult(
            scanner_type=self.SCANNER_TYPE,
            vulnerabilities=vulnerabilities,
            scan_date=scan_date,
            scan_metadata=metadata,
            errors=self.errors,
            warnings=self.warnings,
        )
    
    def _parse_host_xml(self, host: ET.Element) -> list[ParsedVulnerability]:
        """Parse a single host element from Nmap XML."""
        vulnerabilities = []
        
        # Get host address
        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            addr_elem = host.find("address")
        host_ip = addr_elem.get("addr", "") if addr_elem is not None else ""
        
        # Get hostname
        hostname = ""
        hostname_elem = host.find(".//hostname")
        if hostname_elem is not None:
            hostname = hostname_elem.get("name", "")
        
        # Parse ports and scripts
        for port in host.findall(".//port"):
            port_id = port.get("portid", "")
            protocol = port.get("protocol", "tcp")
            
            # Get service info
            service = port.find("service")
            service_name = service.get("name", "") if service is not None else ""
            service_product = service.get("product", "") if service is not None else ""
            service_version = service.get("version", "") if service is not None else ""
            
            # Parse vulnerability scripts (vulners, vuln, etc.)
            for script in port.findall("script"):
                script_id = script.get("id", "")
                script_output = script.get("output", "")
                
                # Look for CVEs in script output
                cves = re.findall(r"CVE-\d{4}-\d+", script_output, re.IGNORECASE)
                
                # Parse vulnerability tables
                for table in script.findall(".//table"):
                    vuln_data = self._parse_vuln_table(table)
                    if vuln_data:
                        vuln = ParsedVulnerability(
                            title=vuln_data.get("title", f"{script_id} finding"),
                            severity=self._determine_severity(vuln_data),
                            description=vuln_data.get("description", script_output[:500]),
                            asset_name=hostname or host_ip,
                            asset_ip=host_ip,
                            asset_port=int(port_id) if port_id.isdigit() else None,
                            cve_id=vuln_data.get("cve", cves[0] if cves else ""),
                            cvss_score=vuln_data.get("cvss"),
                            scanner_id=script_id,
                            solution=vuln_data.get("solution", ""),
                            raw_data={
                                "service": service_name,
                                "product": service_product,
                                "version": service_version,
                                "protocol": protocol,
                                "script_output": script_output[:1000],
                            },
                        )
                        vulnerabilities.append(vuln)
                
                # If no tables but script has vulnerability output
                if not script.findall(".//table") and self._is_vuln_script(script_id):
                    vuln = ParsedVulnerability(
                        title=f"{script_id}: {service_name} on port {port_id}",
                        severity=self._severity_from_script(script_id, script_output),
                        description=script_output[:1000],
                        asset_name=hostname or host_ip,
                        asset_ip=host_ip,
                        asset_port=int(port_id) if port_id.isdigit() else None,
                        cve_id=cves[0] if cves else "",
                        scanner_id=script_id,
                        raw_data={
                            "service": service_name,
                            "product": service_product,
                            "version": service_version,
                        },
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _parse_vuln_table(self, table: ET.Element) -> dict:
        """Parse a vulnerability table from Nmap script output."""
        data = {}
        for elem in table.findall("elem"):
            key = elem.get("key", "")
            value = elem.text or ""
            if key and value:
                data[key.lower()] = value
        return data
    
    def _is_vuln_script(self, script_id: str) -> bool:
        """Check if script is a vulnerability detection script."""
        vuln_scripts = [
            "vulners", "vuln", "exploit", "ssl-heartbleed", "smb-vuln",
            "http-vuln", "smtp-vuln", "ftp-vuln", "ssh-vuln", "cve"
        ]
        return any(vs in script_id.lower() for vs in vuln_scripts)
    
    def _determine_severity(self, vuln_data: dict) -> str:
        """Determine severity from vulnerability data."""
        cvss = vuln_data.get("cvss")
        if cvss:
            try:
                score = float(cvss)
                if score >= 9.0:
                    return "critical"
                elif score >= 7.0:
                    return "high"
                elif score >= 4.0:
                    return "medium"
                elif score > 0:
                    return "low"
            except ValueError:
                pass
        
        # Check for severity in data
        severity = vuln_data.get("severity", vuln_data.get("risk", "")).lower()
        return self.normalize_severity(severity) if severity else "medium"
    
    def _severity_from_script(self, script_id: str, output: str) -> str:
        """Infer severity from script name and output."""
        critical_indicators = ["remote code execution", "rce", "critical", "heartbleed"]
        high_indicators = ["overflow", "injection", "authentication bypass"]
        
        combined = f"{script_id} {output}".lower()
        
        if any(ind in combined for ind in critical_indicators):
            return "critical"
        if any(ind in combined for ind in high_indicators):
            return "high"
        return "medium"
    
    def _parse_txt(self, file_path: Path) -> ParseResult:
        """Parse Nmap text/greppable format."""
        vulnerabilities = []
        metadata = {"source_file": str(file_path), "format": "txt"}
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            # Parse vulnerability findings from text
            current_host = None
            current_output = []
            
            lines = content.split("\n")
            for line in lines:
                # Detect host
                host_match = re.search(r"Nmap scan report for (\S+)", line)
                if host_match:
                    if current_host and current_output:
                        vulns = self._parse_text_block(current_host, "\n".join(current_output))
                        vulnerabilities.extend(vulns)
                    current_host = host_match.group(1)
                    current_output = []
                
                # Detect nmap command with target
                cmd_match = re.search(r"nmap.*?(\d+\.\d+\.\d+\.\d+|\S+\.\S+)$", line)
                if cmd_match and not current_host:
                    current_host = cmd_match.group(1)
                
                current_output.append(line)
            
            # Don't forget the last host
            if current_host and current_output:
                vulns = self._parse_text_block(current_host, "\n".join(current_output))
                vulnerabilities.extend(vulns)
        
        except Exception as e:
            self.add_error(f"Failed to parse Nmap text: {e}")
        
        return ParseResult(
            scanner_type=self.SCANNER_TYPE,
            vulnerabilities=vulnerabilities,
            scan_metadata=metadata,
            errors=self.errors,
            warnings=self.warnings,
        )
    
    def _parse_text_block(self, host: str, block: str) -> list[ParsedVulnerability]:
        """Parse vulnerability findings from a text block."""
        vulnerabilities = []
        
        # Look for CVEs
        cves = re.findall(r"(CVE-\d{4}-\d+)", block, re.IGNORECASE)
        
        # Look for VULNERABLE markers
        vuln_matches = re.finditer(
            r"(VULNERABLE|State: VULNERABLE).*?(?=\n\n|\Z)",
            block,
            re.DOTALL | re.IGNORECASE
        )
        
        for match in vuln_matches:
            vuln_text = match.group(0)
            
            # Try to extract title
            title_match = re.search(r"(\S+.*?)(?:VULNERABLE|:)", vuln_text)
            title = title_match.group(1).strip() if title_match else "Nmap Vulnerability Finding"
            
            vuln = ParsedVulnerability(
                title=title,
                severity="high",  # VULNERABLE findings are typically high
                description=vuln_text[:500],
                asset_name=host,
                asset_ip=host if re.match(r"\d+\.\d+\.\d+\.\d+", host) else "",
                cve_id=cves[0] if cves else "",
                scanner_id="nmap-vuln-script",
                raw_data={"full_output": block[:2000]},
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
