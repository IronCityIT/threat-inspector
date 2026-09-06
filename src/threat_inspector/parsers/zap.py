"""
Parser for OWASP ZAP vulnerability scan exports.
Supports XML and JSON formats.
"""

import json
import xml.etree.ElementTree as ET
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path

from .base import BaseParser, ParsedVulnerability, ParseResult


def _parse_generated(value: str) -> datetime | None:
    """Read the timestamp a web-application report stamps itself with.

    The reports use RFC-2822 (`Mon, 6 Sep 2026 10:00:00`), not ISO-8601, so
    fromisoformat raised on every one of them and the scan date was silently
    dropped — every ingested XML report claimed no scan date at all. ISO is
    still tried first so any report that does use it keeps working.
    """
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        pass
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None


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

    def _to_severity(self, raw: str) -> str:
        """Map a risk to a severity, whichever form the export wrote it in.

        The XML report and the traditional JSON report give a numeric riskcode,
        which RISK_CODE_MAP handles. The API view gives the WORD instead —
        "High", "Medium" — and no riskcode at all. RISK_CODE_MAP knows only the
        numbers, so every alert from an API-shaped export fell through to its
        `.get` default: a SQL injection was filed, and reported to the client,
        as informational. normalize_severity knows the words, so try the codes
        first and defer to it for anything else.
        """
        raw = str(raw or "").strip()
        if raw in self.RISK_CODE_MAP:
            return self.RISK_CODE_MAP[raw]
        return self.normalize_severity(raw)

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
            generated = root.get("generated")
            if generated:
                scan_date = _parse_generated(generated)

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
    ) -> ParsedVulnerability | None:
        """Parse a single alert element from ZAP XML."""

        def get_text(tag: str, default: str = "") -> str:
            elem = alert.find(tag)
            return elem.text.strip() if elem is not None and elem.text else default

        title = get_text("alert")
        if not title:
            return None

        severity = self._to_severity(get_text("riskcode") or get_text("risk"))

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
            with open(file_path, encoding="utf-8") as f:
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

    def _parse_alert_json(self, alert: dict, site_name: str) -> ParsedVulnerability | None:
        """Parse a single alert from ZAP JSON."""
        title = alert.get("alert", alert.get("name", ""))
        if not title:
            return None

        # An empty riskcode counts as absent, not as risk 0 — otherwise an
        # export carrying `"riskcode": ""` alongside a real `"risk": "High"`
        # grades as informational.
        raw_risk = alert.get("riskcode")
        if raw_risk is None or str(raw_risk).strip() == "":
            raw_risk = alert.get("risk", "")
        severity = self._to_severity(raw_risk)

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
