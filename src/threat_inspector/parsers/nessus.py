"""
Parser for Nessus vulnerability scan exports.
Supports .nessus (XML) and CSV formats.
"""

import contextlib
import csv
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from .base import BaseParser, ParsedVulnerability, ParseResult

# Nessus writes a whole plugin output into a single CSV cell, and csv's default
# cap is 128 KB. Past that the reader raises mid-file, the exception reached the
# blanket handler in _parse_csv, and the WHOLE export was reported as zero
# findings with one error line. The cap is RAISED, not removed: an unlimited
# field lets a single hostile cell exhaust memory, while 64 MB is orders of
# magnitude past any genuine plugin output.
_CSV_FIELD_LIMIT = 64 * 1024 * 1024


@contextlib.contextmanager
def _raised_csv_field_limit(limit: int = _CSV_FIELD_LIMIT) -> Iterator[None]:
    """Raise csv's field cap for one read, then put it back.

    csv.field_size_limit is process-global state. Setting it and walking away
    would mean one ingest silently changes the limit every later ingest in the
    process runs under, so it is restored even when the read raises.
    """
    previous = csv.field_size_limit()
    try:
        csv.field_size_limit(limit)
        yield
    finally:
        csv.field_size_limit(previous)


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
        metadata: dict[str, Any] = {"source_file": str(file_path), "format": "nessus"}

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
                            scan_date = datetime.strptime(tag.text or "", "%a %b %d %H:%M:%S %Y")
                        except (ValueError, TypeError):
                            pass

                # Parse report items (vulnerabilities)
                for item in report_host.findall(".//ReportItem"):
                    try:
                        vuln = self._parse_report_item(item, host_name, host_ip, host_fqdn, os_info)
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
        self, item: ET.Element, host_name: str, host_ip: str, host_fqdn: str, os_info: str
    ) -> ParsedVulnerability | None:
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

        # EVERY CVE, not just the first. A ReportItem carries one <cve> element
        # per CVE, and find() returns one of them — so a plugin citing several
        # was reported against a single CVE and the rest vanished. The plugins
        # that cite several are exactly the ones worth chasing.
        cve_ids = [e.text.strip() for e in item.findall("cve") if e.text and e.text.strip()]
        cve_id = ", ".join(cve_ids)

        # Prefer CVSS v3 and fall back to v2 — but decide on the VALUE, not on
        # the element's presence. Nessus emits an empty <cvss3_base_score/> for
        # plugins scored only under v2; keying the fallback off `is None` meant
        # that empty element shadowed the v2 score and the finding reached the
        # client carrying no score at all.
        cvss_score = None
        for score_tag in ("cvss3_base_score", "cvss_base_score"):
            score_elem = item.find(score_tag)
            if score_elem is None or not score_elem.text:
                continue
            try:
                cvss_score = float(score_elem.text)
                break
            except ValueError:
                continue

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
        metadata: dict[str, Any] = {"source_file": str(file_path), "format": "csv"}
        columns: list[str] = []
        rows_read = 0

        try:
            # encoding="utf-8-sig", NOT "utf-8". A Nessus export saved or
            # re-saved on Windows carries a UTF-8 BOM, and under plain utf-8
            # those three bytes land inside the FIRST column's NAME. Every
            # lookup of that column then misses. When the first column is
            # "Name" — the title — every row was skipped as untitled and the
            # export ingested as ZERO findings, with no error and no warning:
            # the client got a clean report from a scan that found things.
            # utf-8-sig strips a BOM when there is one and is identical to
            # utf-8 when there is not.
            #
            # newline="" is what csv requires: without it a quoted cell
            # containing a newline is split across rows, which for Nessus means
            # any finding whose description wraps.
            with (
                open(file_path, encoding="utf-8-sig", newline="") as f,
                _raised_csv_field_limit(),
            ):
                reader = csv.DictReader(f)
                columns = list(reader.fieldnames or [])

                for row in reader:
                    rows_read += 1
                    try:
                        vuln = self._parse_csv_row(row)
                        if vuln:
                            vulnerabilities.append(vuln)
                    except Exception as e:
                        self.add_warning(f"Error parsing CSV row: {e}")

        except Exception as e:
            self.add_error(f"Failed to parse Nessus CSV: {e}")

        metadata["columns"] = columns
        metadata["rows_read"] = rows_read

        # An export whose rows all vanish is the shape every silent column
        # mismatch takes: the file opened, the rows were read, and each was
        # dropped for want of a recognised title column. Reporting a confident
        # zero there is the failure that hurts — say what was seen instead, so
        # the gap is visible rather than indistinguishable from a clean scan.
        if rows_read and not vulnerabilities and not self.errors:
            self.add_warning(
                f"{rows_read} row(s) read but none carried a recognised title column; "
                f"columns present: {', '.join(columns) if columns else 'none'}"
            )

        return ParseResult(
            scanner_type=self.SCANNER_TYPE,
            vulnerabilities=vulnerabilities,
            scan_metadata=metadata,
            errors=self.errors,
            warnings=self.warnings,
        )

    def _parse_csv_row(self, row: dict) -> ParsedVulnerability | None:
        """Parse a single row from Nessus CSV."""
        # Handle various column name formats
        title = (row.get("Name") or row.get("Plugin Name") or row.get("name") or "").strip()

        if not title:
            return None

        # Get severity
        severity_raw = row.get("Risk") or row.get("Severity") or row.get("risk") or "Info"
        severity = self.normalize_severity(severity_raw)

        # Get CVSS
        cvss_score = None
        cvss_raw = (
            row.get("CVSS v3.0 Base Score") or row.get("CVSS") or row.get("CVSS v2.0 Base Score")
        )
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
