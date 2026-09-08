"""
Core ThreatInspector class - main entry point for the library.
"""

from collections import defaultdict
from datetime import datetime
from pathlib import Path

from threat_inspector.config import Settings, get_settings
from threat_inspector.parsers import SUPPORTED_FORMATS, ParsedVulnerability, ParseResult, parse_file
from threat_inspector.reports import REPORT_FORMATS
from threat_inspector.utils.compliance import get_compliance_mappings
from threat_inspector.utils.remediation import generate_remediation

# Worst first. Anything unrecognised sorts after every known band rather than
# ahead of "critical", so an odd severity string cannot promote itself.
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Fields worth carrying across when one duplicate displaces another. Severity,
# port and score are handled separately because they are not strings.
_MERGEABLE_TEXT_FIELDS = (
    "description",
    "asset_name",
    "asset_ip",
    "asset_url",
    "cve_id",
    "cwe_id",
    "cvss_vector",
    "scanner_id",
    "scanner_severity",
    "solution",
    "evidence",
    "request",
    "response",
)


def _severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get((severity or "").lower().strip(), len(_SEVERITY_RANK))


def _information_score(vuln: ParsedVulnerability) -> tuple[int, ...]:
    """How much a record actually carries — used only to break a severity tie."""
    return (
        int(vuln.cvss_score is not None),
        int(bool(vuln.cve_id)),
        int(bool(vuln.solution)),
        int(bool(vuln.evidence)),
        len(vuln.description or ""),
    )


def _preference(vuln: ParsedVulnerability) -> tuple[int, ...]:
    """Sort key for choosing between duplicates: LOWER wins.

    Severity dominates. Richness only breaks a tie, and is negated so that more
    information sorts earlier.
    """
    return (_severity_rank(vuln.severity), *(-n for n in _information_score(vuln)))


def _fill_gaps(winner: ParsedVulnerability, loser: ParsedVulnerability) -> ParsedVulnerability:
    """Copy into the winner any field it left empty, from the record it displaced.

    Choosing a winner must not cost a CVE, a score or a fix that only the other
    copy carried. Nothing already set is overwritten.
    """
    for field_name in _MERGEABLE_TEXT_FIELDS:
        if not getattr(winner, field_name) and getattr(loser, field_name):
            setattr(winner, field_name, getattr(loser, field_name))
    if winner.cvss_score is None and loser.cvss_score is not None:
        winner.cvss_score = loser.cvss_score
    if winner.asset_port is None and loser.asset_port is not None:
        winner.asset_port = loser.asset_port
    return winner


class ThreatInspector:
    """
    Main class for vulnerability assessment and reporting.

    Usage:
        inspector = ThreatInspector()
        inspector.load_scans("./scans/")
        results = inspector.analyze()
        inspector.generate_report("./report.html")
    """

    def __init__(self, config_path: Path | None = None, settings: Settings | None = None):
        """
        Initialize ThreatInspector.

        Args:
            config_path: Path to YAML configuration file
            settings: Pre-configured Settings object
        """
        if settings:
            self.settings = settings
        elif config_path:
            self.settings = Settings.from_yaml(config_path)
        else:
            self.settings = get_settings()

        self._parse_results: list[ParseResult] = []
        self._vulnerabilities: list[ParsedVulnerability] = []
        self._analysis_complete = False

    def load_file(self, file_path: str | Path, scanner_type: str | None = None) -> ParseResult:
        """
        Load and parse a single scan file.

        Args:
            file_path: Path to the scan file
            scanner_type: Optional hint for scanner type

        Returns:
            ParseResult with vulnerabilities
        """
        file_path = Path(file_path)
        result = parse_file(file_path, scanner_type)
        self._parse_results.append(result)
        self._vulnerabilities.extend(result.vulnerabilities)
        self._analysis_complete = False
        return result

    def load_scans(self, directory: str | Path, recursive: bool = False) -> list[ParseResult]:
        """
        Load all scan files from a directory.

        Args:
            directory: Directory containing scan files
            recursive: Whether to search subdirectories

        Returns:
            List of ParseResult objects
        """
        directory = Path(directory)
        results = []

        pattern = "**/*" if recursive else "*"

        for file_path in directory.glob(pattern):
            if file_path.is_file() and file_path.suffix.lower() in SUPPORTED_FORMATS:
                try:
                    result = self.load_file(file_path)
                    results.append(result)
                except Exception as e:
                    print(f"Warning: Failed to parse {file_path}: {e}")

        return results

    def analyze(
        self,
        deduplicate: bool = True,
        enrich_remediation: bool = True,
        map_compliance: bool = True,
    ) -> dict:
        """
        Analyze loaded vulnerabilities.

        Args:
            deduplicate: Remove duplicate vulnerabilities
            enrich_remediation: Generate AI remediation guidance
            map_compliance: Map vulnerabilities to compliance frameworks

        Returns:
            Analysis results dictionary
        """
        if deduplicate:
            self._deduplicate_vulnerabilities()

        if enrich_remediation:
            self._enrich_remediation()

        if map_compliance:
            self._map_compliance()

        self._analysis_complete = True

        return self.get_summary()

    def _deduplicate_vulnerabilities(self):
        """Collapse the same finding when more than one scan reported it.

        Two scanners covering one host report the same issue, and loading a
        directory of exports exists precisely so that they can. What matters is
        which copy survives when they disagree.

        This used to keep whichever copy had the LONGER DESCRIPTION, and
        nothing else. So a critical remote code execution carrying a terse
        description lost to an informational duplicate carrying a wordy one:
        the client's report kept the informational row, and the critical —
        with its CVSS score — left the report entirely. Severity is the one
        thing a duplicate must never be able to talk down.

        Severity now decides. Richness only breaks a tie between equal
        severities, and either way every field the winner left empty is filled
        from the copy it displaced, so choosing a winner cannot cost a CVE, a
        score or a fix that only the other copy had.

        The rebuild is also no longer quadratic: the old branch rescanned the
        whole output list on every replacement, filtering by `!=` — and
        ParsedVulnerability is a plain dataclass, so that compares by VALUE and
        would drop any other copy that happened to be field-identical.
        """
        best: dict[tuple, ParsedVulnerability] = {}
        first_seen: list[tuple] = []

        for vuln in self._vulnerabilities:
            # Title is matched case-insensitively: two scanners naming the same
            # issue rarely capitalise it the same way.
            key = (
                vuln.title.lower().strip(),
                vuln.asset_ip or vuln.asset_name,
                vuln.asset_port,
            )

            incumbent = best.get(key)
            if incumbent is None:
                best[key] = vuln
                first_seen.append(key)
                continue

            if _preference(vuln) < _preference(incumbent):
                winner, loser = vuln, incumbent
            else:
                winner, loser = incumbent, vuln
            best[key] = _fill_gaps(winner, loser)

        self._vulnerabilities = [best[key] for key in first_seen]

    def _enrich_remediation(self):
        """Generate remediation guidance for findings that arrived without any.

        The trigger used to be `len(vuln.solution) < 50`, and generate_remediation
        only hands a scanner's own text back when it is longer than 50
        characters — so any solution under that was REPLACED by generic
        guidance. "Upgrade nginx to 1.18.1 and disable TLS 1.0." became
        "Address within 30 days. General Remediation Steps for: ...".

        Length is not a proxy for quality; if anything it is the inverse, since
        the most precise fix is usually the shortest sentence on the page. The
        scanner raised the finding and knows what it looked at, so its text is
        kept whenever there is any, and guidance is generated only to fill a
        genuine blank.
        """
        for vuln in self._vulnerabilities:
            if vuln.solution and vuln.solution.strip():
                continue
            result = generate_remediation(
                title=vuln.title,
                description=vuln.description,
                cve_id=vuln.cve_id,
                severity=vuln.severity,
                existing_solution=vuln.solution,
            )
            vuln.solution = result.guidance

    def _map_compliance(self):
        """Map vulnerabilities to compliance frameworks."""
        frameworks = self.settings.compliance_frameworks

        for vuln in self._vulnerabilities:
            mappings = get_compliance_mappings(vuln.title, frameworks)
            vuln.raw_data["compliance_mappings"] = [
                {
                    "framework": m.framework,
                    "requirement": m.requirement,
                    "description": m.description,
                }
                for m in mappings
            ]

    def get_summary(self) -> dict:
        """Get summary statistics of the analysis."""
        severity_counts: defaultdict[str, int] = defaultdict(int)
        asset_counts: defaultdict[str, int] = defaultdict(int)
        scanner_counts: defaultdict[str, int] = defaultdict(int)

        for vuln in self._vulnerabilities:
            severity_counts[vuln.severity] += 1
            # A finding with neither an IP nor a name is not an asset. Counting
            # it made "assets affected" report 2 for one host plus one
            # host-less finding, which is a number a client reads and acts on.
            asset = vuln.asset_ip or vuln.asset_name
            if asset:
                asset_counts[asset] += 1

        for result in self._parse_results:
            scanner_counts[result.scanner_type] += len(result.vulnerabilities)

        return {
            "total_vulnerabilities": len(self._vulnerabilities),
            "severity_breakdown": dict(severity_counts),
            "assets_affected": len(asset_counts),
            "scanners_used": list(scanner_counts.keys()),
            "scan_files_processed": len(self._parse_results),
            "critical_count": severity_counts.get("critical", 0),
            "high_count": severity_counts.get("high", 0),
            "medium_count": severity_counts.get("medium", 0),
            "low_count": severity_counts.get("low", 0),
            "info_count": severity_counts.get("info", 0),
        }

    def get_vulnerabilities(
        self,
        severity: str | None = None,
        asset: str | None = None,
        limit: int | None = None,
    ) -> list[ParsedVulnerability]:
        """
        Get vulnerabilities with optional filtering.

        Args:
            severity: Filter by severity level
            asset: Filter by asset name/IP
            limit: Maximum number to return

        Returns:
            List of vulnerabilities
        """
        vulns = self._vulnerabilities

        if severity:
            vulns = [v for v in vulns if v.severity.lower() == severity.lower()]

        if asset:
            vulns = [
                v
                for v in vulns
                if asset.lower() in (v.asset_ip or "").lower()
                or asset.lower() in (v.asset_name or "").lower()
            ]

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        vulns = sorted(vulns, key=lambda v: severity_order.get(v.severity, 5))

        if limit:
            vulns = vulns[:limit]

        return vulns

    def generate_report(
        self,
        output_path: str | Path,
        format: str = "html",
        client_name: str | None = None,
        project_name: str | None = None,
        include_remediation: bool = True,
        include_compliance: bool = True,
    ) -> Path:
        """
        Generate a vulnerability report.

        Args:
            output_path: Path for the output file
            format: Report format — one of REPORT_FORMATS
            client_name: Client name for the report
            project_name: Project name for the report
            include_remediation: Include remediation guidance
            include_compliance: Include compliance mappings

        Returns:
            Path to the generated report
        """
        output_path = Path(output_path)

        # Ensure analysis is complete
        if not self._analysis_complete:
            self.analyze()

        client_name = client_name or self.settings.client_name or "Client"

        if format.lower() == "html":
            return self._generate_html_report(
                output_path, client_name, project_name, include_remediation, include_compliance
            )
        elif format.lower() == "json":
            return self._generate_json_report(output_path)
        elif format.lower() == "csv":
            return self._generate_csv_report(output_path)
        else:
            raise ValueError(
                f"Unsupported report format {format!r}; supported: {', '.join(REPORT_FORMATS)}"
            )

    def _generate_html_report(
        self,
        output_path: Path,
        client_name: str,
        project_name: str | None,
        include_remediation: bool,
        include_compliance: bool,
    ) -> Path:
        """Generate HTML report."""
        from threat_inspector.reports.html import generate_html_report

        return generate_html_report(
            vulnerabilities=self._vulnerabilities,
            output_path=output_path,
            client_name=client_name,
            project_name=project_name,
            summary=self.get_summary(),
            include_remediation=include_remediation,
            include_compliance=include_compliance,
            company_name=self.settings.reports.company_name,
        )

    def _generate_json_report(self, output_path: Path) -> Path:
        """Generate JSON report."""
        import json

        data = {
            "generated_at": datetime.now().isoformat(),
            "summary": self.get_summary(),
            "vulnerabilities": [v.to_dict() for v in self._vulnerabilities],
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        return output_path

    def _generate_csv_report(self, output_path: Path) -> Path:
        """Generate CSV report."""
        import csv

        output_path.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "title",
            "severity",
            "asset_name",
            "asset_ip",
            "asset_port",
            "cve_id",
            "cvss_score",
            "description",
            "solution",
        ]

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for vuln in self._vulnerabilities:
                writer.writerow(
                    {
                        "title": vuln.title,
                        "severity": vuln.severity,
                        "asset_name": vuln.asset_name,
                        "asset_ip": vuln.asset_ip,
                        "asset_port": vuln.asset_port,
                        "cve_id": vuln.cve_id,
                        "cvss_score": vuln.cvss_score,
                        "description": vuln.description[:500] if vuln.description else "",
                        "solution": vuln.solution[:500] if vuln.solution else "",
                    }
                )

        return output_path

    def clear(self):
        """Clear all loaded data."""
        self._parse_results = []
        self._vulnerabilities = []
        self._analysis_complete = False
