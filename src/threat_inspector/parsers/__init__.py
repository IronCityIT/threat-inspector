"""
Vulnerability scan file parsers.
Auto-detects and parses various scanner output formats.
"""

from pathlib import Path

from .base import BaseParser, ParsedVulnerability, ParseResult
from .nessus import NessusParser
from .nmap import NmapParser
from .qualys import QualysComplianceParser, QualysParser
from .zap import ZAPParser

__all__ = [
    "BaseParser",
    "ParseResult",
    "ParsedVulnerability",
    "QualysParser",
    "QualysComplianceParser",
    "ZAPParser",
    "NmapParser",
    "NessusParser",
    "get_parser",
    "parse_file",
    "SUPPORTED_FORMATS",
    "KNOWN_SCANNER_TYPES",
]

# Registry of all parsers
PARSER_REGISTRY: list[type[BaseParser]] = [
    QualysParser,
    QualysComplianceParser,
    ZAPParser,
    NmapParser,
    NessusParser,
]

# The scanner_type values a caller may assert. Derived from the registry so a
# new parser cannot be addressable in one place and not the other.
KNOWN_SCANNER_TYPES = tuple(sorted({p.SCANNER_TYPE for p in PARSER_REGISTRY}))

# Supported file formats.
# Descriptions are client-safe (white-labeled): they must not name the underlying
# scanner/vendor. Internal auto-detection below still keys off vendor filename hints.
SUPPORTED_FORMATS = {
    ".xlsx": "Spreadsheet export (Excel)",
    ".xlsm": "Spreadsheet export (macro-enabled Excel)",
    ".csv": "CSV scan export",
    ".xml": "XML scan export",
    ".json": "JSON scan export",
    ".nessus": "Vulnerability scan export",
    ".txt": "Text scan output",
    ".nmap": "Network scan output",
}


def get_parser(file_path: Path, scanner_type: str | None = None) -> BaseParser | None:
    """
    Get the appropriate parser for a file.

    Args:
        file_path: Path to the scan file
        scanner_type: Optional. The caller ASSERTING the format. A value that is
            not recognised, or whose parser cannot read this file, raises rather
            than falling back to auto-detection.

    Returns:
        Parser instance, or None when auto-detection finds no match.

    Raises:
        ValueError: If `scanner_type` is given and cannot be honoured.
    """
    # An explicit scanner_type is the caller ASSERTING what the file is. It used
    # to be a suggestion: an unknown value, or one whose parser could not read
    # the file, silently fell through to auto-detection and something else
    # parsed it. Measured through the API's own query parameter, against a
    # vulnerability-scan CSV:
    #
    #     scanner_type=zap    -> 200, 8 findings   (hint discarded, Nessus ran)
    #     scanner_type=bogus  -> 200, 8 findings   (typo discarded)
    #     scanner_type=QUALYS -> 200, 0 findings   (honoured, wrong, and empty)
    #
    # The first two ignore what the caller said without a word; the third is the
    # "corrupt upload reported as a clean, empty ingest" failure, reachable from
    # a query string. A false assertion is now refused rather than worked around.
    if scanner_type:
        requested = scanner_type.lower().strip()
        candidates = [p for p in PARSER_REGISTRY if p.SCANNER_TYPE == requested]
        if not candidates:
            raise ValueError(
                f"unknown scanner_type {scanner_type!r}; "
                f"known types: {', '.join(KNOWN_SCANNER_TYPES)}"
            )
        for parser_class in candidates:
            if parser_class.can_parse(file_path):
                return parser_class()
        handles = sorted({e for p in candidates for e in p.SUPPORTED_EXTENSIONS})
        raise ValueError(
            f"scanner_type {scanner_type!r} cannot read {file_path.suffix or '(no extension)'!r}; "
            f"it handles: {', '.join(handles)}"
        )

    # Auto-detect based on file extension and content
    extension = file_path.suffix.lower()

    # Special handling for .nessus files
    if extension == ".nessus":
        return NessusParser()

    # Try to detect from filename hints
    filename_lower = file_path.name.lower()

    if "qualys" in filename_lower:
        if "compliance" in filename_lower:
            return QualysComplianceParser()
        return QualysParser()

    if "zap" in filename_lower:
        return ZAPParser()

    if "nmap" in filename_lower:
        return NmapParser()

    if "nessus" in filename_lower or "tenable" in filename_lower:
        return NessusParser()

    # Fall back to extension-based detection
    if extension in [".xlsx", ".xlsm"]:
        # Default Excel files to Qualys
        return QualysParser()

    if extension == ".xml":
        # Try to detect XML type from content
        try:
            with open(file_path, encoding="utf-8") as f:
                header = f.read(500).lower()

            if "owasp zap" in header or "<alertitem" in header:
                return ZAPParser()
            if "nessus" in header or "<reporthost" in header:
                return NessusParser()
            if "nmaprun" in header or "<host" in header:
                return NmapParser()
        except Exception:
            pass

        # Default XML to ZAP
        return ZAPParser()

    if extension in [".txt", ".nmap"]:
        return NmapParser()

    if extension == ".json":
        return ZAPParser()

    if extension == ".csv":
        # Try to detect CSV type from headers
        try:
            with open(file_path, encoding="utf-8") as f:
                header = f.readline().lower()

            if "plugin" in header or "nessus" in header:
                return NessusParser()
            # Default CSV to Qualys
            return QualysParser()
        except Exception:
            return QualysParser()

    return None


def parse_file(file_path: Path, scanner_type: str | None = None) -> ParseResult:
    """
    Parse a vulnerability scan file.

    Args:
        file_path: Path to the scan file
        scanner_type: Optional hint for scanner type

    Returns:
        ParseResult with vulnerabilities and metadata

    Raises:
        ValueError: If no suitable parser found
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    parser = get_parser(file_path, scanner_type)

    if parser is None:
        raise ValueError(
            f"No parser available for file: {file_path}\n"
            f"Supported formats: {', '.join(SUPPORTED_FORMATS.keys())}"
        )

    return parser.parse(file_path)
