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
]

# Registry of all parsers
PARSER_REGISTRY: list[type[BaseParser]] = [
    QualysParser,
    QualysComplianceParser,
    ZAPParser,
    NmapParser,
    NessusParser,
]

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
        scanner_type: Optional hint for scanner type (qualys, zap, nmap, nessus)

    Returns:
        Parser instance or None if no suitable parser found
    """
    # If scanner type is specified, try to match directly
    if scanner_type:
        scanner_type = scanner_type.lower()
        for parser_class in PARSER_REGISTRY:
            if parser_class.SCANNER_TYPE == scanner_type:
                if parser_class.can_parse(file_path):
                    return parser_class()

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
