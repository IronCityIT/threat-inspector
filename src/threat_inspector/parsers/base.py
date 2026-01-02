"""
Base parser class for vulnerability scan files.
All scanner-specific parsers inherit from this.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
import hashlib


@dataclass
class ParsedVulnerability:
    """Standardized vulnerability data structure."""
    title: str
    severity: str  # critical, high, medium, low, info
    description: str = ""
    
    # Asset info
    asset_name: str = ""
    asset_ip: str = ""
    asset_port: Optional[int] = None
    asset_url: str = ""
    
    # Vulnerability identifiers
    cve_id: str = ""
    cwe_id: str = ""
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    
    # Scanner-specific
    scanner_id: str = ""
    scanner_severity: str = ""
    
    # Remediation
    solution: str = ""
    
    # Evidence
    evidence: str = ""
    request: str = ""
    response: str = ""
    
    # Metadata
    discovered_at: Optional[datetime] = None
    raw_data: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "asset_name": self.asset_name,
            "asset_ip": self.asset_ip,
            "asset_port": self.asset_port,
            "asset_url": self.asset_url,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "scanner_id": self.scanner_id,
            "scanner_severity": self.scanner_severity,
            "solution": self.solution,
            "evidence": self.evidence,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
        }


@dataclass
class ParseResult:
    """Result of parsing a scan file."""
    scanner_type: str
    vulnerabilities: list[ParsedVulnerability]
    scan_date: Optional[datetime] = None
    scan_metadata: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    
    @property
    def total_count(self) -> int:
        return len(self.vulnerabilities)
    
    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in self.vulnerabilities:
            severity = vuln.severity.lower()
            if severity in counts:
                counts[severity] += 1
        return counts


class BaseParser(ABC):
    """Abstract base class for scan file parsers."""
    
    # Override in subclasses
    SCANNER_TYPE: str = "unknown"
    SUPPORTED_EXTENSIONS: list[str] = []
    
    def __init__(self):
        self.errors: list[str] = []
        self.warnings: list[str] = []
    
    @abstractmethod
    def parse(self, file_path: Path) -> ParseResult:
        """
        Parse a scan file and return standardized results.
        
        Args:
            file_path: Path to the scan file
            
        Returns:
            ParseResult containing vulnerabilities and metadata
        """
        pass
    
    @classmethod
    def can_parse(cls, file_path: Path) -> bool:
        """Check if this parser can handle the given file."""
        return file_path.suffix.lower() in cls.SUPPORTED_EXTENSIONS
    
    @staticmethod
    def normalize_severity(severity: str) -> str:
        """
        Normalize severity to standard levels.
        
        Args:
            severity: Raw severity string from scanner
            
        Returns:
            One of: critical, high, medium, low, info
        """
        severity = str(severity).lower().strip()
        
        # Map common variations
        mapping = {
            # Critical
            "critical": "critical",
            "crit": "critical",
            "4": "critical",
            "urgent": "critical",
            
            # High
            "high": "high",
            "3": "high",
            "serious": "high",
            
            # Medium
            "medium": "medium",
            "med": "medium",
            "moderate": "medium",
            "2": "medium",
            
            # Low
            "low": "low",
            "1": "low",
            "minor": "low",
            
            # Info
            "info": "info",
            "informational": "info",
            "information": "info",
            "0": "info",
            "none": "info",
        }
        
        return mapping.get(severity, "info")
    
    @staticmethod
    def calculate_file_hash(file_path: Path) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def add_error(self, message: str):
        """Add an error message."""
        self.errors.append(message)
    
    def add_warning(self, message: str):
        """Add a warning message."""
        self.warnings.append(message)
