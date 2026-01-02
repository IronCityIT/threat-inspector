"""
Tests for Threat Inspector parsers.
"""

import pytest
from pathlib import Path
from threat_inspector.parsers import parse_file, get_parser, SUPPORTED_FORMATS
from threat_inspector.parsers.base import ParsedVulnerability


class TestParserRegistry:
    """Test parser registration and detection."""
    
    def test_supported_formats_not_empty(self):
        """Ensure we have supported formats."""
        assert len(SUPPORTED_FORMATS) > 0
    
    def test_get_parser_xlsx(self, tmp_path):
        """Test parser detection for Excel files."""
        test_file = tmp_path / "test.xlsx"
        test_file.touch()
        
        parser = get_parser(test_file)
        assert parser is not None
        assert parser.SCANNER_TYPE == "qualys"
    
    def test_get_parser_xml_zap_hint(self, tmp_path):
        """Test parser detection with scanner hint."""
        test_file = tmp_path / "test.xml"
        test_file.touch()
        
        parser = get_parser(test_file, scanner_type="zap")
        assert parser is not None
        assert parser.SCANNER_TYPE == "zap"
    
    def test_get_parser_nessus(self, tmp_path):
        """Test parser detection for .nessus files."""
        test_file = tmp_path / "scan.nessus"
        test_file.touch()
        
        parser = get_parser(test_file)
        assert parser is not None
        assert parser.SCANNER_TYPE == "nessus"


class TestParsedVulnerability:
    """Test ParsedVulnerability dataclass."""
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        vuln = ParsedVulnerability(
            title="SQL Injection",
            severity="high",
            description="Test description",
            asset_ip="192.168.1.1",
        )
        
        data = vuln.to_dict()
        
        assert data["title"] == "SQL Injection"
        assert data["severity"] == "high"
        assert data["asset_ip"] == "192.168.1.1"
    
    def test_severity_normalization(self):
        """Test that severity is stored correctly."""
        vuln = ParsedVulnerability(
            title="Test",
            severity="high",
        )
        
        assert vuln.severity == "high"


class TestSeverityNormalization:
    """Test severity normalization across parsers."""
    
    def test_normalize_critical(self):
        """Test critical severity normalization."""
        from threat_inspector.parsers.base import BaseParser
        
        assert BaseParser.normalize_severity("critical") == "critical"
        assert BaseParser.normalize_severity("CRITICAL") == "critical"
        assert BaseParser.normalize_severity("4") == "critical"
    
    def test_normalize_high(self):
        """Test high severity normalization."""
        from threat_inspector.parsers.base import BaseParser
        
        assert BaseParser.normalize_severity("high") == "high"
        assert BaseParser.normalize_severity("HIGH") == "high"
        assert BaseParser.normalize_severity("3") == "high"
    
    def test_normalize_medium(self):
        """Test medium severity normalization."""
        from threat_inspector.parsers.base import BaseParser
        
        assert BaseParser.normalize_severity("medium") == "medium"
        assert BaseParser.normalize_severity("moderate") == "medium"
        assert BaseParser.normalize_severity("2") == "medium"
    
    def test_normalize_low(self):
        """Test low severity normalization."""
        from threat_inspector.parsers.base import BaseParser
        
        assert BaseParser.normalize_severity("low") == "low"
        assert BaseParser.normalize_severity("1") == "low"
    
    def test_normalize_info(self):
        """Test info severity normalization."""
        from threat_inspector.parsers.base import BaseParser
        
        assert BaseParser.normalize_severity("info") == "info"
        assert BaseParser.normalize_severity("informational") == "info"
        assert BaseParser.normalize_severity("0") == "info"


# Run with: pytest tests/test_parsers.py -v
