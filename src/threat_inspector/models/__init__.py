"""
Database models for Threat Inspector.
Supports multi-client, multi-project vulnerability management.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Float, 
    ForeignKey, Boolean, JSON, Enum, create_engine
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
import enum

Base = declarative_base()


class SeverityLevel(enum.Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScannerType(enum.Enum):
    """Supported vulnerability scanners."""
    QUALYS = "qualys"
    ZAP = "zap"
    NMAP = "nmap"
    NESSUS = "nessus"
    OPENVAS = "openvas"
    BURP = "burp"
    TENABLE = "tenable"
    CUSTOM = "custom"


class Client(Base):
    """Client/organization model."""
    __tablename__ = "clients"
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    contact_email = Column(String(255))
    contact_name = Column(String(255))
    industry = Column(String(100))
    notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    domains = relationship("Domain", back_populates="client", cascade="all, delete-orphan")
    projects = relationship("Project", back_populates="client", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Client(id={self.id}, name='{self.name}')>"


class Domain(Base):
    """Domain/asset configuration for a client."""
    __tablename__ = "domains"
    
    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    name = Column(String(255), nullable=False)
    ip_addresses = Column(JSON, default=list)  # List of IPs
    subnets = Column(JSON, default=list)  # List of CIDR notations
    description = Column(Text)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    client = relationship("Client", back_populates="domains")
    
    def __repr__(self):
        return f"<Domain(id={self.id}, name='{self.name}')>"


class Project(Base):
    """Assessment project for a client."""
    __tablename__ = "projects"
    
    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("clients.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    status = Column(String(50), default="active")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    client = relationship("Client", back_populates="projects")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Project(id={self.id}, name='{self.name}')>"


class Scan(Base):
    """Uploaded scan file and metadata."""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    scanner_type = Column(String(50), nullable=False)
    scan_date = Column(DateTime)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    file_hash = Column(String(64))  # SHA-256 hash
    raw_data_path = Column(String(500))  # Path to stored file
    status = Column(String(50), default="pending")  # pending, processed, error
    error_message = Column(Text)
    metadata = Column(JSON, default=dict)
    
    # Relationships
    project = relationship("Project", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Scan(id={self.id}, scanner='{self.scanner_type}')>"


class Vulnerability(Base):
    """Individual vulnerability finding."""
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    
    # Core fields
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    
    # Asset information
    asset_name = Column(String(255))
    asset_ip = Column(String(50))
    asset_port = Column(Integer)
    asset_url = Column(String(1000))
    
    # Vulnerability details
    cve_id = Column(String(50))
    cwe_id = Column(String(50))
    cvss_score = Column(Float)
    cvss_vector = Column(String(100))
    
    # Scanner-specific
    scanner_id = Column(String(100))  # ID from the scanner
    scanner_severity = Column(String(50))  # Original severity from scanner
    
    # Remediation
    solution = Column(Text)
    remediation_generated = Column(Text)  # AI-generated remediation
    
    # Evidence
    evidence = Column(Text)
    request = Column(Text)
    response = Column(Text)
    
    # Compliance
    compliance_tags = Column(JSON, default=list)  # ["pci-dss-6.1", "hipaa-164.312"]
    
    # Status tracking
    status = Column(String(50), default="open")  # open, in_progress, resolved, false_positive
    notes = Column(Text)
    
    # Correlation
    correlation_id = Column(String(100))  # For grouping related vulns
    is_duplicate = Column(Boolean, default=False)
    duplicate_of_id = Column(Integer, ForeignKey("vulnerabilities.id"))
    
    # Timestamps
    discovered_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")
    
    def __repr__(self):
        return f"<Vulnerability(id={self.id}, title='{self.title[:50]}...', severity='{self.severity}')>"
    
    @property
    def severity_order(self) -> int:
        """Return numeric severity for sorting (lower = more severe)."""
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return order.get(self.severity.lower(), 5)


class Report(Base):
    """Generated report metadata."""
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    title = Column(String(255), nullable=False)
    format = Column(String(20), nullable=False)  # html, pdf, json, csv
    file_path = Column(String(500))
    generated_at = Column(DateTime, default=datetime.utcnow)
    generated_by = Column(String(100))
    parameters = Column(JSON, default=dict)  # Report generation parameters
    
    def __repr__(self):
        return f"<Report(id={self.id}, title='{self.title}', format='{self.format}')>"


# Database initialization
def init_db(database_url: str = "sqlite:///data/threat_inspector.db"):
    """Initialize the database and create tables."""
    engine = create_engine(database_url, echo=False)
    Base.metadata.create_all(engine)
    return engine


def get_session(database_url: str = "sqlite:///data/threat_inspector.db"):
    """Get a database session."""
    engine = create_engine(database_url, echo=False)
    Session = sessionmaker(bind=engine)
    return Session()
