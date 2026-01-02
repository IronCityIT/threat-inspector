"""
Configuration management for Threat Inspector.
Supports environment variables, .env files, and YAML config files.
"""

import os
from pathlib import Path
from typing import Optional
import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """Database configuration."""
    url: str = Field(default="sqlite:///data/threat_inspector.db", alias="DATABASE_URL")
    echo: bool = False


class APISettings(BaseSettings):
    """API server configuration."""
    secret_key: str = Field(default="change-me-in-production", alias="API_SECRET_KEY")
    host: str = Field(default="0.0.0.0", alias="API_HOST")
    port: int = Field(default=8000, alias="API_PORT")
    debug: bool = Field(default=False, alias="API_DEBUG")


class RemediationSettings(BaseSettings):
    """AI remediation engine configuration."""
    engine: str = Field(default="local", alias="REMEDIATION_ENGINE")
    ollama_host: str = Field(default="http://localhost:11434", alias="OLLAMA_HOST")
    ollama_model: str = Field(default="llama3", alias="OLLAMA_MODEL")
    openai_api_key: Optional[str] = Field(default=None, alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4", alias="OPENAI_MODEL")
    anthropic_api_key: Optional[str] = Field(default=None, alias="ANTHROPIC_API_KEY")
    anthropic_model: str = Field(default="claude-3-sonnet-20240229", alias="ANTHROPIC_MODEL")


class ReportSettings(BaseSettings):
    """Report generation configuration."""
    output_dir: Path = Field(default=Path("./reports"), alias="REPORT_OUTPUT_DIR")
    company_name: str = Field(default="Iron City IT Advisors", alias="REPORT_COMPANY_NAME")
    logo_path: Optional[Path] = Field(default=None, alias="REPORT_LOGO_PATH")
    default_formats: list[str] = ["html"]


class Settings(BaseSettings):
    """Main application settings."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )
    
    # Sub-settings
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    api: APISettings = Field(default_factory=APISettings)
    remediation: RemediationSettings = Field(default_factory=RemediationSettings)
    reports: ReportSettings = Field(default_factory=ReportSettings)
    
    # Logging
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    log_file: Optional[Path] = Field(default=None, alias="LOG_FILE")
    
    # Client configuration (loaded from YAML)
    client_name: Optional[str] = None
    domains: list[dict] = []
    compliance_frameworks: list[str] = ["pci-dss"]
    
    @classmethod
    def from_yaml(cls, yaml_path: Path) -> "Settings":
        """Load settings from a YAML configuration file."""
        settings = cls()
        
        if yaml_path.exists():
            with open(yaml_path) as f:
                config = yaml.safe_load(f)
            
            if config:
                if "client" in config:
                    settings.client_name = config["client"].get("name")
                
                if "domains" in config:
                    settings.domains = config["domains"]
                
                if "compliance" in config:
                    settings.compliance_frameworks = config["compliance"].get("frameworks", [])
                
                if "output" in config:
                    if "directory" in config["output"]:
                        settings.reports.output_dir = Path(config["output"]["directory"])
                    if "formats" in config["output"]:
                        settings.reports.default_formats = config["output"]["formats"]
                
                if "remediation" in config:
                    if "engine" in config["remediation"]:
                        settings.remediation.engine = config["remediation"]["engine"]
                    if "model" in config["remediation"]:
                        settings.remediation.ollama_model = config["remediation"]["model"]
        
        return settings


def get_settings(config_path: Optional[Path] = None) -> Settings:
    """
    Get application settings.
    
    Priority:
    1. Environment variables
    2. .env file
    3. YAML config file
    4. Defaults
    """
    if config_path and config_path.exists():
        return Settings.from_yaml(config_path)
    
    # Check for config.yaml in current directory
    default_config = Path("config.yaml")
    if default_config.exists():
        return Settings.from_yaml(default_config)
    
    return Settings()


# Global settings instance
settings = get_settings()
