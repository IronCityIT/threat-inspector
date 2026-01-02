"""
Command Line Interface for Threat Inspector.
"""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from threat_inspector import ThreatInspector, __version__
from threat_inspector.parsers import SUPPORTED_FORMATS

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="threat-inspector")
def main():
    """
    Iron City Threat Inspector - Advanced Vulnerability Assessment Platform
    
    Aggregate, analyze, and report on vulnerability scan data from multiple sources.
    """
    pass


@main.command()
@click.option(
    "--input", "-i",
    required=True,
    type=click.Path(exists=True),
    help="Input file or directory containing scan files"
)
@click.option(
    "--output", "-o",
    default="./reports",
    type=click.Path(),
    help="Output directory for reports (default: ./reports)"
)
@click.option(
    "--format", "-f",
    multiple=True,
    default=["html"],
    type=click.Choice(["html", "json", "csv", "pdf"]),
    help="Output format(s) (default: html)"
)
@click.option(
    "--client", "-c",
    default=None,
    help="Client name for the report"
)
@click.option(
    "--project", "-p",
    default=None,
    help="Project name for the report"
)
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Path to YAML configuration file"
)
@click.option(
    "--recursive", "-r",
    is_flag=True,
    help="Recursively search directories for scan files"
)
@click.option(
    "--no-remediation",
    is_flag=True,
    help="Skip remediation guidance generation"
)
@click.option(
    "--no-compliance",
    is_flag=True,
    help="Skip compliance framework mapping"
)
def analyze(
    input: str,
    output: str,
    format: tuple,
    client: Optional[str],
    project: Optional[str],
    config: Optional[str],
    recursive: bool,
    no_remediation: bool,
    no_compliance: bool,
):
    """
    Analyze vulnerability scan files and generate reports.
    
    Examples:
    
        threat-inspector analyze -i ./scans -o ./reports
        
        threat-inspector analyze -i scan.xml -f html -f json -c "Acme Corp"
        
        threat-inspector analyze -i ./scans -r --config config.yaml
    """
    input_path = Path(input)
    output_path = Path(output)
    
    # Initialize inspector
    config_path = Path(config) if config else None
    inspector = ThreatInspector(config_path=config_path)
    
    console.print(f"\n[bold blue]Iron City Threat Inspector v{__version__}[/bold blue]\n")
    
    # Load scan files
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Loading scan files...", total=None)
        
        if input_path.is_file():
            try:
                result = inspector.load_file(input_path)
                progress.update(task, description=f"Loaded {input_path.name}: {result.total_count} findings")
            except Exception as e:
                console.print(f"[red]Error loading {input_path}: {e}[/red]")
                sys.exit(1)
        else:
            results = inspector.load_scans(input_path, recursive=recursive)
            total_vulns = sum(r.total_count for r in results)
            progress.update(task, description=f"Loaded {len(results)} files: {total_vulns} findings")
    
    # Analyze
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing vulnerabilities...", total=None)
        
        summary = inspector.analyze(
            enrich_remediation=not no_remediation,
            map_compliance=not no_compliance,
        )
        
        progress.update(task, description="Analysis complete")
    
    # Display summary
    _display_summary(summary)
    
    # Generate reports
    output_path.mkdir(parents=True, exist_ok=True)
    
    client_name = client or "Assessment"
    timestamp = Path(input_path).stem if input_path.is_file() else "report"
    
    for fmt in format:
        report_name = f"{timestamp}_vulnerability_report.{fmt}"
        report_path = output_path / report_name
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(f"Generating {fmt.upper()} report...", total=None)
            
            try:
                inspector.generate_report(
                    output_path=report_path,
                    format=fmt,
                    client_name=client_name,
                    project_name=project,
                    include_remediation=not no_remediation,
                    include_compliance=not no_compliance,
                )
                progress.update(task, description=f"[green]✓[/green] Generated: {report_path}")
                console.print(f"  [green]→[/green] {report_path}")
            except Exception as e:
                console.print(f"  [red]✗[/red] Failed to generate {fmt}: {e}")
    
    console.print("\n[green]Analysis complete![/green]\n")


@main.command()
def formats():
    """List supported scan file formats."""
    console.print("\n[bold]Supported Scan File Formats[/bold]\n")
    
    table = Table(show_header=True, header_style="bold")
    table.add_column("Extension")
    table.add_column("Description")
    
    for ext, desc in SUPPORTED_FORMATS.items():
        table.add_row(ext, desc)
    
    console.print(table)
    console.print()


@main.command()
@click.option(
    "--output", "-o",
    default=".",
    type=click.Path(),
    help="Output directory for config files"
)
def init(output: str):
    """Initialize a new project with sample configuration."""
    output_path = Path(output)
    
    # Create config.yaml
    config_content = """# Iron City Threat Inspector Configuration

client:
  name: "Your Client Name"

domains:
  - name: "example.com"
    ips: ["192.168.1.1", "192.168.1.2"]
    subnets: ["192.168.1.0/24"]

output:
  directory: "./reports"
  formats: ["html", "json"]

remediation:
  engine: "local"  # Options: local, ollama, openai, anthropic

compliance:
  frameworks: ["pci-dss", "hipaa", "soc2", "nist"]
"""
    
    config_path = output_path / "config.yaml"
    with open(config_path, "w") as f:
        f.write(config_content)
    
    console.print(f"[green]✓[/green] Created {config_path}")
    
    # Create .env.example
    env_content = """# Threat Inspector Environment Configuration

# Database
DATABASE_URL=sqlite:///data/threat_inspector.db

# AI Remediation
REMEDIATION_ENGINE=local
# OLLAMA_HOST=http://localhost:11434
# OLLAMA_MODEL=llama3

# Report Branding
REPORT_COMPANY_NAME=Iron City IT Advisors
"""
    
    env_path = output_path / ".env.example"
    with open(env_path, "w") as f:
        f.write(env_content)
    
    console.print(f"[green]✓[/green] Created {env_path}")
    
    # Create directories
    (output_path / "scans").mkdir(exist_ok=True)
    (output_path / "reports").mkdir(exist_ok=True)
    
    console.print(f"[green]✓[/green] Created scans/ directory")
    console.print(f"[green]✓[/green] Created reports/ directory")
    
    console.print("\n[bold]Project initialized![/bold]")
    console.print("\nNext steps:")
    console.print("  1. Edit config.yaml with your client information")
    console.print("  2. Copy .env.example to .env and configure")
    console.print("  3. Add scan files to the scans/ directory")
    console.print("  4. Run: threat-inspector analyze -i ./scans\n")


@main.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8000, type=int, help="Port to listen on")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
def serve(host: str, port: int, reload: bool):
    """Start the web dashboard."""
    try:
        import uvicorn
        from threat_inspector.api.main import app
        
        console.print(f"\n[bold blue]Starting Threat Inspector Dashboard[/bold blue]")
        console.print(f"  → http://{host}:{port}\n")
        
        uvicorn.run(
            "threat_inspector.api.main:app",
            host=host,
            port=port,
            reload=reload,
        )
    except ImportError:
        console.print("[red]Error: uvicorn not installed. Run: pip install uvicorn[/red]")
        sys.exit(1)


@main.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8000, type=int, help="Port to listen on")
def api(host: str, port: int):
    """Start the REST API server."""
    try:
        import uvicorn
        
        console.print(f"\n[bold blue]Starting Threat Inspector API[/bold blue]")
        console.print(f"  → http://{host}:{port}")
        console.print(f"  → Docs: http://{host}:{port}/docs\n")
        
        uvicorn.run(
            "threat_inspector.api.main:app",
            host=host,
            port=port,
        )
    except ImportError:
        console.print("[red]Error: uvicorn not installed. Run: pip install uvicorn[/red]")
        sys.exit(1)


def _display_summary(summary: dict):
    """Display analysis summary in a table."""
    console.print("\n[bold]Analysis Summary[/bold]\n")
    
    table = Table(show_header=False, box=None)
    table.add_column(style="dim")
    table.add_column()
    
    table.add_row("Total Vulnerabilities", f"[bold]{summary['total_vulnerabilities']}[/bold]")
    table.add_row("", "")
    
    # Severity breakdown with colors
    if summary['critical_count'] > 0:
        table.add_row("Critical", f"[red bold]{summary['critical_count']}[/red bold]")
    if summary['high_count'] > 0:
        table.add_row("High", f"[orange1]{summary['high_count']}[/orange1]")
    if summary['medium_count'] > 0:
        table.add_row("Medium", f"[yellow]{summary['medium_count']}[/yellow]")
    if summary['low_count'] > 0:
        table.add_row("Low", f"[blue]{summary['low_count']}[/blue]")
    if summary['info_count'] > 0:
        table.add_row("Informational", f"[dim]{summary['info_count']}[/dim]")
    
    table.add_row("", "")
    table.add_row("Assets Affected", str(summary.get('assets_affected', 'N/A')))
    table.add_row("Scan Files", str(summary.get('scan_files_processed', 'N/A')))
    
    console.print(table)
    console.print()


if __name__ == "__main__":
    main()
