"""
HTML report generator for Threat Inspector.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional

from threat_inspector.parsers.base import ParsedVulnerability


def generate_html_report(
    vulnerabilities: list[ParsedVulnerability],
    output_path: Path,
    client_name: str = "Client",
    project_name: Optional[str] = None,
    summary: Optional[dict] = None,
    include_remediation: bool = True,
    include_compliance: bool = True,
    company_name: str = "Iron City IT Advisors",
    logo_base64: Optional[str] = None,
) -> Path:
    """
    Generate an HTML vulnerability report.
    
    Args:
        vulnerabilities: List of vulnerabilities to include
        output_path: Path to save the report
        client_name: Name of the client
        project_name: Name of the project/assessment
        summary: Summary statistics dictionary
        include_remediation: Include remediation guidance
        include_compliance: Include compliance mappings
        company_name: Company name for branding
        logo_base64: Base64 encoded logo image
        
    Returns:
        Path to the generated report
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Sort vulnerabilities by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_vulns = sorted(vulnerabilities, key=lambda v: severity_order.get(v.severity, 5))
    
    # Generate summary if not provided
    if summary is None:
        summary = {
            "total_vulnerabilities": len(vulnerabilities),
            "critical_count": sum(1 for v in vulnerabilities if v.severity == "critical"),
            "high_count": sum(1 for v in vulnerabilities if v.severity == "high"),
            "medium_count": sum(1 for v in vulnerabilities if v.severity == "medium"),
            "low_count": sum(1 for v in vulnerabilities if v.severity == "low"),
            "info_count": sum(1 for v in vulnerabilities if v.severity == "info"),
        }
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Assessment Report - {client_name}</title>
    <style>
        :root {{
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #2563eb;
            --info: #6b7280;
            --bg-primary: #ffffff;
            --bg-secondary: #f8fafc;
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --border: #e2e8f0;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: var(--bg-secondary);
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        header {{
            background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%);
            color: white;
            padding: 3rem 2rem;
            margin-bottom: 2rem;
        }}
        
        header h1 {{
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }}
        
        header .subtitle {{
            opacity: 0.9;
            font-size: 1.1rem;
        }}
        
        header .meta {{
            margin-top: 1.5rem;
            font-size: 0.9rem;
            opacity: 0.8;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        
        .summary-card {{
            background: var(--bg-primary);
            border-radius: 8px;
            padding: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .summary-card .count {{
            font-size: 2.5rem;
            font-weight: 700;
            line-height: 1;
        }}
        
        .summary-card .label {{
            font-size: 0.875rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 0.5rem;
        }}
        
        .summary-card.critical .count {{ color: var(--critical); }}
        .summary-card.high .count {{ color: var(--high); }}
        .summary-card.medium .count {{ color: var(--medium); }}
        .summary-card.low .count {{ color: var(--low); }}
        .summary-card.info .count {{ color: var(--info); }}
        
        section {{
            background: var(--bg-primary);
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        
        section h2 {{
            font-size: 1.5rem;
            margin-bottom: 1.5rem;
            padding-bottom: 0.75rem;
            border-bottom: 2px solid var(--border);
        }}
        
        .vuln-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }}
        
        .vuln-table th,
        .vuln-table td {{
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        
        .vuln-table th {{
            background: var(--bg-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
        }}
        
        .vuln-table tr:hover {{
            background: var(--bg-secondary);
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .severity-critical {{
            background: #fef2f2;
            color: var(--critical);
        }}
        
        .severity-high {{
            background: #fff7ed;
            color: var(--high);
        }}
        
        .severity-medium {{
            background: #fefce8;
            color: var(--medium);
        }}
        
        .severity-low {{
            background: #eff6ff;
            color: var(--low);
        }}
        
        .severity-info {{
            background: #f9fafb;
            color: var(--info);
        }}
        
        .vuln-detail {{
            background: var(--bg-secondary);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border-left: 4px solid var(--border);
        }}
        
        .vuln-detail.critical {{ border-left-color: var(--critical); }}
        .vuln-detail.high {{ border-left-color: var(--high); }}
        .vuln-detail.medium {{ border-left-color: var(--medium); }}
        .vuln-detail.low {{ border-left-color: var(--low); }}
        .vuln-detail.info {{ border-left-color: var(--info); }}
        
        .vuln-detail h3 {{
            font-size: 1.1rem;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .vuln-detail .meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 1rem;
            font-size: 0.875rem;
            color: var(--text-secondary);
        }}
        
        .vuln-detail .meta span {{
            display: flex;
            align-items: center;
            gap: 0.25rem;
        }}
        
        .vuln-detail .description {{
            margin-bottom: 1rem;
        }}
        
        .vuln-detail .remediation {{
            background: var(--bg-primary);
            border-radius: 4px;
            padding: 1rem;
            margin-top: 1rem;
        }}
        
        .vuln-detail .remediation h4 {{
            font-size: 0.875rem;
            color: var(--text-secondary);
            margin-bottom: 0.5rem;
        }}
        
        .compliance-tags {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.5rem;
        }}
        
        .compliance-tag {{
            background: #dbeafe;
            color: #1e40af;
            padding: 0.125rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
        }}
        
        footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}
        
        @media print {{
            body {{ background: white; }}
            .container {{ max-width: 100%; padding: 0; }}
            section {{ box-shadow: none; border: 1px solid var(--border); }}
            .vuln-detail {{ break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Vulnerability Assessment Report</h1>
            <div class="subtitle">{client_name}{f" - {project_name}" if project_name else ""}</div>
            <div class="meta">
                <div>Generated: {datetime.now().strftime("%B %d, %Y at %H:%M")}</div>
                <div>Prepared by: {company_name}</div>
            </div>
        </div>
    </header>
    
    <div class="container">
        <div class="summary-grid">
            <div class="summary-card">
                <div class="count">{summary['total_vulnerabilities']}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="summary-card critical">
                <div class="count">{summary['critical_count']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">{summary['high_count']}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{summary['medium_count']}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">{summary['low_count']}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card info">
                <div class="count">{summary['info_count']}</div>
                <div class="label">Informational</div>
            </div>
        </div>
        
        <section>
            <h2>Executive Summary</h2>
            <p>
                This report presents the findings from a comprehensive vulnerability assessment 
                conducted for {client_name}. A total of <strong>{summary['total_vulnerabilities']}</strong> 
                vulnerabilities were identified across the scanned assets.
            </p>
            <p style="margin-top: 1rem;">
                {"<strong style='color: var(--critical)'>Immediate attention is required</strong> for " + str(summary['critical_count']) + " critical vulnerabilities that pose significant risk to the organization." if summary['critical_count'] > 0 else "No critical vulnerabilities were identified during this assessment."}
            </p>
        </section>
        
        <section>
            <h2>Vulnerability Summary</h2>
            <table class="vuln-table">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Vulnerability</th>
                        <th>Asset</th>
                        <th>CVE</th>
                        <th>CVSS</th>
                    </tr>
                </thead>
                <tbody>
"""
    
    # Add summary table rows
    for vuln in sorted_vulns[:50]:  # Limit to 50 in summary table
        cvss_display = f"{vuln.cvss_score:.1f}" if vuln.cvss_score else "N/A"
        html_content += f"""
                    <tr>
                        <td><span class="severity-badge severity-{vuln.severity}">{vuln.severity}</span></td>
                        <td>{_escape_html(vuln.title[:80])}{"..." if len(vuln.title) > 80 else ""}</td>
                        <td>{_escape_html(vuln.asset_ip or vuln.asset_name or "N/A")}</td>
                        <td>{_escape_html(vuln.cve_id) if vuln.cve_id else "N/A"}</td>
                        <td>{cvss_display}</td>
                    </tr>
"""
    
    html_content += """
                </tbody>
            </table>
        </section>
        
        <section>
            <h2>Detailed Findings</h2>
"""
    
    # Add detailed findings
    for i, vuln in enumerate(sorted_vulns, 1):
        compliance_html = ""
        if include_compliance and vuln.raw_data.get("compliance_mappings"):
            tags = [f"{m['framework']}-{m['requirement']}" for m in vuln.raw_data["compliance_mappings"]]
            compliance_html = f"""
                <div class="compliance-tags">
                    {"".join(f'<span class="compliance-tag">{tag}</span>' for tag in tags[:5])}
                </div>
"""
        
        remediation_html = ""
        if include_remediation and vuln.solution:
            remediation_html = f"""
                <div class="remediation">
                    <h4>Remediation</h4>
                    <div>{_escape_html(vuln.solution).replace(chr(10), '<br>')}</div>
                </div>
"""
        
        html_content += f"""
            <div class="vuln-detail {vuln.severity}">
                <h3>
                    <span class="severity-badge severity-{vuln.severity}">{vuln.severity}</span>
                    {_escape_html(vuln.title)}
                </h3>
                <div class="meta">
                    <span><strong>Asset:</strong> {_escape_html(vuln.asset_ip or vuln.asset_name or "N/A")}</span>
                    {f'<span><strong>Port:</strong> {vuln.asset_port}</span>' if vuln.asset_port else ''}
                    {f'<span><strong>CVE:</strong> {_escape_html(vuln.cve_id)}</span>' if vuln.cve_id else ''}
                    {f'<span><strong>CVSS:</strong> {vuln.cvss_score:.1f}</span>' if vuln.cvss_score else ''}
                </div>
                {compliance_html}
                <div class="description">
                    {_escape_html(vuln.description[:1000] if vuln.description else "No description available.")}
                </div>
                {remediation_html}
            </div>
"""
    
    html_content += f"""
        </section>
        
        <section>
            <h2>Recommendations</h2>
            <p>Based on the findings of this assessment, we recommend the following prioritized actions:</p>
            <ol style="margin-top: 1rem; padding-left: 1.5rem;">
                <li style="margin-bottom: 0.5rem;"><strong>Address Critical Vulnerabilities Immediately:</strong> 
                    Focus on the {summary['critical_count']} critical findings that pose the highest risk.</li>
                <li style="margin-bottom: 0.5rem;"><strong>Patch Management:</strong> 
                    Implement a regular patch management process to address outdated software components.</li>
                <li style="margin-bottom: 0.5rem;"><strong>Security Configuration:</strong> 
                    Review and harden security configurations based on industry best practices.</li>
                <li style="margin-bottom: 0.5rem;"><strong>Continuous Monitoring:</strong> 
                    Establish ongoing vulnerability scanning to detect new issues promptly.</li>
                <li style="margin-bottom: 0.5rem;"><strong>Security Awareness:</strong> 
                    Ensure development and operations teams are trained on secure coding and configuration practices.</li>
            </ol>
        </section>
    </div>
    
    <footer>
        <p>This report was generated by {company_name} using Iron City Threat Inspector.</p>
        <p>Confidential - For authorized recipients only.</p>
    </footer>
</body>
</html>
"""
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    return output_path


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    if not text:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )
