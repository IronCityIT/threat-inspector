"""
FastAPI REST API for Threat Inspector.
"""

import tempfile
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from threat_inspector import ThreatInspector, __version__
from threat_inspector.config import get_settings
from threat_inspector.parsers import SUPPORTED_FORMATS

app = FastAPI(
    title="Iron City Threat Inspector API",
    description="Advanced Vulnerability Assessment & Remediation Platform",
    version=__version__,
)

# CORS: use an explicit origin allowlist from settings. Never combine a "*"
# wildcard with credentials — that is disabled by the browser and is unsafe.
# Credentials are only allowed when a concrete origin allowlist is configured.
_cors_origins = get_settings().api.cors_origin_list
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=bool(_cors_origins),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Multi-tenant in-memory store: one inspector per client_id so no client's
# uploaded scan data is ever visible on another client's requests.
_inspectors: dict[str, ThreatInspector] = {}


def get_inspector(client_id: str) -> ThreatInspector:
    """Return the inspector scoped to a client_id, creating it on first use."""
    client_id = (client_id or "").strip()
    if not client_id:
        raise HTTPException(status_code=400, detail="client_id is required")
    if client_id not in _inspectors:
        _inspectors[client_id] = ThreatInspector()
    return _inspectors[client_id]


# White-label mapping: never expose the underlying detection tool/format name on
# a client-visible surface. Internal scanner_type -> Iron City branded category.
_SOURCE_LABELS = {
    "qualys": "Vulnerability Assessment",
    "nessus": "Vulnerability Assessment",
    "zap": "Web Application Scan",
    "nmap": "Network Scan",
}


def _whitelabel_source(scanner_type: str) -> str:
    """Map an internal scanner_type to a client-safe source label."""
    return _SOURCE_LABELS.get((scanner_type or "").lower(), "Security Assessment")


class AnalyzeRequest(BaseModel):
    """Request model for analysis."""
    client_id: str
    client_name: str | None = "Assessment"
    project_name: str | None = None
    include_remediation: bool = True
    include_compliance: bool = True


class ReportRequest(BaseModel):
    """Request model for report generation."""
    client_id: str
    format: str = "html"
    client_name: str | None = "Assessment"
    project_name: str | None = None
    include_remediation: bool = True
    include_compliance: bool = True


@app.get("/")
async def root():
    """API root - health check."""
    return {
        "name": "Iron City Threat Inspector",
        "version": __version__,
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/api/v1/formats")
async def get_supported_formats():
    """Get list of supported scan file formats."""
    return {
        "formats": SUPPORTED_FORMATS,
        "count": len(SUPPORTED_FORMATS),
    }


@app.post("/api/v1/scans/upload")
async def upload_scan(
    client_id: str = Query(..., description="Client identifier for multi-tenant isolation"),
    file: UploadFile = File(...),
    scanner_type: str | None = Query(None, description="Scan format hint (auto-detected if omitted)"),
):
    """
    Upload and parse a vulnerability scan file.

    Returns parsed vulnerabilities and summary statistics.
    """
    inspector = get_inspector(client_id)

    # Validate file extension
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in SUPPORTED_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format: {suffix}. Supported: {list(SUPPORTED_FORMATS.keys())}"
        )

    # Save to temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        # Parse the file
        result = inspector.load_file(tmp_path, scanner_type)

        return {
            "filename": file.filename,
            "source": _whitelabel_source(result.scanner_type),
            "vulnerabilities_found": result.total_count,
            "severity_breakdown": result.severity_counts,
            "errors": result.errors,
            "warnings": result.warnings,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        tmp_path.unlink(missing_ok=True)


@app.post("/api/v1/analyze")
async def analyze_vulnerabilities(request: AnalyzeRequest):
    """
    Analyze all loaded vulnerabilities.

    Performs deduplication, enriches with remediation guidance,
    and maps to compliance frameworks.
    """
    inspector = get_inspector(request.client_id)
    if not inspector._vulnerabilities:
        raise HTTPException(
            status_code=400,
            detail="No vulnerabilities loaded. Upload scan files first."
        )

    summary = inspector.analyze(
        deduplicate=True,
        enrich_remediation=request.include_remediation,
        map_compliance=request.include_compliance,
    )

    return {
        "status": "analysis_complete",
        "summary": summary,
    }


@app.get("/api/v1/vulnerabilities")
async def get_vulnerabilities(
    client_id: str = Query(..., description="Client identifier for multi-tenant isolation"),
    severity: str | None = Query(None, description="Filter by severity"),
    asset: str | None = Query(None, description="Filter by asset"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
    offset: int = Query(0, ge=0, description="Results offset"),
):
    """
    Get parsed vulnerabilities with optional filtering.
    """
    inspector = get_inspector(client_id)
    vulns = inspector.get_vulnerabilities(
        severity=severity,
        asset=asset,
        limit=limit + offset,
    )

    # Apply offset
    vulns = vulns[offset:offset + limit]

    return {
        "total": len(inspector._vulnerabilities),
        "returned": len(vulns),
        "offset": offset,
        "limit": limit,
        "vulnerabilities": [v.to_dict() for v in vulns],
    }


@app.get("/api/v1/summary")
async def get_summary(
    client_id: str = Query(..., description="Client identifier for multi-tenant isolation"),
):
    """Get analysis summary statistics."""
    return get_inspector(client_id).get_summary()


@app.post("/api/v1/reports/generate")
async def generate_report(request: ReportRequest):
    """
    Generate a vulnerability report.

    Returns the report file for download.
    """
    inspector = get_inspector(request.client_id)
    if not inspector._vulnerabilities:
        raise HTTPException(
            status_code=400,
            detail="No vulnerabilities loaded. Upload scan files first."
        )

    # Ensure analysis is complete
    if not inspector._analysis_complete:
        inspector.analyze(
            enrich_remediation=request.include_remediation,
            map_compliance=request.include_compliance,
        )

    # Generate to temp file
    with tempfile.TemporaryDirectory() as tmp_dir:
        report_name = f"vulnerability_report.{request.format}"
        report_path = Path(tmp_dir) / report_name

        try:
            inspector.generate_report(
                output_path=report_path,
                format=request.format,
                client_name=request.client_name,
                project_name=request.project_name,
                include_remediation=request.include_remediation,
                include_compliance=request.include_compliance,
            )

            # Determine media type
            media_types = {
                "html": "text/html",
                "json": "application/json",
                "csv": "text/csv",
                "pdf": "application/pdf",
            }

            return FileResponse(
                path=report_path,
                filename=report_name,
                media_type=media_types.get(request.format, "application/octet-stream"),
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/v1/clear")
async def clear_data(
    client_id: str = Query(..., description="Client identifier for multi-tenant isolation"),
):
    """Clear loaded vulnerability data for a single client."""
    get_inspector(client_id).clear()
    return {"status": "cleared", "message": f"Data cleared for client {client_id}"}


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "version": __version__,
        "clients_loaded": len(_inspectors),
    }
