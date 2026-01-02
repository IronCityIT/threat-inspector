"""
FastAPI REST API for Threat Inspector.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional
import tempfile
import shutil

from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from threat_inspector import ThreatInspector, __version__
from threat_inspector.parsers import SUPPORTED_FORMATS

app = FastAPI(
    title="Iron City Threat Inspector API",
    description="Advanced Vulnerability Assessment & Remediation Platform",
    version=__version__,
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global inspector instance (for simple deployments)
# For production, use proper session management
_inspector = ThreatInspector()


class AnalyzeRequest(BaseModel):
    """Request model for analysis."""
    client_name: Optional[str] = "Assessment"
    project_name: Optional[str] = None
    include_remediation: bool = True
    include_compliance: bool = True


class ReportRequest(BaseModel):
    """Request model for report generation."""
    format: str = "html"
    client_name: Optional[str] = "Assessment"
    project_name: Optional[str] = None
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
    file: UploadFile = File(...),
    scanner_type: Optional[str] = Query(None, description="Scanner type hint (qualys, zap, nmap, nessus)"),
):
    """
    Upload and parse a vulnerability scan file.
    
    Returns parsed vulnerabilities and summary statistics.
    """
    # Validate file extension
    suffix = Path(file.filename).suffix.lower()
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
        result = _inspector.load_file(tmp_path, scanner_type)
        
        return {
            "filename": file.filename,
            "scanner_type": result.scanner_type,
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
    if not _inspector._vulnerabilities:
        raise HTTPException(
            status_code=400,
            detail="No vulnerabilities loaded. Upload scan files first."
        )
    
    summary = _inspector.analyze(
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
    severity: Optional[str] = Query(None, description="Filter by severity"),
    asset: Optional[str] = Query(None, description="Filter by asset"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum results"),
    offset: int = Query(0, ge=0, description="Results offset"),
):
    """
    Get parsed vulnerabilities with optional filtering.
    """
    vulns = _inspector.get_vulnerabilities(
        severity=severity,
        asset=asset,
        limit=limit + offset,
    )
    
    # Apply offset
    vulns = vulns[offset:offset + limit]
    
    return {
        "total": len(_inspector._vulnerabilities),
        "returned": len(vulns),
        "offset": offset,
        "limit": limit,
        "vulnerabilities": [v.to_dict() for v in vulns],
    }


@app.get("/api/v1/summary")
async def get_summary():
    """Get analysis summary statistics."""
    return _inspector.get_summary()


@app.post("/api/v1/reports/generate")
async def generate_report(request: ReportRequest):
    """
    Generate a vulnerability report.
    
    Returns the report file for download.
    """
    if not _inspector._vulnerabilities:
        raise HTTPException(
            status_code=400,
            detail="No vulnerabilities loaded. Upload scan files first."
        )
    
    # Ensure analysis is complete
    if not _inspector._analysis_complete:
        _inspector.analyze(
            enrich_remediation=request.include_remediation,
            map_compliance=request.include_compliance,
        )
    
    # Generate to temp file
    with tempfile.TemporaryDirectory() as tmp_dir:
        report_name = f"vulnerability_report.{request.format}"
        report_path = Path(tmp_dir) / report_name
        
        try:
            _inspector.generate_report(
                output_path=report_path,
                format=request.format,
                client_name=request.client_name,
                project_name=request.project_name,
                include_remediation=request.include_remediation,
                include_compliance=request.include_compliance,
            )
            
            # Read the file content
            with open(report_path, "rb") as f:
                content = f.read()
            
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
async def clear_data():
    """Clear all loaded vulnerability data."""
    _inspector.clear()
    return {"status": "cleared", "message": "All data cleared"}


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "version": __version__,
        "vulnerabilities_loaded": len(_inspector._vulnerabilities),
    }
