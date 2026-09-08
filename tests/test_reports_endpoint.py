"""Downloading a report, and the formats we claim to produce.

Two defects, both found by simply calling the endpoint. It had **no test at
all**, and `src/threat_inspector/cli.py` — the other caller of the same report
code — sat at 0% coverage.

**1. The report download endpoint could not deliver a report.** The handler
built the file inside `with tempfile.TemporaryDirectory()` and returned a
`FileResponse` from within that block. `FileResponse` streams the file *after*
the handler returns, and the context manager removes the directory the moment it
does. Every request died:

    format=html  -> RuntimeError: File at path /tmp/.../vulnerability_report.html does not exist
    format=json  -> RuntimeError: File at path /tmp/.../vulnerability_report.json does not exist
    format=csv   -> RuntimeError: File at path /tmp/.../vulnerability_report.csv  does not exist

Not one format worked. The directory is now created unmanaged and removed by a
background task that runs once the body has been sent.

**2. `pdf` was advertised in three places and implemented in none.** The CLI
offered it as a `--format` choice, this API mapped a media type for it, and the
docstring listed it — while `generate_report` has no `pdf` branch. The API
answered **500** with the raw exception text; the CLI printed a failure and
still exited **0**. `REPORT_FORMATS` is now the single source of truth, and an
unsupported format is a **400**, because asking for one is a bad request rather
than a server fault.
"""

from __future__ import annotations

import glob
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "examples" / "file-ingest-selftest" / "nessus-export.csv"

TOKENS = "tok-acme:acme,tok-globex:globex"
ACME = {"Authorization": "Bearer tok-acme"}
GLOBEX = {"Authorization": "Bearer tok-globex"}


@pytest.fixture
def client(monkeypatch):
    """A TestClient over a freshly imported app with one scan already loaded."""
    monkeypatch.setenv("TI_API_TOKENS", TOKENS)
    monkeypatch.delenv("TI_ALLOW_UNAUTHENTICATED", raising=False)

    for name in [m for m in list(sys.modules) if m.startswith("threat_inspector")]:
        del sys.modules[name]
    sys.path.insert(0, str(ROOT / "src"))
    from threat_inspector.api.main import app

    api = TestClient(app)
    api.post(
        "/api/v1/scans/upload",
        headers=ACME,
        files={"file": (FIXTURE.name, FIXTURE.read_bytes(), "text/csv")},
    )
    return api


def generate(api, fmt: str, headers=None):
    return api.post(
        "/api/v1/reports/generate",
        headers=headers or ACME,
        json={
            "client_id": "acme",
            "format": fmt,
            "include_remediation": False,
            "include_compliance": False,
        },
    )


# ---------------------------------------------------------------------------
# The endpoint can actually deliver a report
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["html", "json", "csv"])
def test_a_report_is_delivered_with_a_body(client, fmt):
    """The regression. Every one of these raised before the fix."""
    response = generate(client, fmt)
    assert response.status_code == 200
    assert len(response.content) > 0, "a report with no body is not a report"


@pytest.mark.parametrize(
    ("fmt", "media_type"),
    [("html", "text/html"), ("json", "application/json"), ("csv", "text/csv")],
)
def test_each_format_is_served_with_its_media_type(client, fmt, media_type):
    assert media_type in generate(client, fmt).headers["content-type"]


def test_the_report_is_offered_as_a_download(client):
    disposition = generate(client, "html").headers.get("content-disposition", "")
    assert "vulnerability_report.html" in disposition


def test_the_html_report_carries_the_findings(client):
    body = generate(client, "html").text
    assert "Medium Strength Cipher" in body or "Vulnerability" in body


def test_the_json_report_is_valid_json(client):
    import json

    parsed = json.loads(generate(client, "json").content)
    assert parsed, "the JSON report must not be empty"


def test_the_temporary_directory_is_cleaned_up_after_the_response(client):
    """The fix must not trade a broken download for a leaked directory."""
    before = set(glob.glob("/tmp/ti-report-*"))
    generate(client, "json")
    assert set(glob.glob("/tmp/ti-report-*")) - before == set()


def test_repeated_downloads_do_not_accumulate_directories(client):
    before = set(glob.glob("/tmp/ti-report-*"))
    for _ in range(3):
        generate(client, "csv")
    assert set(glob.glob("/tmp/ti-report-*")) - before == set()


# ---------------------------------------------------------------------------
# A format we cannot produce
# ---------------------------------------------------------------------------


def test_an_unimplemented_format_is_a_400_not_a_500(client):
    """`pdf` was advertised by this API and implemented nowhere. Asking for it
    is a bad request, not a server fault."""
    response = generate(client, "pdf")
    assert response.status_code == 400
    assert "unsupported_format" in response.json()["detail"]


def test_the_refusal_names_the_formats_that_do_work(client):
    detail = generate(client, "pdf").json()["detail"]
    for fmt in ("html", "json", "csv"):
        assert fmt in detail


def test_an_unknown_format_is_refused(client):
    assert generate(client, "docx").status_code == 400


def test_a_refused_format_leaves_no_temporary_directory(client):
    before = set(glob.glob("/tmp/ti-report-*"))
    generate(client, "pdf")
    assert set(glob.glob("/tmp/ti-report-*")) - before == set()


# ---------------------------------------------------------------------------
# Tenancy and preconditions still hold
# ---------------------------------------------------------------------------


def test_generating_a_report_requires_a_credential(client):
    response = client.post("/api/v1/reports/generate", json={"client_id": "acme", "format": "html"})
    assert response.status_code == 401


def test_a_report_cannot_be_generated_for_another_tenant(client):
    """The body names acme; the token is globex's."""
    assert generate(client, "html", headers=GLOBEX).status_code == 403


def test_a_tenant_with_nothing_loaded_gets_a_clear_400(client):
    """Globex uploaded nothing, so there is nothing to report on."""
    response = client.post(
        "/api/v1/reports/generate",
        headers=GLOBEX,
        json={"client_id": "globex", "format": "html"},
    )
    assert response.status_code == 400
    assert (
        "Upload" in response.json()["detail"] or "No vulnerabilities" in (response.json()["detail"])
    )


# ---------------------------------------------------------------------------
# One source of truth for what can be produced
# ---------------------------------------------------------------------------


def test_the_advertised_formats_are_the_ones_the_library_implements():
    """The whole point of REPORT_FORMATS: the CLI's choices, the API's
    validation and generate_report's branches cannot drift apart again."""
    sys.path.insert(0, str(ROOT / "src"))
    from threat_inspector.reports import REPORT_FORMATS

    assert REPORT_FORMATS == ("html", "json", "csv")
    assert "pdf" not in REPORT_FORMATS


def test_the_cli_offers_exactly_those_formats():
    sys.path.insert(0, str(ROOT / "src"))
    from threat_inspector.cli import analyze
    from threat_inspector.reports import REPORT_FORMATS

    choice = next(p for p in analyze.params if p.name == "format")
    assert tuple(choice.type.choices) == REPORT_FORMATS


def test_generate_report_names_the_supported_formats_when_it_refuses():
    sys.path.insert(0, str(ROOT / "src"))
    from threat_inspector.core import ThreatInspector

    inspector = ThreatInspector()
    with pytest.raises(ValueError) as excinfo:
        inspector.generate_report(output_path=Path("/tmp/x.pdf"), format="pdf")
    message = str(excinfo.value)
    assert "pdf" in message
    assert "html" in message
