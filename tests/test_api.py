"""The local REST API: authentication and tenant isolation.

This API ships in the repo's Dockerfile, bound to 0.0.0.0:8000, and
docker-compose publishes that port. It holds one uploaded scan set per
client_id.

Before api/auth.py existed, client_id was a plain query parameter and no
credential appeared anywhere in the request. The partitioning worked; the
identity did not. Demonstrated against the running app:

    POST /api/v1/scans/upload?client_id=acme     -> 200, 8 vulnerabilities
    GET  /api/v1/vulnerabilities?client_id=acme  -> 200, all 8 returned

...with no token, header or session at any point.

These tests drive the real ASGI app through Starlette's TestClient — real
routing, real dependency resolution, real request/response cycle.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "examples" / "file-ingest-selftest" / "nessus-export.csv"

TOKENS = "tok-acme:acme,tok-globex:globex"
ACME = {"Authorization": "Bearer tok-acme"}
GLOBEX = {"Authorization": "Bearer tok-globex"}


def _build_client(monkeypatch, tokens: str | None, allow_anon: bool = False) -> TestClient:
    """A TestClient over a freshly imported app, so module state is not shared."""
    if tokens is None:
        monkeypatch.delenv("TI_API_TOKENS", raising=False)
    else:
        monkeypatch.setenv("TI_API_TOKENS", tokens)
    if allow_anon:
        monkeypatch.setenv("TI_ALLOW_UNAUTHENTICATED", "true")
    else:
        monkeypatch.delenv("TI_ALLOW_UNAUTHENTICATED", raising=False)

    for name in [m for m in list(sys.modules) if m.startswith("threat_inspector")]:
        del sys.modules[name]
    sys.path.insert(0, str(ROOT / "src"))
    from threat_inspector.api.main import app

    return TestClient(app)


@pytest.fixture
def client(monkeypatch) -> TestClient:
    return _build_client(monkeypatch, TOKENS)


def upload_as(client: TestClient, headers: dict) -> dict:
    with FIXTURE.open("rb") as fh:
        r = client.post(
            "/api/v1/scans/upload",
            headers=headers,
            files={"file": ("nessus-export.csv", fh.read(), "text/csv")},
        )
    assert r.status_code == 200, r.text
    return r.json()


# ---- secure by default --------------------------------------------------


def test_unconfigured_api_refuses_to_serve_tenant_data(monkeypatch):
    client = _build_client(monkeypatch, None)
    r = client.get("/api/v1/vulnerabilities")
    assert r.status_code == 503
    assert "api_not_configured" in r.json()["detail"]


def test_health_still_answers_when_unconfigured(monkeypatch):
    """A liveness probe must not need a tenant credential, or the container
    never reports healthy and orchestration restarts it forever."""
    client = _build_client(monkeypatch, None)
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200


def test_local_dev_override_is_explicit(monkeypatch):
    client = _build_client(monkeypatch, None, allow_anon=True)
    assert client.get("/api/v1/vulnerabilities").status_code == 200


# ---- authentication -----------------------------------------------------


def test_no_credential_is_refused(client):
    r = client.get("/api/v1/vulnerabilities?client_id=acme")
    assert r.status_code == 401
    assert r.json()["detail"] == "missing_bearer_token"


def test_an_unrecognised_token_is_refused(client):
    r = client.get("/api/v1/vulnerabilities", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401
    assert r.json()["detail"] == "invalid_token"


@pytest.mark.parametrize(
    "header",
    ["tok-acme", "Basic tok-acme", "Bearer", "Bearer   ", "bearer-tok-acme", ""],
)
def test_malformed_authorization_headers_are_refused(client, header):
    r = client.get("/api/v1/vulnerabilities", headers={"Authorization": header})
    assert r.status_code == 401


def test_the_bearer_scheme_is_case_insensitive(client):
    r = client.get("/api/v1/vulnerabilities", headers={"Authorization": "bearer tok-acme"})
    assert r.status_code == 200


# ---- tenant isolation ---------------------------------------------------


def test_a_tenant_reads_its_own_uploaded_data(client):
    assert upload_as(client, ACME)["vulnerabilities_found"] == 8
    r = client.get("/api/v1/vulnerabilities", headers=ACME)
    assert r.status_code == 200
    assert len(r.json()["vulnerabilities"]) == 8


def test_another_tenant_sees_nothing_of_it(client):
    upload_as(client, ACME)
    r = client.get("/api/v1/vulnerabilities", headers=GLOBEX)
    assert r.status_code == 200
    assert r.json()["vulnerabilities"] == []
    assert r.json()["total"] == 0


def test_naming_another_tenant_in_the_query_is_refused(client):
    """The old hole: client_id was self-asserted, so naming a tenant was enough."""
    upload_as(client, ACME)
    r = client.get("/api/v1/vulnerabilities?client_id=acme", headers=GLOBEX)
    assert r.status_code == 403
    assert "does not match" in r.json()["detail"]


def test_naming_another_tenant_in_the_body_is_refused(client):
    upload_as(client, ACME)
    r = client.post("/api/v1/analyze", headers=GLOBEX, json={"client_id": "acme"})
    assert r.status_code == 403


def test_a_report_cannot_be_generated_for_another_tenant(client):
    upload_as(client, ACME)
    r = client.post("/api/v1/reports/generate", headers=GLOBEX, json={"client_id": "acme"})
    assert r.status_code == 403


def test_a_tenant_cannot_clear_another_tenants_data(client):
    """The destructive one. A cross-tenant clear would be data loss, not just
    disclosure."""
    upload_as(client, ACME)
    r = client.delete("/api/v1/clear?client_id=acme", headers=GLOBEX)
    assert r.status_code == 403
    still_there = client.get("/api/v1/vulnerabilities", headers=ACME)
    assert len(still_there.json()["vulnerabilities"]) == 8


def test_naming_your_own_tenant_is_fine(client):
    upload_as(client, ACME)
    r = client.get("/api/v1/vulnerabilities?client_id=acme", headers=ACME)
    assert r.status_code == 200
    assert len(r.json()["vulnerabilities"]) == 8


def test_a_tenant_can_clear_its_own_data(client):
    upload_as(client, ACME)
    assert client.delete("/api/v1/clear", headers=ACME).status_code == 200
    assert client.get("/api/v1/vulnerabilities", headers=ACME).json()["vulnerabilities"] == []


# ---- white-label --------------------------------------------------------


TOOL_NAMES = ("nessus", "qualys", "nmap", "zap", "tenable", "burp", "openvas")


def test_the_upload_response_reports_a_branded_source_not_a_tool_name(client):
    """`source` is DERIVED by us from the detected scanner type, so it is ours to
    white-label and it must never carry the vendor's name.

    `filename` is deliberately excluded: it is the client's own upload echoed
    back so they can correlate the response with what they sent. The client
    already knows what they uploaded — the white-label rule is about not
    revealing which tools Iron City runs, not about redacting the client's
    own input.
    """
    body = upload_as(client, ACME)
    assert body["source"] == "Vulnerability Assessment"
    for tool in TOOL_NAMES:
        assert tool not in body["source"].lower()


def test_vulnerability_records_never_carry_a_tool_name_in_a_derived_field(client):
    upload_as(client, ACME)
    vulns = client.get("/api/v1/vulnerabilities", headers=ACME).json()["vulnerabilities"]
    assert vulns, "fixture should have produced findings"
    # Fields the product generates, as opposed to text lifted from the client's
    # own export (title/description come from their scanner and are their data).
    for v in vulns:
        for field in ("source", "scanner_severity"):
            value = str(v.get(field, "")).lower()
            for tool in TOOL_NAMES:
                assert tool not in value, f"{field} leaked {tool!r}"
