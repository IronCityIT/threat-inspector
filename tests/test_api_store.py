"""Reading stored scan results over the API, and not reading anyone else's.

`_inspectors` in api/main.py is a process-local dict: it does not survive a
restart and does not work behind more than one replica. These routes are the
read side of the self-hosted store that replaces it.

The tenancy question is the same one `firestore.rules` answered, asked at a
different layer. There the boundary was declarative and outside the
application; here it is two things working together — the tenant comes from the
caller's credential (`current_tenant`), and every query goes through
`ScanRepository`, which has no unscoped entry point. Both halves are exercised
below through the real ASGI app: real routing, real dependency resolution, real
request/response cycle.

The store is optional at runtime. With no `DATABASE_URL` these routes answer
503 and the rest of the API keeps working, because the API must not fail to
start merely because the store is not configured yet.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("sqlalchemy", reason="sqlalchemy is required for the storage suite")
pytest.importorskip("alembic", reason="alembic is declared in requirements.txt")

from alembic import command  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from tests.test_storage_migrations import alembic_config  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

TOKENS = "tok-acme:acme,tok-globex:globex"
ACME = {"Authorization": "Bearer tok-acme"}
GLOBEX = {"Authorization": "Bearer tok-globex"}

# Both tenants deliberately use the SAME scan id.
SCAN_ID = "shared-scan"


def scan_payload(client_id: str, title: str, severity: str = "critical") -> dict:
    return {
        "client_id": client_id,
        "client_name": client_id.title(),
        "scan_id": SCAN_ID,
        "scan_type": "network",
        "target": "example.selftest.invalid",
        "status": "completed",
        "scan_status": "degraded",
        "summary": {"total": 2},
        "consensus": {"status": "success"},
        "diagnostics": {"modules_run": ["tls_cert_check"]},
        "findings": [
            {
                "module": "tls_cert_check",
                "target": "example.selftest.invalid",
                "severity": severity,
                "title": title,
                "evidence": {"verification_error": "certificate has expired"},
            },
            {
                "module": "header_security_check",
                "severity": "low",
                "title": f"{client_id} minor finding",
            },
        ],
    }


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A TestClient over a freshly imported app, backed by a migrated store."""
    dsn = f"sqlite:///{tmp_path / 'store.db'}"
    monkeypatch.setenv("DATABASE_URL", dsn)
    monkeypatch.setenv("TI_API_TOKENS", TOKENS)
    monkeypatch.delenv("TI_ALLOW_UNAUTHENTICATED", raising=False)

    command.upgrade(alembic_config(dsn), "head")

    for name in [m for m in list(sys.modules) if m.startswith("threat_inspector")]:
        del sys.modules[name]
    sys.path.insert(0, str(ROOT / "src"))

    from threat_inspector.storage import ScanRepository

    engine = create_engine(dsn)
    with Session(engine) as session:
        repository = ScanRepository(session)
        repository.store_scan(scan_payload("acme", "ACME finding"))
        repository.store_scan(scan_payload("globex", "GLOBEX finding"))
        session.commit()
    engine.dispose()

    from threat_inspector.api.main import app

    return TestClient(app)


@pytest.fixture
def unconfigured_client(monkeypatch):
    """The app with no store configured at all."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("TI_API_TOKENS", TOKENS)
    monkeypatch.delenv("TI_ALLOW_UNAUTHENTICATED", raising=False)

    for name in [m for m in list(sys.modules) if m.startswith("threat_inspector")]:
        del sys.modules[name]
    sys.path.insert(0, str(ROOT / "src"))
    from threat_inspector.api.main import app

    return TestClient(app)


ROUTES = [
    "/api/v1/store/scans",
    f"/api/v1/store/scans/{SCAN_ID}",
    f"/api/v1/store/scans/{SCAN_ID}/findings",
    "/api/v1/store/findings",
    "/api/v1/store/summary",
]


# ---------------------------------------------------------------------------
# A tenant reads its own
# ---------------------------------------------------------------------------


def test_a_tenant_lists_its_own_scans(client):
    body = client.get("/api/v1/store/scans", headers=ACME).json()
    assert body["client_id"] == "acme"
    assert [s["scan_id"] for s in body["scans"]] == [SCAN_ID]


def test_a_tenant_reads_its_own_scan(client):
    body = client.get(f"/api/v1/store/scans/{SCAN_ID}", headers=ACME).json()
    assert body["client_id"] == "acme"
    assert body["scan_type"] == "network"


def test_a_tenant_reads_its_own_findings(client):
    titles = [
        f["title"] for f in client.get("/api/v1/store/findings", headers=ACME).json()["findings"]
    ]
    assert "ACME finding" in titles


def test_findings_come_back_worst_first(client):
    findings = client.get("/api/v1/store/findings", headers=ACME).json()["findings"]
    assert [f["severity"] for f in findings] == ["critical", "low"]


def test_a_scans_findings_are_readable(client):
    body = client.get(f"/api/v1/store/scans/{SCAN_ID}/findings", headers=ACME).json()
    assert body["count"] == 2
    assert body["scan_id"] == SCAN_ID


def test_findings_can_be_filtered_by_severity(client):
    body = client.get("/api/v1/store/findings?severity=critical", headers=ACME).json()
    assert body["count"] == 1
    assert body["findings"][0]["severity"] == "critical"


def test_the_summary_reports_every_band_including_zeros(client):
    """A missing key renders as "—" and a zero renders as 0. Those say
    different things to whoever reads them."""
    counts = client.get("/api/v1/store/summary", headers=ACME).json()["severity_counts"]
    assert set(counts) == {"critical", "high", "medium", "low", "info"}
    assert counts["critical"] == 1
    assert counts["high"] == 0


def test_the_summary_can_be_scoped_to_one_scan(client):
    counts = client.get(f"/api/v1/store/summary?scan_id={SCAN_ID}", headers=ACME).json()[
        "severity_counts"
    ]
    assert counts["critical"] == 1


def test_the_scans_own_health_is_reported_separately_from_the_run_status(client):
    """An empty findings list means "nothing found" OR "some capability never
    ran", and a client must not be shown the first when it was the second."""
    body = client.get(f"/api/v1/store/scans/{SCAN_ID}", headers=ACME).json()
    assert body["status"] == "completed"
    assert body["scan_status"] == "degraded"


def test_evidence_survives_to_the_response(client):
    findings = client.get("/api/v1/store/findings", headers=ACME).json()["findings"]
    critical = next(f for f in findings if f["severity"] == "critical")
    assert critical["evidence"]["verification_error"] == "certificate has expired"


# ---------------------------------------------------------------------------
# ...and nobody else's
# ---------------------------------------------------------------------------


def test_a_tenant_never_sees_another_tenants_findings(client):
    titles = [
        f["title"] for f in client.get("/api/v1/store/findings", headers=ACME).json()["findings"]
    ]
    assert "GLOBEX finding" not in titles


def test_the_isolation_holds_in_both_directions(client):
    acme = {
        f["title"] for f in client.get("/api/v1/store/findings", headers=ACME).json()["findings"]
    }
    globex = {
        f["title"] for f in client.get("/api/v1/store/findings", headers=GLOBEX).json()["findings"]
    }
    assert "ACME finding" in acme and "ACME finding" not in globex
    assert "GLOBEX finding" in globex and "GLOBEX finding" not in acme


def test_a_shared_scan_id_resolves_to_the_callers_own_scan(client):
    """Both tenants stored a scan under the same id on purpose. This is the
    case a scan-id-only lookup gets wrong."""
    assert client.get(f"/api/v1/store/scans/{SCAN_ID}", headers=ACME).json()["client_id"] == "acme"
    assert (
        client.get(f"/api/v1/store/scans/{SCAN_ID}", headers=GLOBEX).json()["client_id"] == "globex"
    )


def test_each_tenants_scan_findings_are_its_own(client):
    acme = client.get(f"/api/v1/store/scans/{SCAN_ID}/findings", headers=ACME).json()
    globex = client.get(f"/api/v1/store/scans/{SCAN_ID}/findings", headers=GLOBEX).json()
    assert "ACME finding" in {f["title"] for f in acme["findings"]}
    assert "ACME finding" not in {f["title"] for f in globex["findings"]}


def test_naming_a_client_id_in_the_query_string_does_not_change_the_tenant(client):
    """The tenant comes from the credential. A request that also names one must
    name its OWN, or it is refused — a stolen token still cannot cross tenants."""
    assert client.get("/api/v1/store/findings?client_id=globex", headers=ACME).status_code == 403


def test_a_scan_that_does_not_exist_is_a_404(client):
    assert client.get("/api/v1/store/scans/no-such-scan", headers=ACME).status_code == 404


def test_findings_for_a_scan_that_does_not_exist_are_a_404(client):
    assert client.get("/api/v1/store/scans/no-such-scan/findings", headers=ACME).status_code == 404


# ---------------------------------------------------------------------------
# White-label: an underlying scanner's name must not cross this boundary
# ---------------------------------------------------------------------------


def test_the_response_never_names_the_scanner_that_was_missing(tmp_path, monkeypatch):
    """`modules_skipped` entries carry `missing: ["nuclei"]`.

    That is a tool identity, and this response is consumed by the client-facing
    dashboard. The COUNT is what a client needs — "2 checks did not run" — not
    which scanner was absent, which is an operational detail about our estate.
    """
    dsn = f"sqlite:///{tmp_path / 'store.db'}"
    monkeypatch.setenv("DATABASE_URL", dsn)
    monkeypatch.setenv("TI_API_TOKENS", TOKENS)
    monkeypatch.delenv("TI_ALLOW_UNAUTHENTICATED", raising=False)
    command.upgrade(alembic_config(dsn), "head")

    for name in [m for m in list(sys.modules) if m.startswith("threat_inspector")]:
        del sys.modules[name]
    sys.path.insert(0, str(ROOT / "src"))

    from threat_inspector.storage import ScanRepository

    engine = create_engine(dsn)
    with Session(engine) as session:
        payload = scan_payload("acme", "ACME finding")
        payload["diagnostics"] = {
            "modules_run": ["tls_cert_check"],
            "modules_skipped": [{"module": "web_vuln_scan", "missing": ["nuclei"]}],
            "modules_skipped_count": 1,
        }
        ScanRepository(session).store_scan(payload)
        session.commit()
    engine.dispose()

    from threat_inspector.api.main import app

    api = TestClient(app)
    body = api.get(f"/api/v1/store/scans/{SCAN_ID}", headers=ACME).text.lower()
    for tool in ("nuclei", "subfinder", "nmap"):
        assert tool not in body, f"an underlying tool name reached the API response: {tool}"

    diagnostics = api.get(f"/api/v1/store/scans/{SCAN_ID}", headers=ACME).json()["diagnostics"]
    assert diagnostics["modules_skipped_count"] == 1, "the count a client needs is kept"
    assert diagnostics["modules_skipped"][0]["module"] == "web_vuln_scan", (
        "the Iron City capability id is kept"
    )


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("route", ROUTES)
def test_every_route_requires_a_credential(client, route):
    assert client.get(route).status_code == 401


@pytest.mark.parametrize("route", ROUTES)
def test_every_route_rejects_an_unrecognised_token(client, route):
    assert client.get(route, headers={"Authorization": "Bearer nope"}).status_code == 401


def test_a_non_bearer_authorization_header_is_rejected(client):
    assert client.get("/api/v1/store/scans", headers={"Authorization": "tok-acme"}).status_code == (
        401
    )


# ---------------------------------------------------------------------------
# The store is optional
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("route", ROUTES)
def test_an_unconfigured_store_answers_503_not_500(unconfigured_client, route):
    """The store is not broken, it is not configured. A caller can tell
    "come back later" from "something is wrong"."""
    response = unconfigured_client.get(route, headers=ACME)
    assert response.status_code == 503
    assert "store_not_configured" in response.json()["detail"]


def test_the_rest_of_the_api_still_works_without_a_store(unconfigured_client):
    """The API must not fail to start just because the store is unconfigured."""
    assert unconfigured_client.get("/health").status_code == 200
    assert unconfigured_client.get("/api/v1/summary", headers=ACME).status_code == 200


def test_an_unconfigured_store_still_requires_a_credential_first(unconfigured_client):
    """503 must not become a way to probe the API without a token."""
    assert unconfigured_client.get("/api/v1/store/scans").status_code == 401
