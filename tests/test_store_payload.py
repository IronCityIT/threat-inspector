"""The payload builder decides what a client is finally shown about their scan.

It used to be an inline heredoc in _consensus-store.yml, untestable and only
exercised in live runs. The case that matters most: a scan where every module
failed produces the same empty findings list as a genuinely clean scan, and
storing a flat "completed" for both tells a client their estate is fine when
nothing was actually checked.
"""

from __future__ import annotations

import json

import build_store_payload as bsp
import pytest

META = {
    "scan_type": "modular_scan",
    "scan_id": "ti-123",
    "client_id": "acme",
    "client_name": "Acme Corp",
    "target": "example.com",
    "consensus_status": "success",
}


def scan(**overrides):
    base = {
        "client": "acme",
        "scan_id": "ti-123",
        "modules_run": ["port_scan"],
        "target_count": 1,
        "status": "ok",
        "findings": [],
        "errors": [],
        "rejected_targets": [],
        "stats": {"module_runs": 1, "module_runs_failed": 0},
    }
    base.update(overrides)
    return base


# ---- status is not flattened -------------------------------------------


def test_a_clean_scan_stores_as_completed():
    payload = bsp.build_payload(scan(status="ok"), META)
    assert payload["status"] == "completed"
    assert payload["scan_status"] == "ok"
    assert "error" not in payload


def test_a_scan_where_everything_failed_stores_as_failed():
    """Same empty findings list as a clean scan — must not read as completed."""
    doc = scan(status="failed", errors=[{"module": "port_scan", "error": "RuntimeError: boom"}])
    payload = bsp.build_payload(doc, META)
    assert payload["status"] == "failed"
    assert payload["scan_status"] == "failed"
    assert payload["error"]["module_errors"] == doc["errors"]


def test_a_partial_scan_stores_as_completed_but_says_so():
    """Real findings exist, so the record is completed — degraded, not lost."""
    doc = scan(
        status="partial",
        findings=[{"severity": "high", "title": "x"}],
        errors=[{"module": "tls_cert_check", "error": "TimeoutError"}],
    )
    payload = bsp.build_payload(doc, META)
    assert payload["status"] == "completed"
    assert payload["scan_status"] == "partial"
    assert payload["diagnostics"]["module_error_count"] == 1


def test_a_dry_run_is_not_recorded_as_a_failure():
    payload = bsp.build_payload(scan(status="dry_run"), META)
    assert payload["status"] == "completed"
    assert payload["scan_status"] == "dry_run"


# ---- summary ------------------------------------------------------------


def test_summary_counts_by_severity():
    doc = scan(
        findings=[
            {"severity": "high"},
            {"severity": "high"},
            {"severity": "low"},
            {"severity": "info"},
        ]
    )
    summary = bsp.build_payload(doc, META)["summary"]
    assert summary == {"total": 4, "high": 2, "low": 1, "info": 1}


def test_summary_defaults_an_absent_severity_to_info():
    assert bsp.summarize([{"title": "no severity"}]) == {"total": 1, "info": 1}


def test_summary_is_case_insensitive():
    assert bsp.summarize([{"severity": "HIGH"}])["high"] == 1


# ---- diagnostics --------------------------------------------------------


def test_diagnostics_carry_rejected_targets_and_file_failures():
    doc = scan(
        rejected_targets=["'10.0.0.0/99' is not a valid network range"],
        files_failed=[{"file": "a.xml", "errors": ["XML parse error"]}],
    )
    diag = bsp.build_payload(doc, META)["diagnostics"]
    assert diag["rejected_targets"] == doc["rejected_targets"]
    assert diag["files_failed"] == doc["files_failed"]


def test_error_lists_are_capped_but_the_true_count_survives():
    """A /16 x 8 modules run must not build a document Firestore will reject."""
    doc = scan(status="failed", errors=[{"module": f"m{i}"} for i in range(500)])
    diag = bsp.build_payload(doc, META)["diagnostics"]
    assert len(diag["module_errors"]) == bsp.MAX_ERRORS_ON_RECORD
    assert diag["module_error_count"] == 500


def test_payload_is_json_serializable():
    json.dumps(bsp.build_payload(scan(), META))


# ---- missing / malformed artifact ---------------------------------------


def test_a_missing_findings_file_yields_a_failed_record_not_a_crash(tmp_path):
    doc = bsp.load_scan(bsp.find_findings(tmp_path))
    payload = bsp.build_payload(doc, META)
    assert payload["status"] == "failed"
    assert payload["findings"] == []


def test_findings_are_located_inside_an_artifact_directory(tmp_path):
    nested = tmp_path / "ti-findings-1"
    nested.mkdir()
    (nested / "findings.json").write_text(json.dumps(scan(status="ok")))
    found = bsp.find_findings(tmp_path)
    assert found is not None
    assert bsp.load_scan(found)["status"] == "ok"


def test_cli_writes_a_payload(tmp_path, capsys):
    src = tmp_path / "findings.json"
    src.write_text(json.dumps(scan(findings=[{"severity": "critical"}])))
    out = tmp_path / "payload.json"
    code = bsp.main(
        [
            "--findings",
            str(src),
            "--out",
            str(out),
            "--scan-type",
            "modular_scan",
            "--scan-id",
            "ti-1",
            "--client-id",
            "acme",
            "--client-name",
            "Acme",
            "--target",
            "example.com",
        ]
    )
    assert code == 0
    written = json.loads(out.read_text())
    assert written["summary"]["critical"] == 1
    assert written["client_id"] == "acme"


@pytest.mark.parametrize("field", ["scan_type", "scan_id", "client_id", "client_name", "target"])
def test_every_required_field_reaches_the_record(field):
    assert bsp.build_payload(scan(), META)[field] == META[field]
