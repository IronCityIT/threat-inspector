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
    # `stored`/`truncated` ride alongside the counts so a client can tell a
    # complete finding list from a size-trimmed one.
    assert summary == {
        "total": 4,
        "high": 2,
        "low": 1,
        "info": 1,
        "stored": 4,
        "truncated": False,
    }


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


# ---- Firestore document size -------------------------------------------
# Firestore rejects any document over 1 MiB, and a rejected write loses the
# WHOLE scan rather than just the excess. At ~520 bytes per realistic finding
# that ceiling arrives at roughly 2,000 findings — well within reach of a /24
# sweep or a broad subdomain enumeration.


def big_finding(severity="info", i=0):
    return {
        "module": "web_vuln_scan",
        "target": f"https://app.selftest.invalid/p{i}",
        "severity": severity,
        "title": "Cross Site Scripting (Reflected)",
        "detail": "A synthetic description of roughly the length a real scanner emits. " * 3,
        "evidence": {"template": "xss", "matched_at": f"https://app.selftest.invalid/s?q={i}"},
    }


def test_a_large_scan_still_fits_in_a_firestore_document():
    doc = scan(findings=[big_finding(i=i) for i in range(20000)])
    payload = bsp.build_payload(doc, META)
    size = len(json.dumps(payload))
    assert size <= bsp.FIRESTORE_DOC_LIMIT, f"{size} bytes would be rejected"


def test_an_ordinary_scan_is_not_truncated():
    doc = scan(findings=[big_finding(i=i) for i in range(50)])
    payload = bsp.build_payload(doc, META)
    assert payload["summary"]["truncated"] is False
    assert len(payload["findings"]) == 50
    assert payload["summary"]["stored"] == 50


def test_truncation_is_declared_not_silent():
    doc = scan(findings=[big_finding(i=i) for i in range(20000)])
    payload = bsp.build_payload(doc, META)
    assert payload["summary"]["truncated"] is True
    assert payload["summary"]["stored"] < 20000
    trunc = payload["diagnostics"]["truncation"]
    assert trunc["findings_total"] == 20000
    assert trunc["findings_stored"] == payload["summary"]["stored"]
    assert trunc["reason"] == "document_size_limit"


def test_severity_counts_reflect_the_full_set_even_when_truncated():
    """The client's totals must stay true; only the browsable list gets shorter."""
    doc = scan(
        findings=[big_finding("critical", i) for i in range(40)]
        + [big_finding("info", i) for i in range(20000)]
    )
    payload = bsp.build_payload(doc, META)
    assert payload["summary"]["truncated"] is True
    assert payload["summary"]["total"] == 20040
    assert payload["summary"]["critical"] == 40
    assert payload["summary"]["info"] == 20000


def test_truncation_never_drops_the_most_severe_findings():
    """Dropping criticals to keep informational findings would be the worst
    possible failure mode for this product."""
    doc = scan(
        findings=[big_finding("info", i) for i in range(20000)]
        + [big_finding("critical", i) for i in range(40)]
        + [big_finding("high", i) for i in range(40)]
    )
    payload = bsp.build_payload(doc, META)
    kept = [f["severity"] for f in payload["findings"]]
    assert kept.count("critical") == 40, "criticals must survive truncation"
    assert kept.count("high") == 40, "highs must survive truncation"


def test_a_runaway_evidence_blob_cannot_eat_the_whole_budget():
    """One scanner echoing a whole response body should not cost every other
    finding its place in the document."""
    hog = big_finding("low", 0)
    hog["evidence"]["response"] = "A" * 500_000
    hog["detail"] = "B" * 500_000
    doc = scan(findings=[hog] + [big_finding("high", i) for i in range(100)])
    payload = bsp.build_payload(doc, META)
    assert payload["summary"]["truncated"] is False, "clamping should avoid truncation entirely"
    assert len(payload["findings"]) == 101, "every finding should still be stored"
    stored_hog = next(f for f in payload["findings"] if len(f["target"]) and f["severity"] == "low")
    assert len(stored_hog["detail"]) <= bsp.MAX_DETAIL_CHARS + 20
    assert len(stored_hog["evidence"]["response"]) <= bsp.MAX_EVIDENCE_CHARS + 20


def test_clamping_leaves_ordinary_findings_untouched():
    original = big_finding("high", 1)
    clamped = bsp.clamp_finding(original)
    assert clamped == original


def test_an_empty_finding_set_is_not_marked_truncated():
    payload = bsp.build_payload(scan(findings=[]), META)
    assert payload["summary"]["truncated"] is False
    assert payload["summary"]["stored"] == 0


# --- AI consensus -----------------------------------------------------------
# The shared engine returns one ConsensusResult for the scan document. It used to
# be discarded (only the job's pass/fail reached the record). What reaches the
# record now is an allowlisted, bounded summary: the raw result names the LLM
# providers and models behind every vote, which is not client-facing.


def engine_result(**overrides):
    """The shape consensus-engine's analyze.yml emits (asdict(ConsensusResult))."""
    base = {
        "consensus_severity": "HIGH",
        "confidence_percent": 82.5,
        "exploitability": "MEDIUM",
        "impact": "HIGH",
        "false_positive_likelihood": "LOW",
        "internet_exposed": True,
        "compliance_impact": {
            "frameworks": ["PCI-DSS", "SOC2"],
            "control_domains": ["Access Control"],
            "control_mappings": {"SOC2": ["CC6.1", "CC7.1"]},
            "audit_risk": "HIGH",
            "breach_notification_risk": False,
        },
        "aggregated_remediation": ["Disable TLS 1.0 and 1.1 on the web tier"],
        "verification_steps": ["Re-run the TLS check and confirm only TLS 1.2+ is offered"],
        "total_models": 15,
        "successful_models": 12,
        "failed_models": 3,
        "severity_distribution": {"HIGH": 9, "MEDIUM": 3},
        "weighted_scores": {"HIGH": 71.0, "MEDIUM": 29.0},
        "model_responses": [
            {
                "model_name": "llama-3.3-70b-versatile",
                "provider": "groq",
                "reasoning": "As an LLM hosted by Groq ...",
                "error": None,
            }
        ],
        "engine_version": "5.0",
        "timestamp": "2026-09-24T12:00:00Z",
    }
    base.update(overrides)
    return base


def test_consensus_assessment_reaches_the_record():
    p = bsp.build_payload(scan(), META, consensus=engine_result())
    c = p["consensus"]
    assert c["status"] == "success"
    assert c["severity"] == "HIGH"
    assert c["confidence_percent"] == 82.5
    assert c["exploitability"] == "MEDIUM"
    assert c["impact"] == "HIGH"
    assert c["false_positive_likelihood"] == "LOW"
    assert c["internet_exposed"] is True
    assert c["remediation"] == ["Disable TLS 1.0 and 1.1 on the web tier"]
    assert c["verification_steps"] == ["Re-run the TLS check and confirm only TLS 1.2+ is offered"]
    assert c["compliance"]["frameworks"] == ["PCI-DSS", "SOC2"]
    assert c["compliance"]["control_mappings"] == {"SOC2": ["CC6.1", "CC7.1"]}
    assert c["compliance"]["audit_risk"] == "HIGH"
    assert c["compliance"]["breach_notification_risk"] is False
    assert c["models"] == {"total": 15, "succeeded": 12}
    assert c["analyzed_at"] == "2026-09-24T12:00:00Z"


def test_consensus_never_carries_provider_or_model_identity():
    """model_responses / weighted_scores name the LLMs; none of it is stored."""
    p = bsp.build_payload(scan(), META, consensus=engine_result())
    blob = json.dumps(p["consensus"]).lower()
    for leaked in ("groq", "llama", "model_responses", "weighted_scores", "reasoning", "provider"):
        assert leaked not in blob


def test_consensus_free_text_does_not_name_underlying_scanners():
    """LLM remediation text is client-facing, so scanner names are redacted."""
    result = engine_result(
        aggregated_remediation=["Close port 23, then confirm with NMAP -sV that it is filtered"],
        verification_steps=["Re-scan with nuclei templates for CVE-2021-44228"],
    )
    c = bsp.build_payload(scan(), META, consensus=result)["consensus"]
    blob = json.dumps(c).lower()
    for tool in ("nmap", "nuclei"):
        assert tool not in blob
    assert c["remediation"] == [
        "Close port 23, then confirm with a scanner -sV that it is filtered"
    ]
    # The rest of the advice survives; only the name is replaced.
    assert "CVE-2021-44228" in c["verification_steps"][0]


def test_no_successful_model_means_no_assessment():
    """The engine answers 'UNKNOWN' when every model failed; that is not a verdict."""
    result = engine_result(
        consensus_severity="UNKNOWN",
        confidence_percent=0,
        successful_models=0,
        failed_models=15,
        compliance_impact={},
        aggregated_remediation=[],
        verification_steps=[],
    )
    c = bsp.build_payload(scan(), META, consensus=result)["consensus"]
    assert c == {"status": "unavailable", "models": {"total": 15, "succeeded": 0}}


def test_missing_consensus_keeps_the_job_status_only():
    """The analysis job failed or was skipped: record why, invent nothing."""
    meta = {**META, "consensus_status": "failure"}
    assert bsp.build_payload(scan(), meta)["consensus"] == {"status": "failure"}


def test_job_succeeded_but_returned_nothing_usable():
    for bad in (None, "not a result", [engine_result(), engine_result()], {"unexpected": 1}):
        c = bsp.build_payload(scan(), META, consensus=bad)["consensus"]
        assert c == {"status": "no_result"}, bad


def test_single_element_list_is_accepted():
    """The engine collapses one result to an object, but a list of one is equivalent."""
    c = bsp.build_payload(scan(), META, consensus=[engine_result()])["consensus"]
    assert c["severity"] == "HIGH"


def test_consensus_enums_are_validated():
    """An LLM-derived field outside its vocabulary is dropped, not stored verbatim."""
    result = engine_result(
        consensus_severity="<img src=x onerror=alert(1)>",
        exploitability="VERY",
        internet_exposed="yes",
        confidence_percent="high",
    )
    c = bsp.build_payload(scan(), META, consensus=result)["consensus"]
    assert c["status"] == "success"
    for key in ("severity", "exploitability", "internet_exposed", "confidence_percent"):
        assert key not in c
    assert c["impact"] == "HIGH"


def test_consensus_is_bounded():
    """A runaway LLM answer cannot push the record past Firestore's limit."""
    result = engine_result(
        aggregated_remediation=["x" * 50_000] * 500,
        verification_steps=["y" * 50_000] * 500,
        compliance_impact={
            "frameworks": ["f" * 5_000] * 500,
            "control_domains": ["d"] * 500,
            "control_mappings": {f"K{i}": ["c" * 5_000] * 500 for i in range(500)},
            "audit_risk": "HIGH",
            "breach_notification_risk": True,
        },
    )
    c = bsp.build_payload(scan(), META, consensus=result)["consensus"]
    assert len(c["remediation"]) == bsp.MAX_CONSENSUS_ITEMS
    assert len(c["verification_steps"]) == bsp.MAX_CONSENSUS_ITEMS
    assert all(len(s) <= bsp.MAX_CONSENSUS_TEXT + len("… [truncated]") for s in c["remediation"])
    assert len(c["compliance"]["control_mappings"]) <= bsp.MAX_CONSENSUS_ITEMS
    assert len(json.dumps(c)) < 60_000


def test_cli_reads_consensus_file(tmp_path):
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps(scan()))
    consensus = tmp_path / "consensus.json"
    consensus.write_text(json.dumps(engine_result()))
    out = tmp_path / "payload.json"
    rc = bsp.main(
        [
            "--findings",
            str(findings),
            "--out",
            str(out),
            "--scan-type",
            "modular_scan",
            "--scan-id",
            "ti-123",
            "--client-id",
            "acme",
            "--client-name",
            "Acme",
            "--target",
            "example.com",
            "--consensus-status",
            "success",
            "--consensus-file",
            str(consensus),
        ]
    )
    assert rc == 0
    assert json.loads(out.read_text())["consensus"]["severity"] == "HIGH"


@pytest.mark.parametrize("content", ["", "{not json", "\x00\x01"])
def test_cli_tolerates_unreadable_consensus_file(tmp_path, content):
    """A bad consensus blob must not cost the client their findings."""
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps(scan(findings=[{"severity": "high", "title": "t"}])))
    consensus = tmp_path / "consensus.json"
    consensus.write_text(content)
    out = tmp_path / "payload.json"
    rc = bsp.main(
        [
            "--findings",
            str(findings),
            "--out",
            str(out),
            "--scan-type",
            "modular_scan",
            "--scan-id",
            "ti-123",
            "--client-id",
            "acme",
            "--client-name",
            "Acme",
            "--target",
            "example.com",
            "--consensus-status",
            "success",
            "--consensus-file",
            str(consensus),
        ]
    )
    assert rc == 0
    payload = json.loads(out.read_text())
    assert payload["consensus"] == {"status": "no_result"}
    assert payload["summary"]["total"] == 1


def test_boolean_model_count_is_not_a_success():
    """True is an int in Python; it must not read as "one model agreed"."""
    c = bsp.build_payload(scan(), META, consensus=engine_result(successful_models=True))[
        "consensus"
    ]
    assert c["status"] == "unavailable"
