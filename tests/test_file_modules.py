"""
Tests for the file-ingestion module type (PR 3).

FileModules re-house the existing parsers behind the framework's ingest(file, ctx)
contract and emit the SAME Finding shape as the active scanners. As with
test_modules.py we put module_framework/ on sys.path (flat imports), plus src/ so
the wrapped threat_inspector parsers import. No external tools needed — fixtures
are tiny synthetic exports written to tmp_path.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "module_framework"))
sys.path.insert(0, str(ROOT / "src"))

import ingest  # noqa: E402
import registry  # noqa: E402
from base import FileModule, Finding  # noqa: E402
from file_modules._convert import to_findings  # noqa: E402

from threat_inspector.parsers.base import ParsedVulnerability, ParseResult  # noqa: E402

EXPECTED_FILE_MODULES = {
    "qualys_ingest",
    "qualys_compliance_ingest",
    "zap_ingest",
    "nmap_ingest",
    "nessus_ingest",
}


# ---- discovery / catalog ------------------------------------------------

def test_discovers_all_file_modules():
    reg = registry.discover_files("file_modules")
    assert set(reg) == EXPECTED_FILE_MODULES
    assert all(isinstance(m, FileModule) for m in reg.values())


def test_shared_mixin_not_discovered():
    # ParserFileModule is a mixin, not a module — it must not leak into the registry.
    reg = registry.discover_files("file_modules")
    assert "ParserFileModule" not in reg
    assert all(m.name for m in reg.values())


def test_catalog_marks_file_kind_with_extensions():
    reg = registry.discover_files("file_modules")
    cat = {c["name"]: c for c in registry.catalog(reg)}
    zap = cat["zap_ingest"]
    assert zap["kind"] == "file"
    assert ".json" in zap["extensions"]
    assert "target_kinds" not in zap  # file modules expose extensions, not target_kinds


def test_ingest_group_present():
    reg = registry.discover_files("file_modules")
    assert "ingest" in registry.all_groups(reg)


# ---- conversion ---------------------------------------------------------

def test_to_findings_maps_fields_and_target_precedence():
    result = ParseResult(
        scanner_type="x",
        vulnerabilities=[
            ParsedVulnerability(title="XSS", severity="high", description="d",
                                asset_url="https://a/x", asset_ip="10.0.0.1", cve_id="CVE-1"),
            ParsedVulnerability(title="Open port", severity="info", asset_ip="10.0.0.2"),
        ],
        scan_metadata={"source_file": "f.xml"},
    )
    findings = to_findings("zap_ingest", result)
    assert [f.title for f in findings] == ["XSS", "Open port"]
    # URL wins over IP for target; falls back to IP when no URL.
    assert findings[0].target == "https://a/x"
    assert findings[1].target == "10.0.0.2"
    assert findings[0].evidence["cve_id"] == "CVE-1"
    assert all(isinstance(f, Finding) for f in findings)


def test_to_findings_normalizes_out_of_range_severity():
    # A parser that emitted a raw vendor value must still land in SEVERITIES,
    # otherwise Finding would hard-error.
    result = ParseResult(
        scanner_type="x",
        vulnerabilities=[ParsedVulnerability(title="V", severity="URGENT")],
        scan_metadata={"source_file": "f.csv"},
    )
    findings = to_findings("qualys_ingest", result)
    assert findings[0].severity == "critical"


def test_empty_evidence_keys_dropped():
    result = ParseResult(
        scanner_type="x",
        vulnerabilities=[ParsedVulnerability(title="V", severity="low", asset_ip="1.1.1.1")],
        scan_metadata={"source_file": "f.csv"},
    )
    ev = to_findings("nessus_ingest", result)[0].evidence
    assert "asset_ip" in ev
    assert "cve_id" not in ev  # empty string dropped


# ---- ingest CLI end to end ---------------------------------------------

ZAP_JSON = {
    "site": [{
        "@name": "https://app.acme.com",
        "alerts": [
            {"alert": "SQL Injection", "riskcode": "3", "desc": "<p>SQLi</p>",
             "solution": "Parameterize", "cweid": "89", "pluginid": "40018",
             "instances": [{"uri": "https://app.acme.com/login"}]},
            {"alert": "Info Leak", "riskcode": "0", "desc": "banner",
             "instances": [{"uri": "https://app.acme.com/"}]},
        ],
    }]
}


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_ingest_cli_emits_contract(tmp_path, capsys):
    f = _write(tmp_path, "zap.json", json.dumps(ZAP_JSON))
    rc = ingest.main(["--group", "ingest", "--files", str(f),
                      "--client", "Acme Corp", "--scan-id", "s1"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    # Same contract keys the analyze/store pipeline consumes.
    assert out["client"] == "Acme Corp"
    assert out["scan_id"] == "s1"
    assert out["file_count"] == 1
    assert set(out["modules_run"]) == EXPECTED_FILE_MODULES
    titles = [x["title"] for x in out["findings"]]
    assert "SQL Injection" in titles
    for finding in out["findings"]:
        assert set(finding) >= {"module", "target", "severity", "title", "detail", "evidence"}
        assert finding["severity"] in ("info", "low", "medium", "high", "critical")


def test_ingest_cli_disambiguates_shared_extension(tmp_path, capsys):
    # A .csv is claimed by qualys, qualys_compliance and nessus. Content detection
    # must route a Nessus CSV to nessus_ingest, not silently mis-parse it.
    csv = "Plugin ID,Name,Risk,Host,CVE\n19506,Ping,None,10.0.0.5,\n"
    f = _write(tmp_path, "export.csv", csv)
    rc = ingest.main(["--group", "ingest", "--files", str(f), "--client", "c"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["file_count"] == 1
    assert out["files_skipped"] == []


def test_ingest_cli_no_files_is_error(capsys):
    rc = ingest.main(["--group", "ingest"])
    assert rc == 2


def test_ingest_cli_unknown_module_is_error(capsys):
    rc = ingest.main(["--modules", "nope", "--files", "x.json"])
    assert rc == 2
