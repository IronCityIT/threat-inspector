"""
Tests for the module_framework scan modules (PR 2 modular refactor).

The framework runs with `module_framework/` on sys.path (flat imports: `base`,
`registry`, `modules.*`), so we put it on the path here and exercise each module's
pure parse function plus registry discovery/selection. No external scanners needed.
"""
import sys
from pathlib import Path

import pytest

FRAMEWORK = Path(__file__).resolve().parent.parent / "module_framework"
sys.path.insert(0, str(FRAMEWORK))

import registry  # noqa: E402
from base import Finding  # noqa: E402
from modules.cve_lookup import parse_cves  # noqa: E402
from modules.default_creds_check import evaluate  # noqa: E402
from modules.header_security_check import evaluate_headers  # noqa: E402
from modules.port_scan import parse_ports  # noqa: E402
from modules.service_fingerprint import parse_services  # noqa: E402
from modules.subdomain_enum import parse_subdomains  # noqa: E402
from modules.tls_cert_check import cert_finding, grade_finding  # noqa: E402
from modules.web_vuln_scan import parse_findings as parse_web  # noqa: E402

# ---- registry / catalog -------------------------------------------------

EXPECTED_MODULES = {
    "port_scan",
    "service_fingerprint",
    "tls_cert_check",
    "cve_lookup",
    "web_vuln_scan",
    "subdomain_enum",
    "header_security_check",
    "default_creds_check",
}


def _registry():
    return registry.discover("modules")


def test_all_modules_discovered():
    reg = _registry()
    assert set(reg) == EXPECTED_MODULES
    assert "example_recon" not in reg  # reference module removed


def test_group_presets():
    reg = _registry()
    quick = {m.name for m in registry.select(reg, group="quick")}
    deep = {m.name for m in registry.select(reg, group="deep")}
    assert quick == {"port_scan", "tls_cert_check", "header_security_check"}
    assert deep == EXPECTED_MODULES  # deep = everything
    assert "web_vuln_scan" not in quick  # intrusive, deep-only


def test_select_individual_modules():
    reg = _registry()
    chosen = registry.select(reg, modules=["port_scan", "cve_lookup"])
    assert [m.name for m in chosen] == ["port_scan", "cve_lookup"]


def test_select_unknown_module_raises():
    reg = _registry()
    with pytest.raises(KeyError):
        registry.select(reg, modules=["does_not_exist"])


# ---- pure parsers -------------------------------------------------------

def test_port_scan_parse():
    raw = "22/tcp open ssh\n80/tcp open http\nnot a port line\n443/tcp closed https"
    findings = parse_ports(raw, "10.0.0.1")
    assert [f.evidence["port"] for f in findings] == [22, 80]
    assert all(f.module == "port_scan" and f.severity == "info" for f in findings)


def test_service_fingerprint_parse():
    raw = "22/tcp open ssh OpenSSH 8.2p1 Ubuntu\n80/tcp open http\n"
    findings = parse_services(raw, "10.0.0.1")
    # only the line carrying a version becomes a finding
    assert len(findings) == 1
    assert findings[0].evidence["version"].startswith("OpenSSH 8.2p1")


def test_tls_grade_and_cert_findings():
    assert grade_finding("A+", "acme.com")[0].severity == "info"
    assert grade_finding("F", "acme.com")[0].severity == "high"
    assert grade_finding(None, "acme.com") == []
    assert cert_finding(-1, "acme.com")[0].severity == "critical"
    assert cert_finding(10, "acme.com")[0].severity == "high"
    assert cert_finding(25, "acme.com")[0].severity == "medium"
    assert cert_finding(200, "acme.com")[0].severity == "info"
    assert cert_finding(None, "acme.com") == []


def test_header_evaluation():
    findings = evaluate_headers({"Strict-Transport-Security": "max-age=1"}, "acme.com")
    flagged = {f.evidence["header"] for f in findings}
    assert "strict-transport-security" not in flagged  # present -> not flagged
    assert "content-security-policy" in flagged  # missing -> flagged


def test_subdomain_parse_dedupes():
    raw = "a.acme.com\nA.ACME.COM\nb.acme.com\n\n"
    findings = parse_subdomains(raw, "acme.com")
    assert {f.evidence["subdomain"] for f in findings} == {"a.acme.com", "b.acme.com"}


def test_web_vuln_parse_jsonl():
    raw = '{"info":{"name":"XSS","severity":"high"},"matched-at":"http://x/","template-id":"xss"}\nbad\n'
    findings = parse_web(raw, "http://x/")
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].evidence["template"] == "xss"


def test_web_vuln_parse_unknown_severity_defaults_info():
    raw = '{"info":{"name":"Note","severity":"bogus"}}'
    assert parse_web(raw, "http://x/")[0].severity == "info"


def test_cve_parse_scores_to_severity():
    raw = "  CVE-2021-3156  9.8  https://vulners.com/x\n  CVE-2019-0001  5.0  url\n  CVE-2021-3156  9.8  dup"
    findings = parse_cves(raw, "10.0.0.1")
    sev = {f.evidence["cve"]: f.severity for f in findings}
    assert sev == {"CVE-2021-3156": "critical", "CVE-2019-0001": "medium"}  # deduped


def test_default_creds_eval():
    results = {"/admin": 200, "/login": 302, "/missing": 404, "/err": 500, "/none": None}
    findings = evaluate(results, "acme.com")
    paths = {f.evidence["path"] for f in findings}
    assert paths == {"/admin", "/login"}
    assert all(f.severity == "medium" for f in findings)


def test_finding_rejects_bad_severity():
    with pytest.raises(ValueError):
        Finding(module="m", target="t", severity="explosive", title="x")
