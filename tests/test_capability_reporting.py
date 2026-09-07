"""A capability that never ran must not report as a capability that found nothing.

Five modules shell out to an external scanner. When that scanner is not
installed, `run_cmd` returns None, the module returns `[]`, and the runner
recorded a SUCCESSFUL run with zero findings — which is byte-identical to a
clean result. Measured against the real entry point before this change:

    cli.py --modules subdomain_enum ...   (subfinder not installed)
    -> status "ok", 0 findings, module_runs 1, module_runs_failed 0

A scan that reports "no subdomains" or "no web application vulnerabilities"
when the scanner was never installed is the worst thing a security product can
say, and the run's own health did not catch it: those counters track module
EXCEPTIONS, and nothing raised.

Modules now DECLARE what they need. The runner checks before executing, records
what it skipped and why, and reports "degraded" — every capability that ran ran
cleanly, but some never ran at all.

These drive cli.main() in-process with a stubbed registry, so nothing here
touches the network.
"""

from __future__ import annotations

import json

import cli
import pytest
from base import Finding, ScanModule


class Plain(ScanModule):
    name = "plain"
    description = "Needs no external scanner."
    groups = ("quick",)

    def run(self, target, ctx):
        return [Finding(module="plain", target=target.value, severity="low", title="found")]


class NeedsMissing(ScanModule):
    name = "needs_missing"
    description = "Requires a scanner that is not installed."
    groups = ("quick",)
    requires = ("definitely-not-a-real-scanner",)

    def run(self, target, ctx):  # pragma: no cover - must never be reached
        raise AssertionError("a module with a missing requirement must not be run")


class NeedsPresent(ScanModule):
    name = "needs_present"
    description = "Requires a scanner that every environment has."
    groups = ("quick",)
    requires = ("python3",)

    def run(self, target, ctx):
        return [Finding(module="needs_present", target=target.value, severity="info", title="ran")]


class Boom(ScanModule):
    name = "boom"
    description = "Raises."
    groups = ("quick",)

    def run(self, target, ctx):
        raise RuntimeError("module exploded")


@pytest.fixture
def stub_registry(monkeypatch):
    def install(*modules):
        reg = {m.name: m for m in modules}
        monkeypatch.setattr(cli.registry, "discover", lambda package="modules": reg)
        return reg

    return install


def run_cli(capsys, argv):
    code = cli.main(argv)
    out = capsys.readouterr().out
    return code, (json.loads(out) if out.strip() else None)


# ---------------------------------------------------------------------------
# Declaring a requirement
# ---------------------------------------------------------------------------


def test_a_module_with_no_requirements_is_never_skipped():
    assert Plain().missing_requirements() == []


def test_a_missing_scanner_is_reported_by_name():
    assert NeedsMissing().missing_requirements() == ["definitely-not-a-real-scanner"]


def test_a_present_scanner_is_not_reported_missing():
    assert NeedsPresent().missing_requirements() == []


@pytest.mark.parametrize(
    ("module_name", "tool"),
    [
        ("port_scan", "nmap"),
        ("service_fingerprint", "nmap"),
        ("cve_lookup", "nmap"),
        ("subdomain_enum", "subfinder"),
        ("web_vuln_scan", "nuclei"),
    ],
)
def test_every_module_that_shells_out_declares_what_it_needs(module_name, tool):
    """The declaration is what makes the skip possible, so it has to exist."""
    import registry

    module = registry.discover()[module_name]
    assert tool in module.requires


def test_a_module_that_needs_nothing_declares_nothing():
    import registry

    discovered = registry.discover()
    assert discovered["header_security_check"].requires == ()
    assert discovered["tls_cert_check"].requires == ()


# ---------------------------------------------------------------------------
# The runner
# ---------------------------------------------------------------------------


def test_a_module_whose_scanner_is_missing_is_not_run_at_all(stub_registry, capsys):
    """NeedsMissing.run() raises if reached — the skip must happen first."""
    stub_registry(NeedsMissing())
    code, doc = run_cli(capsys, ["--modules", "needs_missing", "--targets", "example.com"])
    assert code == 0
    assert doc["errors"] == []


def test_the_skip_names_the_module_the_target_and_the_missing_tool(stub_registry, capsys):
    stub_registry(NeedsMissing())
    _, doc = run_cli(capsys, ["--modules", "needs_missing", "--targets", "example.com"])
    assert doc["skipped"] == [
        {
            "module": "needs_missing",
            "target": "example.com",
            "missing": ["definitely-not-a-real-scanner"],
        }
    ]


def test_a_scan_that_skipped_something_is_degraded_not_ok(stub_registry, capsys):
    """The regression: this used to be "ok" with zero findings."""
    stub_registry(Plain(), NeedsMissing())
    _, doc = run_cli(capsys, ["--modules", "plain,needs_missing", "--targets", "example.com"])
    assert doc["status"] == "degraded"
    assert len(doc["findings"]) == 1, "the module that could run must still report"


def test_a_scan_where_nothing_could_run_is_not_ok(stub_registry, capsys):
    """Zero modules attempted and zero findings must never read as clean."""
    stub_registry(NeedsMissing())
    _, doc = run_cli(capsys, ["--modules", "needs_missing", "--targets", "example.com"])
    assert doc["status"] == "failed"
    assert doc["findings"] == []


def test_a_fully_available_scan_is_still_ok(stub_registry, capsys):
    stub_registry(Plain(), NeedsPresent())
    _, doc = run_cli(capsys, ["--modules", "plain,needs_present", "--targets", "example.com"])
    assert doc["status"] == "ok"
    assert doc["skipped"] == []
    assert len(doc["findings"]) == 2


def test_a_failure_still_outranks_a_skip(stub_registry, capsys):
    """A module that blew up is a stronger signal than one that was absent."""
    stub_registry(Plain(), Boom(), NeedsMissing())
    _, doc = run_cli(capsys, ["--modules", "plain,boom,needs_missing", "--targets", "example.com"])
    assert doc["status"] == "partial"
    assert len(doc["errors"]) == 1
    assert len(doc["skipped"]) == 1


def test_the_stats_count_skips_separately_from_runs(stub_registry, capsys):
    stub_registry(Plain(), NeedsMissing())
    _, doc = run_cli(capsys, ["--modules", "plain,needs_missing", "--targets", "example.com"])
    assert doc["stats"]["module_runs"] == 1
    assert doc["stats"]["module_runs_failed"] == 0
    assert doc["stats"]["module_runs_skipped"] == 1


def test_a_skip_is_recorded_per_target(stub_registry, capsys):
    stub_registry(NeedsMissing())
    _, doc = run_cli(
        capsys, ["--modules", "needs_missing", "--targets", "example.com,other.example.com"]
    )
    assert [s["target"] for s in doc["skipped"]] == ["example.com", "other.example.com"]


def test_a_dry_run_skips_the_availability_check_along_with_everything_else(stub_registry, capsys):
    """The dry-run guard stops before any module work, skips included."""
    stub_registry(NeedsMissing())
    _, doc = run_cli(
        capsys, ["--modules", "needs_missing", "--targets", "example.com", "--dry-run"]
    )
    assert doc["status"] == "dry_run"
    assert doc["skipped"] == []


def test_the_skipped_key_is_present_even_on_a_clean_scan(stub_registry, capsys):
    """Downstream consumers must not have to guess whether the key exists."""
    stub_registry(Plain())
    _, doc = run_cli(capsys, ["--modules", "plain", "--targets", "example.com"])
    assert doc["skipped"] == []
    assert doc["stats"]["module_runs_skipped"] == 0


# ---------------------------------------------------------------------------
# Reaching the stored record
# ---------------------------------------------------------------------------


def build(scan: dict) -> dict:
    from build_store_payload import build_payload

    meta = {
        "scan_type": "network",
        "scan_id": "s1",
        "client_id": "acme",
        "client_name": "Acme",
        "target": "example.com",
    }
    return build_payload(scan, meta)


def test_the_record_says_which_capabilities_never_ran():
    """Without this the record cannot tell "we looked and found nothing" from
    "we never looked" — and the client is shown the former."""
    skipped = [{"module": "web_vuln_scan", "target": "example.com", "missing": ["nuclei"]}]
    payload = build({"findings": [], "status": "degraded", "skipped": skipped})

    assert payload["diagnostics"]["modules_skipped"] == skipped
    assert payload["diagnostics"]["modules_skipped_count"] == 1


def test_a_degraded_scan_is_stored_as_completed_but_says_it_was_degraded():
    payload = build(
        {
            "findings": [],
            "status": "degraded",
            "skipped": [{"module": "m", "target": "t", "missing": ["x"]}],
        }
    )
    assert payload["status"] == "completed"
    assert payload["scan_status"] == "degraded"
    assert payload["diagnostics"]["scan_status"] == "degraded"


def test_a_clean_scan_records_no_skips():
    payload = build({"findings": [], "status": "ok"})
    assert payload["diagnostics"]["modules_skipped"] == []
    assert payload["diagnostics"]["modules_skipped_count"] == 0
