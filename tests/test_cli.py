"""The scan entry point: containment, status honesty, and exit codes.

These drive cli.main() in-process with a stubbed registry, so nothing here
touches the network. The point is the *runtime contract* around modules, not the
modules themselves (those are covered in test_modules.py).
"""

from __future__ import annotations

import json

import cli
import pytest
from base import Finding, ScanModule


class Quiet(ScanModule):
    name = "quiet"
    description = "Returns nothing."
    groups = ("quick",)

    def run(self, target, ctx):
        return []


class Noisy(ScanModule):
    name = "noisy"
    description = "Returns one finding."
    groups = ("quick",)

    def run(self, target, ctx):
        return [Finding(module="noisy", target=target.value, severity="low", title="found")]


class Boom(ScanModule):
    name = "boom"
    description = "Raises."
    groups = ("quick",)

    def run(self, target, ctx):
        raise RuntimeError("module exploded")


class UrlOnly(ScanModule):
    name = "url_only"
    description = "Only handles URLs."
    target_kinds = ("url",)
    groups = ("quick",)

    def run(self, target, ctx):
        return [Finding(module="url_only", target=target.value, severity="info", title="url")]


@pytest.fixture
def stub_registry(monkeypatch):
    """Swap module discovery for a fixed set so the tests are hermetic."""

    def install(*modules):
        reg = {m.name: m for m in modules}
        monkeypatch.setattr(cli.registry, "discover", lambda package="modules": reg)
        return reg

    return install


def run_cli(capsys, argv):
    code = cli.main(argv)
    out = capsys.readouterr().out
    return code, (json.loads(out) if out.strip() else None)


# ---- containment --------------------------------------------------------


def test_a_raising_module_does_not_sink_the_scan(stub_registry, capsys):
    """The whole reason run_module() exists: one bad module used to abort main()
    and discard every finding the previous modules had already produced."""
    stub_registry(Boom(), Noisy())
    code, doc = run_cli(capsys, ["--modules", "boom,noisy", "--targets", "example.com"])

    assert code == 0
    assert len(doc["findings"]) == 1, "the healthy module's finding must survive"
    assert doc["errors"] == [
        {"module": "boom", "target": "example.com", "error": "RuntimeError: module exploded"}
    ]


def test_status_partial_when_some_modules_fail(stub_registry, capsys):
    stub_registry(Boom(), Noisy())
    _, doc = run_cli(capsys, ["--modules", "boom,noisy", "--targets", "example.com"])
    assert doc["status"] == "partial"


def test_status_failed_when_every_module_fails(stub_registry, capsys):
    """Distinguishable from a clean scan — both produce zero findings."""
    stub_registry(Boom())
    _, doc = run_cli(capsys, ["--modules", "boom", "--targets", "example.com"])
    assert doc["status"] == "failed"
    assert doc["findings"] == []


def test_status_ok_on_a_clean_scan_with_no_findings(stub_registry, capsys):
    stub_registry(Quiet())
    _, doc = run_cli(capsys, ["--modules", "quiet", "--targets", "example.com"])
    assert doc["status"] == "ok"
    assert doc["findings"] == []
    assert doc["errors"] == []


def test_stats_account_for_every_module_run(stub_registry, capsys):
    stub_registry(Boom(), Noisy())
    _, doc = run_cli(capsys, ["--modules", "boom,noisy", "--targets", "example.com"])
    stats = doc["stats"]
    assert stats["module_runs"] == 2
    assert stats["module_runs_failed"] == 1
    assert {t["module"] for t in stats["timings"]} == {"boom", "noisy"}
    assert [t["ok"] for t in stats["timings"] if t["module"] == "noisy"] == [True]


def test_modules_that_do_not_apply_to_a_target_kind_are_skipped(stub_registry, capsys):
    stub_registry(UrlOnly())
    _, doc = run_cli(capsys, ["--modules", "url_only", "--targets", "example.com"])
    assert doc["stats"]["module_runs"] == 0
    assert doc["status"] == "ok"


# ---- input handling -----------------------------------------------------


def test_bad_targets_are_reported_without_a_traceback(stub_registry, capsys):
    stub_registry(Noisy())
    code, doc = run_cli(capsys, ["--modules", "noisy", "--targets", "example.com,10.0.0.0/99"])
    assert code == 0
    assert doc["target_count"] == 1
    assert len(doc["rejected_targets"]) == 1


def test_strict_targets_refuses_a_partial_batch(stub_registry, capsys):
    stub_registry(Noisy())
    code, doc = run_cli(
        capsys,
        ["--modules", "noisy", "--targets", "example.com,10.0.0.0/99", "--strict-targets"],
    )
    assert code == 2
    assert doc is None, "nothing should be emitted when the scan is refused"


def test_no_valid_targets_exits_two(stub_registry, capsys):
    stub_registry(Noisy())
    code, _ = run_cli(capsys, ["--modules", "noisy", "--targets", "10.0.0.0/99"])
    assert code == 2


def test_unknown_module_exits_two_and_lists_what_exists(stub_registry, capsys):
    stub_registry(Noisy())
    code = cli.main(["--modules", "nope", "--targets", "example.com"])
    assert code == 2
    assert "noisy" in capsys.readouterr().err


# ---- dry run ------------------------------------------------------------


def test_dry_run_executes_no_module_but_keeps_the_schema(stub_registry, capsys):
    stub_registry(Boom())
    code, doc = run_cli(capsys, ["--modules", "boom", "--targets", "example.com", "--dry-run"])
    assert code == 0, "a dry run must not reach Boom.run()"
    assert doc["status"] == "dry_run"
    assert doc["dry_run"] is True
    # Same keys as a real run, so downstream consumers exercise one path.
    assert {"findings", "errors", "stats", "modules_run", "target_count"} <= set(doc)


def test_list_modules_emits_the_catalog(stub_registry, capsys):
    stub_registry(Noisy())
    code, doc = run_cli(capsys, ["--list-modules"])
    assert code == 0
    assert [m["name"] for m in doc["modules"]] == ["noisy"]
    assert "quick" in doc["groups"]
