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


# ---- target shape vs module shape ------------------------------------------
#
# A selected capability must never vanish silently. Before this, a url-only
# module handed "example.com" — the obvious thing for an operator to type — was
# skipped with a debug log, `modules_run` still listed it, and the run said "ok"
# with zero findings. That is byte-identical to a clean result. The same held in
# the other direction: a host-kind module handed "https://example.com" never ran.


class HostOnly(ScanModule):
    name = "host_only"
    description = "Only handles hosts, like a port scanner."
    target_kinds = ("ip", "domain", "hostname")
    groups = ("quick",)

    def run(self, target, ctx):
        return [
            Finding(
                module="host_only",
                target=target.value,
                severity="info",
                title=f"kind={target.kind}",
            )
        ]


class DomainOnly(ScanModule):
    name = "domain_only"
    description = "Wants a registrable domain, like subdomain enumeration."
    target_kinds = ("domain",)
    groups = ("quick",)

    def run(self, target, ctx):
        return []


@pytest.mark.parametrize(
    ("token", "url"),
    [
        ("example.com", "https://example.com"),
        ("web-1", "https://web-1"),
        ("192.168.1.10", "https://192.168.1.10"),
        ("2001:db8::10", "https://[2001:db8::10]"),
    ],
)
def test_a_url_only_module_runs_against_a_bare_host_addressed_as_a_url(
    stub_registry, capsys, token, url
):
    stub_registry(UrlOnly())
    _, doc = run_cli(capsys, ["--modules", "url_only", "--targets", token])
    assert doc["status"] == "ok"
    assert doc["stats"]["module_runs"] == 1
    assert [f["target"] for f in doc["findings"]] == [url]
    assert doc["skipped"] == []


@pytest.mark.parametrize(
    ("token", "value", "kind"),
    [
        ("https://example.com/login", "example.com", "domain"),
        ("http://web-1:8080/", "web-1", "hostname"),
        ("https://192.168.1.10:8443/", "192.168.1.10", "ip"),
        ("https://[2001:db8::10]/", "2001:db8::10", "ip"),
    ],
)
def test_a_host_module_runs_against_the_host_of_a_url(stub_registry, capsys, token, value, kind):
    stub_registry(HostOnly())
    _, doc = run_cli(capsys, ["--modules", "host_only", "--targets", token])
    assert doc["status"] == "ok"
    assert doc["stats"]["module_runs"] == 1
    assert doc["findings"][0]["target"] == value
    assert doc["findings"][0]["title"] == f"kind={kind}"


def test_a_module_that_genuinely_cannot_address_the_target_is_reported_not_silent(
    stub_registry, capsys
):
    """A domain-only capability given a hostname: no shape fits, so say so."""
    stub_registry(DomainOnly(), Noisy())
    _, doc = run_cli(capsys, ["--modules", "domain_only,noisy", "--targets", "web-1"])
    assert doc["stats"]["module_runs"] == 1
    assert doc["modules_run"] == ["noisy"], "a module that never ran is not reported as run"
    assert doc["skipped"] == [
        {
            "module": "domain_only",
            "target": "web-1",
            "reason": "capability assesses domain targets; web-1 is a hostname",
        }
    ]
    # Every capability that ran ran cleanly, but one selected capability did
    # not run at all — that is "degraded", exactly as for a missing scanner.
    assert doc["status"] == "degraded"


def test_a_skip_for_shape_never_names_an_underlying_tool(stub_registry, capsys):
    stub_registry(DomainOnly())
    _, doc = run_cli(capsys, ["--modules", "domain_only", "--targets", "10.0.0.1"])
    assert "missing" not in doc["skipped"][0]
    assert doc["status"] == "failed", "nothing ran; that is not a clean scan"


def test_modules_run_is_what_executed_not_what_was_selected(stub_registry, capsys):
    stub_registry(DomainOnly(), HostOnly(), UrlOnly())
    _, doc = run_cli(
        capsys, ["--modules", "domain_only,host_only,url_only", "--targets", "example.com,web-1"]
    )
    assert doc["modules_run"] == ["domain_only", "host_only", "url_only"]
    assert doc["stats"]["module_runs"] == 5
    assert [(s["module"], s["target"]) for s in doc["skipped"]] == [("domain_only", "web-1")]
    assert doc["status"] == "degraded"


def test_a_dry_run_still_reports_the_selection_as_modules_run(stub_registry, capsys):
    stub_registry(DomainOnly(), Noisy())
    _, doc = run_cli(capsys, ["--modules", "domain_only,noisy", "--targets", "web-1", "--dry-run"])
    assert doc["modules_run"] == ["domain_only", "noisy"]
    assert doc["skipped"] == []


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


def test_reshaping_for_one_module_does_not_change_what_the_next_module_sees(stub_registry, capsys):
    """The operator typed a URL with a port and a path. A host module is handed
    the host; the URL module after it must still get the whole URL — not a URL
    re-derived from the host, which would have lost `:8443/login`."""
    stub_registry(HostOnly(), UrlOnly())
    _, doc = run_cli(
        capsys,
        ["--modules", "host_only,url_only", "--targets", "https://example.com:8443/login"],
    )
    assert doc["status"] == "ok"
    assert {f["module"]: f["target"] for f in doc["findings"]} == {
        "host_only": "example.com",
        "url_only": "https://example.com:8443/login",
    }


def test_a_reshaped_target_still_names_what_the_operator_entered():
    """Reshaping is a change of address, never of identity."""
    from targets import Target

    url = Target(
        raw="HTTPS://Example.com:8443/login", kind="url", value="https://example.com:8443/login"
    )
    host = url.addressed_for(("ip", "domain", "hostname"))
    assert host is not None
    assert host.raw == "HTTPS://Example.com:8443/login"
    assert (host.kind, host.value) == ("domain", "example.com")

    domain = Target(raw="Example.COM", kind="domain", value="example.com")
    assert domain.as_url().raw == "Example.COM"
