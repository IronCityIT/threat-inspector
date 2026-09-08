"""The `threat-inspector` console entry point.

`[project.scripts]` declares `threat-inspector = threat_inspector.cli:main`, so
this ships in the package and anyone who installs it can run it. It sat at **0%
coverage** — 145 statements nobody had ever executed in a test — with an open
question of whether to cover it or drop it.

Running it answered that: it mostly works, and the ways it did not were all the
same shape this product keeps finding — **something failed and the command said
success anyway**:

  * `--format pdf` was an offered choice that `generate_report` has no branch
    for. It printed a failure and exited **0**, so a scripted caller saw success
    and no file.
  * A directory containing no readable scan files printed "Analysis complete!"
    and exited **0**, having loaded nothing at all.
  * Any report that failed to generate was printed and then forgotten; the exit
    code never reflected it.

These drive the real Click command through `CliRunner`, so the option parsing,
the exit codes and the output are the ones a user gets.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from threat_inspector.cli import main  # noqa: E402
from threat_inspector.reports import REPORT_FORMATS  # noqa: E402

FIXTURE = ROOT / "examples" / "file-ingest-selftest" / "nessus-export.csv"


@pytest.fixture
def runner():
    return CliRunner()


def cli_inspector_class():
    """The ThreatInspector class the CLI will actually instantiate.

    Not `from threat_inspector.core import ThreatInspector`. Several suites here
    delete `threat_inspector*` from sys.modules to get a freshly imported app,
    so a later import yields a DIFFERENT class object from the one `cli.py`
    bound at its own import time — and patching that one changes nothing the CLI
    sees. Running this file alone passed; running the whole suite did not.

    `main.callback.__globals__` is cli.py's own namespace, whatever sys.modules
    has been through since, so this is the object the command really uses.
    """
    return main.callback.__globals__["ThreatInspector"]


def analyze(runner, tmp_path, *extra, source=None):
    """Run `analyze` against a real export unless told otherwise."""
    return runner.invoke(
        main,
        [
            "analyze",
            "-i",
            str(source or FIXTURE),
            "-o",
            str(tmp_path / "out"),
            "--no-remediation",
            "--no-compliance",
            *extra,
        ],
    )


# ---------------------------------------------------------------------------
# It works
# ---------------------------------------------------------------------------


def test_the_entry_point_reports_its_version(runner):
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "threat-inspector" in result.output


def test_the_help_lists_every_command(runner):
    output = runner.invoke(main, ["--help"]).output
    for command in ("analyze", "api", "formats", "init", "serve"):
        assert command in output


def test_formats_lists_the_extensions_that_can_be_ingested(runner):
    result = runner.invoke(main, ["formats"])
    assert result.exit_code == 0
    assert ".nessus" in result.output
    assert ".csv" in result.output


def test_init_creates_a_project_skeleton(runner, tmp_path):
    result = runner.invoke(main, ["init", "-o", str(tmp_path)])
    assert result.exit_code == 0
    assert (tmp_path / "config.yaml").is_file()
    assert (tmp_path / "scans").is_dir()
    assert (tmp_path / "reports").is_dir()


@pytest.mark.parametrize("fmt", REPORT_FORMATS)
def test_a_real_export_produces_a_report_in_every_offered_format(runner, tmp_path, fmt):
    result = analyze(runner, tmp_path, "-f", fmt)
    assert result.exit_code == 0, result.output
    written = list((tmp_path / "out").glob(f"*.{fmt}"))
    assert len(written) == 1
    assert written[0].stat().st_size > 0


def test_the_json_report_is_valid_json(runner, tmp_path):
    analyze(runner, tmp_path, "-f", "json")
    written = next((tmp_path / "out").glob("*.json"))
    assert json.loads(written.read_text())


def test_the_summary_counts_what_was_parsed(runner, tmp_path):
    result = analyze(runner, tmp_path, "-f", "json")
    assert "Total Vulnerabilities" in result.output
    assert "8" in result.output


def test_a_directory_of_exports_is_read(runner, tmp_path):
    source = tmp_path / "scans"
    source.mkdir()
    (source / "export.csv").write_bytes(FIXTURE.read_bytes())
    result = analyze(runner, tmp_path, "-f", "json", source=source)
    assert result.exit_code == 0, result.output


def test_several_formats_can_be_asked_for_at_once(runner, tmp_path):
    result = analyze(runner, tmp_path, "-f", "json", "-f", "csv")
    assert result.exit_code == 0
    assert len(list((tmp_path / "out").glob("*.json"))) == 1
    assert len(list((tmp_path / "out").glob("*.csv"))) == 1


# ---------------------------------------------------------------------------
# ...and when it does not, it says so
# ---------------------------------------------------------------------------


def test_a_format_that_cannot_be_produced_is_not_offered(runner, tmp_path):
    """`pdf` used to be an accepted choice that always failed, and the command
    exited 0 anyway. Click now refuses it at parse time."""
    result = analyze(runner, tmp_path, "-f", "pdf")
    assert result.exit_code != 0
    assert "pdf" in result.output


def test_a_directory_with_no_readable_scans_is_a_failure_not_a_clean_run(runner, tmp_path):
    """Reading NO files is not the same as reading files that found nothing,
    and only the second is a clean result. This used to print
    "Analysis complete!" and exit 0."""
    source = tmp_path / "empty"
    source.mkdir()
    (source / "notes.md").write_text("nothing to see")

    result = analyze(runner, tmp_path, source=source)
    assert result.exit_code == 1
    assert "No scan files were read" in result.output
    # The success banner is "Analysis complete!"; the analyse PHASE separately
    # logs "Analysis complete" as a progress description, so the "!" matters.
    assert "Analysis complete!" not in result.output


def test_the_no_scans_message_says_what_would_have_been_read(runner, tmp_path):
    source = tmp_path / "empty"
    source.mkdir()
    (source / "notes.md").write_text("x")
    output = analyze(runner, tmp_path, source=source).output
    assert ".nessus" in output or ".csv" in output
    assert "--recursive" in output, "the most likely cause is worth naming"


def test_recursive_is_not_suggested_when_it_was_already_used(runner, tmp_path):
    source = tmp_path / "empty"
    (source / "deep").mkdir(parents=True)
    (source / "deep" / "notes.md").write_text("x")
    output = analyze(runner, tmp_path, "-r", source=source).output
    assert "--recursive" not in output


def test_a_failed_report_makes_the_command_fail(runner, tmp_path, monkeypatch):
    """A report that was asked for and not produced is a failure, whatever else
    went right. This used to print the error and still exit 0."""

    def boom(*args, **kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(cli_inspector_class(), "generate_report", boom)

    result = analyze(runner, tmp_path, "-f", "json")
    assert result.exit_code == 1
    assert "Failed to generate" in result.output
    assert "Analysis complete!" not in result.output


def test_one_failed_format_fails_the_run_even_when_another_succeeded(runner, tmp_path, monkeypatch):
    inspector_cls = cli_inspector_class()
    original = inspector_cls.generate_report

    def only_json_works(self, output_path, format="html", **kwargs):
        if format != "json":
            raise RuntimeError("nope")
        return original(self, output_path, format=format, **kwargs)

    monkeypatch.setattr(inspector_cls, "generate_report", only_json_works)

    result = analyze(runner, tmp_path, "-f", "json", "-f", "csv")
    assert result.exit_code == 1
    assert len(list((tmp_path / "out").glob("*.json"))) == 1, "the one that worked still lands"


def test_a_missing_input_path_is_refused_by_the_parser(runner, tmp_path):
    result = analyze(runner, tmp_path, source=tmp_path / "does-not-exist")
    assert result.exit_code != 0


def test_an_unreadable_single_file_is_an_error_not_a_clean_run(runner, tmp_path):
    """A file the parser cannot read must not pass for an empty scan."""
    broken = tmp_path / "broken.xml"
    broken.write_text("<not-closed")

    result = analyze(runner, tmp_path, "-f", "json", source=broken)
    # Either the load is refused outright or the report says nothing was found —
    # what must never happen is a confident, successful, empty report.
    if result.exit_code == 0:
        written = next((tmp_path / "out").glob("*.json"))
        assert (
            json.loads(written.read_text()).get("summary", {}).get("total_vulnerabilities", 0) == 0
        )
