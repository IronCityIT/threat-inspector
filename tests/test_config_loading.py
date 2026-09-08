"""Loading a YAML config, and noticing when it does nothing.

`Settings.from_yaml` is what turns an operator's config file into the settings a
scan and a report actually use. It sat at 67% coverage, and the shipped
operator-facing file was **silently half-ignored**.

`configs/client.yaml` — the file the vuln-report workflow tells you to edit
before a run — puts report settings under a `report:` block. `from_yaml` read
`output:` and `compliance:` and nothing else, so measured against the shipped
file:

    compliance_frameworks -> ['pci-dss']   (the file says pci-dss, hipaa, soc2)
    report formats        -> ['html']      (the file says html, json)

An operator who configured HIPAA and SOC 2 got a report carrying neither, and
one who asked for JSON got only HTML. Nothing said so, because an unrecognised
key looks exactly like a key that was applied — the same shape as every other
defect this pass has turned up.

Both shapes are accepted now, `logging:` is read (it was ignored too), and an
unrecognised top-level section is warned about.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml

from threat_inspector.config import Settings

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def write_config(tmp_path):
    def write(config: dict, name: str = "config.yaml") -> Path:
        path = tmp_path / name
        path.write_text(yaml.safe_dump(config), encoding="utf-8")
        return path

    return write


# ---------------------------------------------------------------------------
# The shipped files must actually work
# ---------------------------------------------------------------------------


def test_the_operator_facing_config_loads_its_compliance_frameworks():
    """The regression. This file is what an operator edits before a run, and
    every framework past the first was being dropped."""
    settings = Settings.from_yaml(ROOT / "configs" / "client.yaml")
    assert settings.compliance_frameworks == ["pci-dss", "hipaa", "soc2"]


def test_the_operator_facing_config_loads_its_report_formats():
    settings = Settings.from_yaml(ROOT / "configs" / "client.yaml")
    assert settings.reports.default_formats == ["html", "json"]


def test_the_operator_facing_config_loads_its_client_name():
    assert Settings.from_yaml(ROOT / "configs" / "client.yaml").client_name == "Acme Corporation"


def test_the_example_config_loads_every_section_it_declares():
    settings = Settings.from_yaml(ROOT / "examples" / "config.yaml")
    assert settings.compliance_frameworks == ["pci-dss", "hipaa", "soc2", "nist"]
    assert settings.reports.default_formats == ["html", "json"]
    assert settings.reports.output_dir == Path("./reports")
    assert settings.remediation.engine == "local"
    assert settings.log_file == Path("logs/threat_inspector.log")


def test_neither_shipped_config_warns_about_itself(caplog):
    """A warning on our own example means we ship configuration that does
    nothing — the same problem as offering a report format we cannot produce."""
    with caplog.at_level(logging.WARNING):
        Settings.from_yaml(ROOT / "examples" / "config.yaml")
        Settings.from_yaml(ROOT / "configs" / "client.yaml")
    assert "unrecognised" not in caplog.text


def test_every_framework_the_shipped_config_names_is_one_the_mapper_knows():
    """A config naming a framework the mapper does not recognise would load
    cleanly and then map nothing."""
    from threat_inspector.utils.compliance import get_compliance_mappings

    settings = Settings.from_yaml(ROOT / "configs" / "client.yaml")
    for framework in settings.compliance_frameworks:
        assert get_compliance_mappings("Weak SSL cipher and missing patch", [framework]), (
            f"{framework} maps nothing"
        )


# ---------------------------------------------------------------------------
# Both shapes
# ---------------------------------------------------------------------------


def test_the_report_shape_supplies_frameworks_and_formats(write_config):
    path = write_config(
        {"report": {"formats": ["json"], "compliance_frameworks": ["hipaa", "soc2"]}}
    )
    settings = Settings.from_yaml(path)
    assert settings.compliance_frameworks == ["hipaa", "soc2"]
    assert settings.reports.default_formats == ["json"]


def test_the_compliance_and_output_shape_still_works(write_config):
    path = write_config(
        {"compliance": {"frameworks": ["nist"]}, "output": {"formats": ["csv"], "directory": "/x"}}
    )
    settings = Settings.from_yaml(path)
    assert settings.compliance_frameworks == ["nist"]
    assert settings.reports.default_formats == ["csv"]
    assert settings.reports.output_dir == Path("/x")


def test_an_explicit_compliance_block_wins_over_the_report_block(write_config):
    """Both shapes in one file is ambiguous; the more specific one decides."""
    path = write_config(
        {
            "compliance": {"frameworks": ["nist"]},
            "report": {"compliance_frameworks": ["hipaa"]},
        }
    )
    assert Settings.from_yaml(path).compliance_frameworks == ["nist"]


def test_logging_settings_are_read(write_config):
    path = write_config({"logging": {"level": "DEBUG", "file": "/var/log/ti.log"}})
    settings = Settings.from_yaml(path)
    assert settings.log_level == "DEBUG"
    assert settings.log_file == Path("/var/log/ti.log")


def test_a_logging_block_without_a_file_leaves_it_unset(write_config):
    path = write_config({"logging": {"level": "WARNING"}})
    settings = Settings.from_yaml(path)
    assert settings.log_level == "WARNING"
    assert settings.log_file is None


def test_the_remediation_engine_and_model_are_read(write_config):
    path = write_config({"remediation": {"engine": "ollama", "model": "llama3"}})
    settings = Settings.from_yaml(path)
    assert settings.remediation.engine == "ollama"
    assert settings.remediation.ollama_model == "llama3"


def test_domains_are_carried_through(write_config):
    path = write_config({"domains": [{"name": "acme.com", "ips": ["10.0.0.1"]}]})
    assert Settings.from_yaml(path).domains[0]["name"] == "acme.com"


# ---------------------------------------------------------------------------
# A config that does nothing must say so
# ---------------------------------------------------------------------------


def test_an_unrecognised_section_is_warned_about(write_config, caplog):
    """A key nobody reads looks exactly like a key that was applied. That is
    how HIPAA and SOC 2 went missing from a client's report for so long."""
    path = write_config({"reporting": {"formats": ["json"]}})
    with caplog.at_level(logging.WARNING):
        Settings.from_yaml(path)
    assert "reporting" in caplog.text
    assert "unrecognised" in caplog.text


def test_the_warning_names_the_sections_that_do_work(write_config, caplog):
    path = write_config({"nonsense": {}})
    with caplog.at_level(logging.WARNING):
        Settings.from_yaml(path)
    for known in ("client", "compliance", "output", "report", "logging"):
        assert known in caplog.text


def test_scan_files_is_not_warned_about(write_config, caplog):
    """It is read by .github/workflows/vuln-report.yml rather than by Settings,
    so warning about it would cry wolf."""
    path = write_config({"scan_files": {"qualys": "scans/q.xlsx"}})
    with caplog.at_level(logging.WARNING):
        Settings.from_yaml(path)
    assert "scan_files" not in caplog.text


def test_a_recognised_section_is_not_warned_about(write_config, caplog):
    path = write_config({"client": {"name": "Acme"}, "report": {"formats": ["json"]}})
    with caplog.at_level(logging.WARNING):
        Settings.from_yaml(path)
    assert "unrecognised" not in caplog.text


# ---------------------------------------------------------------------------
# Degenerate files
# ---------------------------------------------------------------------------


def test_a_missing_file_falls_back_to_defaults(tmp_path):
    settings = Settings.from_yaml(tmp_path / "nope.yaml")
    assert settings.compliance_frameworks == ["pci-dss"]


def test_an_empty_file_falls_back_to_defaults(tmp_path):
    path = tmp_path / "empty.yaml"
    path.write_text("", encoding="utf-8")
    assert Settings.from_yaml(path).compliance_frameworks == ["pci-dss"]


def test_a_file_with_only_comments_falls_back_to_defaults(tmp_path):
    path = tmp_path / "comments.yaml"
    path.write_text("# nothing here\n", encoding="utf-8")
    assert Settings.from_yaml(path).client_name is None


def test_a_client_block_without_a_name_is_not_an_error(write_config):
    path = write_config({"client": {"contact_email": "x@example.invalid"}})
    assert Settings.from_yaml(path).client_name is None
