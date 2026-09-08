"""Where a client's remediation advice comes from.

`generate_remediation` produces the text that tells a client what to DO about a
finding. It is rendered verbatim in the report — `core.py` assigns
`result.guidance` to `vuln.solution` and nothing else survives — so provenance
matters as much as content. The module sat at 57% coverage.

The defect that mattered: **the default engine was `local`, and `local` meant
gpt2.**

```
Settings().remediation.engine  -> 'local'
_generate_local  ->  transformers.pipeline("text-generation", model="gpt2")
core.py:257      ->  vuln.solution = result.guidance
```

It was inert only by accident — `transformers` is not in `requirements.txt` —
but `pyproject.toml` offered an `ai` extra that installs it, so
`pip install threat-inspector[ai]` silently made a 2019 general-purpose language
model the source of security remediation advice in client-facing reports. Text
gpt2 produces about fixing a vulnerability is fluent and unfounded, which is the
worst possible combination for that particular field.

Two more of the same shape as the rest of this pass:

  * `openai` and `anthropic` were configurable — with `OPENAI_API_KEY` and
    `ANTHROPIC_API_KEY` environment aliases — and implemented nowhere. An
    operator who configured one got generic boilerplate and no indication that
    their engine had never run.
  * Model output reached the report unmarked, so a client could not tell
    curated advice from generated advice.
"""

from __future__ import annotations

import logging

import pytest

from threat_inspector.config import RemediationSettings
from threat_inspector.utils.remediation import (
    IMPLEMENTED_ENGINES,
    MODEL_GUIDANCE_NOTICE,
    STATIC_ENGINE,
    RemediationResult,
    _build_prompt,
    _labelled,
    generate_remediation,
    get_static_remediation,
)

# ---------------------------------------------------------------------------
# No model by default, and no gpt2 at all
# ---------------------------------------------------------------------------


def test_the_default_engine_uses_no_model():
    """It used to be "local", which meant gpt2."""
    assert RemediationSettings().engine == STATIC_ENGINE


def test_gpt2_is_gone():
    """A 2019 general-purpose language model is not a source of security
    remediation advice, and it was the default."""
    import threat_inspector.utils.remediation as remediation

    source = remediation.__file__ and __import__("pathlib").Path(remediation.__file__).read_text()
    # The word appears in the module docstring explaining the removal; what must
    # not exist is a code path that calls it.
    assert not hasattr(remediation, "_generate_local")
    assert 'model="gpt2"' not in source


def test_transformers_is_no_longer_imported_anywhere():
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    offenders = [
        path
        for path in (root / "src").rglob("*.py")
        if "import transformers" in path.read_text() or "from transformers" in path.read_text()
    ]
    assert offenders == []


def test_the_engines_that_exist_are_the_ones_named():
    assert IMPLEMENTED_ENGINES == (STATIC_ENGINE, "ollama")


# ---------------------------------------------------------------------------
# Precedence: the scanner's own text first
# ---------------------------------------------------------------------------


def test_a_substantial_scanner_solution_is_used_as_is():
    fix = "Upgrade nginx to 1.18.1, disable TLS 1.0, and restart the service."
    result = generate_remediation("Weak cipher", existing_solution=fix)
    assert result.guidance == fix
    assert result.source == "scanner"


def test_a_curated_entry_is_used_when_the_scanner_gave_nothing():
    result = generate_remediation("SQL Injection in login form")
    assert result.source == "static"
    assert "parameterized queries" in result.guidance


def test_an_unrecognised_finding_falls_back_to_generic_steps():
    result = generate_remediation("Some entirely novel observation", severity="high")
    assert result.source == "generic"
    assert "Prioritize remediation within 7 days" in result.guidance


@pytest.mark.parametrize(
    ("severity", "phrase"),
    [
        ("critical", "Immediate action required"),
        ("high", "within 7 days"),
        ("medium", "within 30 days"),
        ("low", "next maintenance window"),
        ("info", "Review and assess risk"),
    ],
)
def test_generic_guidance_states_an_urgency_matched_to_severity(severity, phrase):
    assert phrase in generate_remediation("Novel finding", severity=severity).guidance


def test_an_unknown_severity_does_not_invent_an_urgency():
    assert generate_remediation("Novel finding", severity="banana").guidance.strip()


def test_curated_lookup_is_case_insensitive():
    assert get_static_remediation("SQL INJECTION") == get_static_remediation("sql injection")


def test_a_title_matching_nothing_curated_returns_nothing():
    assert get_static_remediation("An entirely novel observation") is None


# ---------------------------------------------------------------------------
# An engine that does not exist must say so
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("engine", ["openai", "anthropic", "local", "gpt2", "nonsense"])
def test_an_unimplemented_engine_warns_rather_than_pretending(engine, monkeypatch, caplog):
    """Silently falling back means an operator who configured an engine gets
    boilerplate and believes their model wrote it."""
    monkeypatch.setenv("REMEDIATION_ENGINE", engine)
    _clear_settings_cache(monkeypatch)

    with caplog.at_level(logging.WARNING):
        result = generate_remediation("Some novel finding")

    assert result.source == "generic"
    assert engine in caplog.text
    assert "not implemented" in caplog.text


def test_the_warning_names_the_engines_that_do_work(monkeypatch, caplog):
    monkeypatch.setenv("REMEDIATION_ENGINE", "openai")
    _clear_settings_cache(monkeypatch)
    with caplog.at_level(logging.WARNING):
        generate_remediation("Some novel finding")
    for engine in IMPLEMENTED_ENGINES:
        assert engine in caplog.text


def test_the_static_engine_does_not_warn(monkeypatch, caplog):
    monkeypatch.setenv("REMEDIATION_ENGINE", STATIC_ENGINE)
    _clear_settings_cache(monkeypatch)
    with caplog.at_level(logging.WARNING):
        generate_remediation("Some novel finding")
    assert "not implemented" not in caplog.text


def _patch_ollama(monkeypatch, replacement):
    """Replace the Ollama call in the namespace generate_remediation resolves from.

    NOT `monkeypatch.setattr(remediation, "_generate_ollama", ...)`. Several
    suites here delete `threat_inspector*` from sys.modules to get a freshly
    imported app, so the module object a later import returns can be a different
    one from the module `generate_remediation` actually belongs to — and
    patching that one changes nothing. This test passed alone and failed in the
    full suite until it reached through `__globals__`, which is the same
    order-dependence conftest.py exists to fix.
    """
    monkeypatch.setitem(generate_remediation.__globals__, "_generate_ollama", replacement)


def _clear_settings_cache(monkeypatch):
    """`settings` is a module-level singleton built at import time."""
    import threat_inspector.config as config

    monkeypatch.setattr(config, "settings", config.Settings())


# ---------------------------------------------------------------------------
# Model output is labelled before it reaches a client
# ---------------------------------------------------------------------------


def test_model_guidance_is_marked_as_generated():
    """`source` alone does not survive to the report: core.py assigns
    `result.guidance` to `vuln.solution` and the report renders that field and
    nothing else. The label has to be in the text."""
    labelled = _labelled(RemediationResult(guidance="Do the thing.", source="ollama"))
    assert labelled.guidance.startswith(MODEL_GUIDANCE_NOTICE)
    assert "Do the thing." in labelled.guidance


def test_the_notice_tells_a_reader_to_check_it():
    assert "review" in MODEL_GUIDANCE_NOTICE.lower()


def test_labelling_is_idempotent():
    once = _labelled(RemediationResult(guidance="x", source="ollama"))
    twice = _labelled(once)
    assert twice.guidance == once.guidance


def test_labelling_preserves_source_and_confidence():
    original = RemediationResult(guidance="x", source="ollama", confidence=0.85)
    labelled = _labelled(original)
    assert labelled.source == "ollama"
    assert labelled.confidence == 0.85


def test_curated_guidance_is_not_labelled_as_generated():
    """A person wrote these. Marking them "generated" would be a lie in the
    other direction."""
    assert MODEL_GUIDANCE_NOTICE not in generate_remediation("SQL Injection").guidance


def test_generic_guidance_is_not_labelled_as_generated():
    result = generate_remediation("Some novel finding")
    assert MODEL_GUIDANCE_NOTICE not in result.guidance


def test_scanner_guidance_is_not_labelled_as_generated():
    fix = "Upgrade nginx to 1.18.1, disable TLS 1.0, and restart the service."
    assert MODEL_GUIDANCE_NOTICE not in generate_remediation("x", existing_solution=fix).guidance


# ---------------------------------------------------------------------------
# Configuration for engines that do not exist
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field", ["openai_api_key", "openai_model", "anthropic_api_key", "anthropic_model"]
)
def test_settings_for_unimplemented_engines_are_gone(field):
    """These carried OPENAI_API_KEY and ANTHROPIC_API_KEY environment aliases,
    inviting a deployment to hold credentials for a code path that could never
    use them. Neither name is on the approved secret list in CLAUDE.md."""
    assert not hasattr(RemediationSettings(), field)


def test_the_ollama_settings_remain():
    settings = RemediationSettings()
    assert settings.ollama_host
    assert settings.ollama_model


# ---------------------------------------------------------------------------
# The Ollama path — dispatch and labelling, without an Ollama
# ---------------------------------------------------------------------------


def test_a_configured_model_is_used_and_its_output_is_labelled(monkeypatch, caplog):
    """The end-to-end version of the labelling claim: through
    generate_remediation, not just the helper."""
    monkeypatch.setenv("REMEDIATION_ENGINE", "ollama")
    _clear_settings_cache(monkeypatch)
    _patch_ollama(
        monkeypatch,
        lambda *a, **k: RemediationResult(guidance="Restart the service.", source="ollama"),
    )

    with caplog.at_level(logging.WARNING):
        result = generate_remediation("Some novel finding")

    assert result.source == "ollama"
    assert result.guidance.startswith(MODEL_GUIDANCE_NOTICE)
    assert "Restart the service." in result.guidance
    assert "not implemented" not in caplog.text


def test_a_model_that_is_unreachable_falls_back_to_deterministic_guidance(monkeypatch):
    """Ollama not running must degrade to curated steps, not to nothing."""
    monkeypatch.setenv("REMEDIATION_ENGINE", "ollama")
    _clear_settings_cache(monkeypatch)
    _patch_ollama(monkeypatch, lambda *a, **k: None)

    result = generate_remediation("Some novel finding", severity="high")
    assert result.source == "generic"
    assert MODEL_GUIDANCE_NOTICE not in result.guidance


def test_a_configured_model_still_loses_to_the_scanners_own_fix(monkeypatch):
    """Precedence is not negotiable: the scanner looked at the actual host."""
    monkeypatch.setenv("REMEDIATION_ENGINE", "ollama")
    _clear_settings_cache(monkeypatch)
    _patch_ollama(
        monkeypatch, lambda *a, **k: RemediationResult(guidance="Model text.", source="ollama")
    )

    fix = "Upgrade nginx to 1.18.1, disable TLS 1.0, and restart the service."
    result = generate_remediation("Weak cipher", existing_solution=fix)
    assert result.guidance == fix
    assert result.source == "scanner"


# ---------------------------------------------------------------------------
# The prompt, which is pure
# ---------------------------------------------------------------------------


def test_the_prompt_carries_the_finding_and_its_severity():
    prompt = _build_prompt("SQL Injection", "", "", "critical")
    assert "SQL Injection" in prompt
    assert "critical" in prompt


def test_the_prompt_includes_a_cve_when_there_is_one():
    assert "CVE-2021-44228" in _build_prompt("RCE", "", "CVE-2021-44228", "critical")


def test_the_prompt_omits_the_cve_line_when_there_is_none():
    assert "CVE:" not in _build_prompt("RCE", "", "", "critical")


def test_the_prompt_bounds_the_description_it_sends():
    """A scanner can echo a whole response body into a description; sending all
    of it to a model is a cost and a disclosure question, not just a size one."""
    prompt = _build_prompt("RCE", "x" * 5000, "", "high")
    assert "x" * 500 in prompt
    assert "x" * 600 not in prompt
