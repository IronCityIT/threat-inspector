"""Compliance mappings: what a client's report ends up claiming.

`get_compliance_mappings` turns a finding's title into PCI-DSS, HIPAA, SOC 2 and
NIST 800-53 requirement references, and those references are rendered in the
client-facing report. It sat at 62% coverage with two defects, and both change
what a report says:

  1. **Asking for a framework by its own name selected nothing.** Normalisation
     stripped hyphens and underscores but not spaces, then compared for exact
     membership — so `frameworks=["NIST 800-53"]`, the exact string these
     mappings use and the one a person writes in a config file, matched no key
     and contributed **no mappings at all**, silently.
  2. **A keyword matched any word containing it.** "Dispatcher
     misconfiguration" was mapped to patch-management requirements on the
     strength of "dis-PATCH-er" — a compliance claim about a finding that has
     nothing to do with patching.

The fix for (2) is narrower than it looks, and the first attempt was wrong in an
instructive way: anchoring keywords to a word boundary does kill "dispatcher",
and also kills "un-PATCH-ed" and "Open-SSL", which are real mappings. On a
compliance report a missing true mapping is worse than an extra one, so
substring matching is kept and the known false matches are named explicitly.
That trade is what most of this file pins.
"""

from __future__ import annotations

import logging

import pytest

from threat_inspector.utils.compliance import (
    DEFAULT_FRAMEWORKS,
    KNOWN_FRAMEWORKS,
    format_compliance_tags,
    get_compliance_mappings,
)


def tags(title: str, frameworks=None) -> set[str]:
    return set(format_compliance_tags(get_compliance_mappings(title, frameworks)))


# ---------------------------------------------------------------------------
# Asking for a framework by name
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["nist", "NIST", "nist-800-53", "NIST 800-53", "nist_800_53", "NIST800-53", " nist "],
)
def test_nist_is_selected_however_its_name_is_written(name):
    """The regression. `["NIST 800-53"]` — the name these mappings themselves
    use — produced nothing at all before the fix."""
    assert "NIST 800-53-SI-2" in tags("Missing patch", [name])


@pytest.mark.parametrize("name", ["pci-dss", "PCI-DSS", "pci_dss", "PCI DSS", "pcidss", "pci"])
def test_pci_is_selected_however_its_name_is_written(name):
    assert "PCI-DSS-6.3.3" in tags("Missing patch", [name])


@pytest.mark.parametrize("name", ["soc2", "SOC2", "SOC 2", "soc-2"])
def test_soc2_is_selected_however_its_name_is_written(name):
    assert "SOC2-CC6.7" in tags("Weak SSL cipher", [name])


@pytest.mark.parametrize("name", ["hipaa", "HIPAA", "HiPaa"])
def test_hipaa_is_selected_however_its_name_is_written(name):
    assert "HIPAA-164.312(e)(1)" in tags("Weak SSL cipher", [name])


def test_asking_for_one_framework_does_not_return_another(name="pci-dss"):
    assert all(t.startswith("PCI-DSS") for t in tags("Weak SSL cipher", [name]))


def test_every_documented_framework_name_actually_works():
    """KNOWN_FRAMEWORKS is what an unknown-framework warning tells the caller to
    use, so each of those names has to select something."""
    for name in KNOWN_FRAMEWORKS:
        assert tags("Weak SSL cipher and missing patch", [name]), f"{name} selected nothing"


def test_the_default_frameworks_are_all_recognised():
    for name in DEFAULT_FRAMEWORKS:
        assert tags("Weak SSL cipher", [name]) or tags("Missing patch", [name])


def test_an_unknown_framework_is_warned_about_rather_than_ignored(caplog):
    """Silently contributing nothing is how a report ends up claiming a
    framework was considered when it never was."""
    with caplog.at_level(logging.WARNING):
        result = tags("Weak SSL cipher", ["iso27001"])
    assert result == set()
    assert "iso27001" in caplog.text
    assert "unknown compliance framework" in caplog.text


def test_an_unknown_framework_does_not_suppress_the_known_ones(caplog):
    with caplog.at_level(logging.WARNING):
        result = tags("Weak SSL cipher", ["iso27001", "pci-dss"])
    assert "PCI-DSS-4.2.1" in result


def test_no_frameworks_requested_means_all_of_them():
    everything = tags("Weak SSL cipher and missing patch")
    assert {t.split("-")[0] for t in everything} >= {"PCI"}
    assert any(t.startswith("HIPAA") for t in everything)
    assert any(t.startswith("SOC2") for t in everything)
    assert any(t.startswith("NIST") for t in everything)


def test_an_empty_framework_list_maps_nothing():
    assert tags("Weak SSL cipher", []) == set()


# ---------------------------------------------------------------------------
# A keyword must not match a word that merely contains it
# ---------------------------------------------------------------------------


def test_a_dispatcher_finding_is_not_a_patching_finding():
    """The regression: "dis-PATCH-er" mapped to patch-management requirements."""
    result = tags("Dispatcher misconfiguration")
    assert "PCI-DSS-6.3.3" not in result
    assert "NIST 800-53-SI-2" not in result


def test_a_dispatcher_finding_still_maps_on_its_own_merits():
    """Removing the false match must not remove the true ones in the same title."""
    assert "NIST 800-53-CM-6" in tags("Dispatcher misconfiguration")


@pytest.mark.parametrize("title", ["Unpatched OpenSSL", "Missing patches on host", "Patch missing"])
def test_the_inflections_that_matter_still_map(title):
    """Anchoring keywords to a word boundary would have killed these. On a
    compliance report a missing true mapping is worse than an extra one."""
    assert "PCI-DSS-6.3.3" in tags(title)


def test_ssl_still_matches_inside_openssl():
    """ "OpenSSL" is a transmission-encryption finding, and a word-boundary rule
    would have dropped every one of these."""
    result = tags("Unpatched OpenSSL")
    assert "PCI-DSS-4.2.1" in result
    assert "HIPAA-164.312(e)(1)" in result
    assert "SOC2-CC6.7" in result


# ---------------------------------------------------------------------------
# The mapping itself
# ---------------------------------------------------------------------------


def test_a_sql_injection_maps_to_the_injection_requirement():
    assert "PCI-DSS-6.5.1" in tags("SQL Injection in login form")


def test_cross_site_scripting_maps_under_both_spellings():
    assert "PCI-DSS-6.5.7" in tags("Reflected XSS")
    assert "PCI-DSS-6.5.7" in tags("Cross-Site Scripting")


def test_matching_is_case_insensitive():
    assert tags("WEAK SSL CIPHER") == tags("weak ssl cipher")


def test_a_title_matching_nothing_maps_to_nothing():
    assert tags("An entirely unremarkable observation") == set()


def test_an_empty_title_is_not_an_error():
    assert get_compliance_mappings("") == []


def test_a_requirement_is_never_listed_twice():
    """Several keywords in one title can select the same requirement — "patch"
    and "vulnerability" both reach PCI 11.3.1."""
    mappings = get_compliance_mappings("Patch missing for known vulnerability")
    keys = [(m.framework, m.requirement) for m in mappings]
    assert len(keys) == len(set(keys))


def test_each_mapping_carries_a_framework_requirement_and_description():
    for mapping in get_compliance_mappings("Weak SSL cipher"):
        assert mapping.framework
        assert mapping.requirement
        assert mapping.description


def test_tags_render_as_framework_and_requirement():
    assert format_compliance_tags(get_compliance_mappings("SQL Injection")) == [
        "PCI-DSS-6.2.4",
        "PCI-DSS-6.5.1",
    ]


def test_tags_of_nothing_is_an_empty_list():
    assert format_compliance_tags([]) == []
