"""The dashboard catalog must stay in lockstep with the registries, and must
never carry an underlying tool's name to a client-facing surface."""

from __future__ import annotations

import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import build_catalog  # noqa: E402

CATALOG = ROOT / "dashboard" / "public" / "catalog.json"

# Names of the underlying scanners. Internal code and CLI output may use them;
# anything the dashboard renders may not.
TOOL_NAMES = [
    "nessus",
    "qualys",
    "nmap",
    "nuclei",
    "subfinder",
    "zap",
    "openvas",
    "burp",
    "wazuh",
    "prowler",
    "puppeteer",
    "selenium",
    "metasploit",
]


def test_committed_catalog_matches_registry():
    """A stale catalog.json means the UI offers modules the CLI does not have."""
    assert CATALOG.exists(), "catalog.json missing — run tools/build_catalog.py"
    committed = json.loads(CATALOG.read_text())
    assert committed == build_catalog.build(), (
        "catalog.json is stale — re-run: python3 tools/build_catalog.py"
    )


def test_every_module_has_a_client_facing_label():
    catalog = json.loads(CATALOG.read_text())
    for module in catalog["modules"]:
        assert module.get("label"), f"{module['name']} has no client-facing label"


@pytest.mark.parametrize("field", ["label", "description"])
def test_rendered_fields_never_name_a_tool(field):
    """`label` and `description` are what the dashboard shows. They must be clean.

    `name` and `extensions` are deliberately NOT checked: `name` is the CLI
    identifier (internal, and what --modules takes), and `extensions` feeds
    internal file handling. Neither may be rendered — the Playwright DOM test
    in tests/ui is what enforces that at the surface.
    """
    catalog = json.loads(CATALOG.read_text())
    for module in catalog["modules"]:
        value = module[field].lower()
        for tool in TOOL_NAMES:
            assert tool not in value, f"{module['name']}.{field} names a tool: {tool!r}"


def test_group_presets_are_selectable():
    """Every group the UI offers must contain at least one module, or the preset
    would select nothing and the scan would be a no-op."""
    catalog = json.loads(CATALOG.read_text())
    for group in catalog["groups"]:
        members = [m for m in catalog["modules"] if group["name"] in m["groups"]]
        assert members, f"group {group['name']} has no modules"
