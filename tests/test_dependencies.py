"""Dependency hygiene for the scan runner.

This is a security product: its scan runner handles client data, so every
package installed there is supply-chain surface. requirements.txt used to
mandate the local-AI stack — torch, transformers, nltk, scikit-learn, ollama —
which meant ~1.7 GB of torch and CUDA wheels downloaded on every CI job that
installed it (three of them), for code the scanner never calls.

Measured from the CI log of run 33554719630:
    torch          526.6 MB
    nvidia_cublas  423.1 MB
    nvidia_cufft   214.1 MB
    ... 8 more CUDA wheels
    total        ~1,715 MB

These tests keep that from creeping back, and keep the two entry points honest
about what they actually need.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Never required to scan, ingest, or report.
OPTIONAL_AI_PACKAGES = {"torch", "transformers", "nltk", "scikit-learn", "ollama"}


def declared(path: Path) -> set[str]:
    """Package names declared in a requirements file (ignoring -r includes)."""
    names = set()
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        names.add(re.split(r"[<>=!~\[]", line)[0].strip().lower())
    return names


def test_the_ai_stack_is_not_a_mandatory_runtime_dependency():
    """A scan runner must not be made to install a GPU compute stack it never
    calls. If a feature genuinely needs one, put it in requirements-ai.txt."""
    mandatory = declared(ROOT / "requirements.txt")
    leaked = mandatory & OPTIONAL_AI_PACKAGES
    assert not leaked, (
        f"{sorted(leaked)} is back in requirements.txt. "
        "The scanner does not import it; put it in requirements-ai.txt."
    )


def test_the_optional_stack_is_still_installable():
    """Removed from the default set, not deleted — the feature still exists."""
    optional = ROOT / "requirements-ai.txt"
    assert optional.is_file(), "requirements-ai.txt is missing"
    assert OPTIONAL_AI_PACKAGES <= declared(optional)


def test_requirements_and_pyproject_agree_on_what_is_optional():
    """pyproject.toml has always classified these as an `ai` extra. Before this
    change requirements.txt contradicted it, and requirements.txt is what CI
    and the workflows actually install."""
    pyproject = (ROOT / "pyproject.toml").read_text()
    ai_extra = re.search(r"^ai\s*=\s*\[(.*?)\]", pyproject, re.S | re.M)
    assert ai_extra, "pyproject.toml no longer declares an `ai` extra"
    extra_names = set(re.findall(r'"([A-Za-z0-9_.-]+)', ai_extra.group(1)))
    mandatory = declared(ROOT / "requirements.txt")
    assert not (extra_names & mandatory), (
        "a package is optional in pyproject.toml but mandatory in requirements.txt"
    )


def _third_party_imports(path: Path) -> set[str]:
    """Top-level module names imported at MODULE scope (not inside functions)."""
    tree = ast.parse(path.read_text())
    found: set[str] = set()
    for node in tree.body:  # module scope only — lazy imports are the point
        if isinstance(node, ast.Import):
            found.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module.split(".")[0])
    return found


@pytest.mark.parametrize("entry", ["cli.py", "ingest.py"])
def test_entry_points_do_not_import_the_ai_stack_at_module_scope(entry):
    imported = _third_party_imports(ROOT / "module_framework" / entry)
    assert not (imported & OPTIONAL_AI_PACKAGES)


def test_scan_entry_point_needs_no_third_party_package_at_all():
    """cli.py drives the active scanners using only the standard library and the
    framework's own flat modules. That is worth keeping: it is what lets a scan
    run on a minimal runner."""
    imported = _third_party_imports(ROOT / "module_framework" / "cli.py")
    stdlib = {
        "argparse",
        "json",
        "logging",
        "os",
        "sys",
        "time",
        "pathlib",
        "__future__",
    }
    local = {"registry", "base", "targets"}
    assert imported <= (stdlib | local), (
        f"unexpected import(s): {sorted(imported - stdlib - local)}"
    )


def test_the_ai_code_path_degrades_without_its_packages():
    """transformers/ollama are imported lazily inside try/except, so an
    uninstalled optional stack costs one feature rather than breaking the run."""
    import sys

    sys.path.insert(0, str(ROOT / "src"))
    from threat_inspector.utils.remediation import generate_remediation

    result = generate_remediation("SQL Injection", "Synthetic fixture", "", "high")
    assert result.guidance, "remediation must still return guidance with no AI stack installed"
