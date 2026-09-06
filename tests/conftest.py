"""Deterministic import paths for the whole test suite.

The three import roots this project tests across are not installed packages:

  src/               the `threat_inspector` library (parsers, core, reports)
  module_framework/  the framework's FLAT imports (`base`, `registry`, `targets`)
  tools/             `build_catalog`, exercised by tests/test_catalog.py

Before this file existed each test module inserted the roots it happened to need
at import time, which meant the suite only passed because collection is
alphabetical: `test_file_modules.py` sorts ahead of `test_parsers.py` and put
`src/` on the path as a side effect of being imported first. Running one file on
its own (`pytest tests/test_parsers.py`), filtering with `-k`, or any reordering
(pytest-randomly, xdist) aborted the ENTIRE run with a collection error:

    ModuleNotFoundError: No module named 'threat_inspector'

conftest.py is imported before any test module, so doing it once here makes the
path independent of collection order.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# module_framework/ first: its flat modules (base, registry, targets) are what
# `modules.*` and `file_modules.*` import by bare name at runtime, exactly as the
# CLI entry points set it up.
for _root in ("module_framework", "src", "tools"):
    _path = str(ROOT / _root)
    if _path not in sys.path:
        sys.path.insert(0, _path)
