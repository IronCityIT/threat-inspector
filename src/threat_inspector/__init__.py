"""
Iron City Threat Inspector
Advanced Vulnerability Assessment & Remediation Platform

Copyright (c) 2024 Iron City IT Advisors

`ThreatInspector` and `Settings` are resolved lazily (PEP 562). Importing them
eagerly pulled `core` -> `config` -> pydantic-settings into EVERY consumer of
this package, including `threat_inspector.parsers`, which the scan framework
imports just to reach the parser base classes. The public API is unchanged --
`from threat_inspector import ThreatInspector` still works -- but a caller that
only wants the parsers no longer pays for the settings/ORM stack.
"""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from threat_inspector.config import Settings
    from threat_inspector.core import ThreatInspector

__version__ = "1.0.0"
__author__ = "Iron City IT Advisors"
__all__ = ["ThreatInspector", "Settings"]

_LAZY = {
    "ThreatInspector": ("threat_inspector.core", "ThreatInspector"),
    "Settings": ("threat_inspector.config", "Settings"),
}


def __getattr__(name: str) -> Any:
    target = _LAZY.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    value = getattr(importlib.import_module(target[0]), target[1])
    globals()[name] = value  # cache so the lookup happens once
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY))
