"""
registry.py — discover modules and resolve selections.

Selection is the whole point of the reframe: run one module, a few, or a named
group. This resolves --modules a,b,c and --group deep into the actual module set,
and powers the dashboard's checkboxes + group presets from the same source.
"""
from __future__ import annotations
import importlib
import inspect
import pkgutil
from base import ScanModule


def discover(package: str = "modules") -> dict[str, ScanModule]:
    """Import every module file in the package, instantiate each ScanModule."""
    pkg = importlib.import_module(package)
    found: dict[str, ScanModule] = {}
    for _, modname, _ in pkgutil.iter_modules(pkg.__path__):
        sub = importlib.import_module(f"{package}.{modname}")
        for _, obj in inspect.getmembers(sub, inspect.isclass):
            if issubclass(obj, ScanModule) and obj is not ScanModule:
                inst = obj()
                if not inst.name:
                    raise ValueError(f"{obj.__name__} has no name")
                found[inst.name] = inst
    return found


def all_groups(reg: dict[str, ScanModule]) -> set[str]:
    return {g for m in reg.values() for g in m.groups}


def select(reg: dict[str, ScanModule],
           modules: list[str] | None = None,
           group: str | None = None) -> list[ScanModule]:
    """Resolve a selection. --modules wins if given; else --group; else 'standard'."""
    if modules:
        missing = [m for m in modules if m not in reg]
        if missing:
            raise KeyError(f"unknown modules: {', '.join(missing)}")
        return [reg[m] for m in modules]

    grp = group or "standard"
    chosen = [m for m in reg.values() if grp in m.groups]
    if not chosen:
        raise KeyError(f"no modules in group {grp!r}; groups: {sorted(all_groups(reg))}")
    return chosen


def catalog(reg: dict[str, ScanModule]) -> list[dict]:
    """Machine-readable module list for --list-modules and the dashboard."""
    return [
        {"name": m.name, "description": m.description,
         "target_kinds": list(m.target_kinds), "groups": list(m.groups)}
        for m in sorted(reg.values(), key=lambda x: x.name)
    ]
