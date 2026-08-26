#!/usr/bin/env python3
"""Build dashboard/public/catalog.json from the live module registries.

The dashboard renders its module checkboxes and group presets from this file, so
UI selection maps 1:1 onto `--modules` / `--group`. Generating it from
`registry.catalog()` is what keeps the CLI and the UI from drifting apart —
tests/test_catalog.py fails the build if the committed file goes stale.

WHITE-LABEL GATE: internal module names (and some file extensions) name the
underlying tools. Those names are fine in code and CLI output, which are internal,
but must never reach a client-facing surface. Every module therefore needs an
entry in LABELS below; a module without one raises rather than silently shipping
its internal name to the browser.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "dashboard" / "public" / "catalog.json"

# Client-facing label for every module. Iron City branding only — no tool names.
LABELS: dict[str, str] = {
    # active scanners
    "cve_lookup": "Known Vulnerability Correlation",
    "default_creds_check": "Default Credential Exposure",
    "header_security_check": "Security Header Review",
    "port_scan": "Network Exposure",
    "service_fingerprint": "Service Identification",
    "subdomain_enum": "Attack Surface Discovery",
    "tls_cert_check": "Transport Security",
    "web_vuln_scan": "Web Application Testing",
    # file ingestion
    "nessus_ingest": "Vulnerability Scan Import",
    "nmap_ingest": "Network Scan Import",
    "qualys_compliance_ingest": "Compliance Export Import",
    "qualys_ingest": "Vulnerability Export Import",
    "zap_ingest": "Web Application Scan Import",
}

# Client-facing description, used where the module's internal description would
# name a tool or a tool-specific file extension. Modules absent from this map keep
# their registry description, which the white-label test verifies is already clean.
DESCRIPTIONS: dict[str, str] = {
    "nessus_ingest": "Imports findings from an existing vulnerability assessment export.",
    "nmap_ingest": "Imports host and service data from an existing network discovery export.",
    "qualys_compliance_ingest": "Imports control results from an existing compliance export.",
    "qualys_ingest": "Imports findings from an existing spreadsheet vulnerability export.",
    "zap_ingest": "Imports findings from an existing web application assessment export.",
}

# Group presets, in the order the dashboard shows them.
GROUP_ORDER = ["quick", "standard", "deep", "ingest"]
GROUP_LABELS = {
    "quick": "Quick",
    "standard": "Standard",
    "deep": "Deep",
    "ingest": "Import",
}


def _run(script: str) -> dict:
    """Ask an entry point for its own catalog. Never re-derive it here."""
    proc = subprocess.run(
        [sys.executable, str(ROOT / "module_framework" / script), "--list-modules"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        # Surface the real reason. A bare CalledProcessError hides the import
        # error that actually broke it, which is almost always a missing
        # dependency on a clean checkout.
        raise SystemExit(
            f"{script} --list-modules failed (exit {proc.returncode}):\n{proc.stderr.strip()}"
        )
    return json.loads(proc.stdout)


def build() -> dict:
    scan = _run("cli.py")
    files = _run("ingest.py")

    modules = []
    missing = []
    for entry in scan["modules"] + files["modules"]:
        label = LABELS.get(entry["name"])
        if not label:
            missing.append(entry["name"])
            continue
        modules.append(
            {
                **entry,
                "label": label,
                "description": DESCRIPTIONS.get(entry["name"], entry["description"]),
            }
        )

    if missing:
        raise SystemExit(
            "white-label gate: no client-facing label for "
            + ", ".join(sorted(missing))
            + "\nAdd one to LABELS in tools/build_catalog.py before it reaches the UI."
        )

    modules.sort(key=lambda m: m["label"])
    groups = sorted(
        {g for m in modules for g in m["groups"]},
        key=lambda g: GROUP_ORDER.index(g) if g in GROUP_ORDER else 99,
    )
    return {
        "modules": modules,
        "groups": [{"name": g, "label": GROUP_LABELS.get(g, g.title())} for g in groups],
    }


if __name__ == "__main__":
    data = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, indent=2) + "\n")
    print(
        f"wrote {OUT.relative_to(ROOT)}: {len(data['modules'])} modules, {len(data['groups'])} groups"
    )
