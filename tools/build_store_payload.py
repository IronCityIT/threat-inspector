#!/usr/bin/env python3
"""Build the storeScanResults payload from a scan's findings.json.

This used to live as an inline heredoc inside _consensus-store.yml, where it
could not be tested and a mistake was only visible in a live run. It is the step
that decides what a client is ultimately shown about their scan, so it gets the
same treatment as the rest of the pipeline: a real module with real tests
(tests/test_store_payload.py).

Usage (from the workflow):
    python3 tools/build_store_payload.py --findings incoming/findings.json \
        --out payload.json --scan-type modular_scan --scan-id ... \
        --client-id acme --client-name Acme --target example.com \
        --consensus-status success

White-label: `diagnostics` names Iron City module ids and carries parser/probe
error text. Module ids are internal Iron City identifiers, never vendor names.
"""

from __future__ import annotations

import argparse
import datetime
import json
from pathlib import Path
from typing import Any

# How many module errors travel on the record. A pathological run (say a /16 of
# targets x 8 modules) could otherwise produce a document too large for
# Firestore's 1 MiB limit, which would fail the write and lose the findings too.
MAX_ERRORS_ON_RECORD = 50


def summarize(findings: list[dict]) -> dict[str, int]:
    """Count findings by severity, plus a total."""
    summary: dict[str, int] = {"total": len(findings)}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        summary[sev] = summary.get(sev, 0) + 1
    return summary


def build_payload(scan: dict, meta: dict[str, str]) -> dict[str, Any]:
    """Turn a scan document + run metadata into the stored record.

    The important decision here is `status`. An empty findings list means
    "nothing found" OR "every capability failed", and the pipeline used to store
    a flat "completed" for both — which tells a client their estate is clean when
    in fact nothing was checked. The scan now reports its own health, and that
    survives to the record.
    """
    findings = scan.get("findings") or []
    scan_status = scan.get("status", "ok")
    module_errors = scan.get("errors") or []
    file_failures = scan.get("files_failed") or []

    # ok / partial / dry_run have real results behind them; failed does not.
    record_status = "failed" if scan_status == "failed" else "completed"

    payload: dict[str, Any] = {
        "scan_type": meta["scan_type"],
        "scan_id": meta["scan_id"],
        "client_id": meta["client_id"],
        "client_name": meta["client_name"],
        "target": meta["target"],
        "status": record_status,
        "scan_status": scan_status,
        "summary": summarize(findings),
        "findings": findings,
        "consensus": {"status": meta.get("consensus_status", "unknown")},
        "diagnostics": {
            "scan_status": scan_status,
            "modules_run": scan.get("modules_run") or [],
            "target_count": scan.get("target_count", 0),
            "module_errors": module_errors[:MAX_ERRORS_ON_RECORD],
            "module_error_count": len(module_errors),
            "files_failed": file_failures[:MAX_ERRORS_ON_RECORD],
            "rejected_targets": scan.get("rejected_targets") or [],
            "stats": scan.get("stats") or {},
        },
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    if record_status == "failed":
        payload["error"] = {
            "message": "every selected capability failed to run",
            "module_errors": module_errors[:MAX_ERRORS_ON_RECORD],
        }
    return payload


def load_scan(path: Path | None) -> dict:
    """Read the scan document, tolerating a missing artifact.

    A missing findings.json is not a reason to crash the store step: an empty,
    explicitly-flagged record is more useful to an operator than no record and a
    stack trace.
    """
    if path is None or not path.is_file():
        return {"findings": [], "modules_run": [], "target_count": 0, "status": "failed"}
    return json.loads(path.read_text())


def find_findings(root: Path) -> Path | None:
    """Locate findings.json inside a downloaded artifact directory."""
    if root.is_file():
        return root
    matches = sorted(root.rglob("findings.json"))
    return matches[0] if matches else None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="build-store-payload")
    p.add_argument("--findings", required=True, help="findings.json, or a directory holding it")
    p.add_argument("--out", required=True)
    p.add_argument("--scan-type", required=True)
    p.add_argument("--scan-id", required=True)
    p.add_argument("--client-id", required=True)
    p.add_argument("--client-name", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--consensus-status", default="unknown")
    args = p.parse_args(argv)

    scan = load_scan(find_findings(Path(args.findings)))
    payload = build_payload(
        scan,
        {
            "scan_type": args.scan_type,
            "scan_id": args.scan_id,
            "client_id": args.client_id,
            "client_name": args.client_name,
            "target": args.target,
            "consensus_status": args.consensus_status,
        },
    )
    Path(args.out).write_text(json.dumps(payload))

    summary = payload["summary"]
    diag = payload["diagnostics"]
    print(
        f"Payload built: {summary['total']} findings, scan_status={payload['scan_status']}, "
        f"{diag['module_error_count']} module error(s), client_id={payload['client_id']}"
    )
    if payload["scan_status"] != "ok":
        print(
            f"::warning::scan reported status '{payload['scan_status']}' — "
            "see diagnostics on the stored record"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
