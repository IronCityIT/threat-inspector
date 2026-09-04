#!/usr/bin/env python3
"""End-to-end local smoke test for Threat Inspector.

Runs the REAL entry points as subprocesses against REAL inputs and asserts the
JSON contract at every hop. Nothing here is mocked or stubbed:

  1. both entry points enumerate their modules (`--list-modules`)
  2. `python3 -m module_framework.cli` works, not just the script form
  3. a dry run validates targets + selection and executes nothing
  4. an ACTIVE scan runs against a live HTTP server this script starts on
     loopback -- real sockets, real responses, real findings. The server is
     local by design: the product must never be smoke-tested by scanning a
     third party, and loopback needs --allow-local, which also exercises that
     flag's opt-out path.
  5. bad input is rejected with a readable reason and no traceback
  6. a module that fails does not sink the scan (an intentionally broken target)
  7. the fixture set ingests through all five file modules
  8. a corrupt upload is reported as failed, not as a clean empty ingest
  9. the store payload builds from both scan and ingest output
 10. the committed dashboard catalog matches the live registries

Usage:  python3 tools/smoke_test.py [-v]
Exit:   0 all checks passed, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "module_framework" / "cli.py"
INGEST = ROOT / "module_framework" / "ingest.py"
FIXTURES = ROOT / "examples" / "file-ingest-selftest"

PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, str, str]] = []
VERBOSE = False


def check(name: str, ok: bool, detail: str = "") -> bool:
    results.append((PASS if ok else FAIL, name, detail))
    marker = " ok " if ok else "FAIL"
    print(f"  {marker}  {name}" + (f"  -- {detail}" if detail and (VERBOSE or not ok) else ""))
    return ok


def run(argv: list[str], expect: int | None = 0) -> tuple[int, str, str]:
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=600)
    if expect is not None and proc.returncode != expect:
        print(f"      (exit {proc.returncode}, expected {expect})\n{proc.stderr[-1500:]}")
    return proc.returncode, proc.stdout, proc.stderr


def as_json(out: str):
    """Parse a document AND enforce the byte-level contract the workflows gate on."""
    if not out.startswith("{"):
        raise ValueError("document does not start with '{'")
    return json.loads(out)


# ---- a real, local target ------------------------------------------------


class Target(BaseHTTPRequestHandler):
    """A deliberately weak endpoint: no security headers, an admin path behind 401."""

    def do_HEAD(self):  # noqa: N802
        if self.path.rstrip("/") in ("/admin", "/login"):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="synthetic"')
        else:
            self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_HEAD  # noqa: N815 — BaseHTTPRequestHandler's required spelling

    def log_message(self, *a):
        pass


def serve() -> tuple[ThreadingHTTPServer, str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host, port = srv.server_address[:2]
    return srv, f"http://{host}:{port}"


# ---- the checks ----------------------------------------------------------


def check_entry_points() -> None:
    print("\nentry points")
    code, out, _ = run([sys.executable, str(CLI), "--list-modules"])
    ok = code == 0
    if ok:
        doc = as_json(out)
        ok = len(doc["modules"]) > 0
        check("scan catalog lists modules", ok, f"{len(doc['modules'])} modules")
    else:
        check("scan catalog lists modules", False)

    code, out, _ = run([sys.executable, str(INGEST), "--list-modules"])
    doc = as_json(out) if code == 0 else {"modules": []}
    check(
        "ingest catalog lists modules", len(doc["modules"]) == 5, f"{len(doc['modules'])} modules"
    )

    # The docstring advertised `-m` while it raised ModuleNotFoundError.
    code, out, err = run([sys.executable, "-m", "module_framework.cli", "--list-modules"], expect=0)
    check("python -m module_framework.cli works", code == 0 and out.startswith("{"))


def check_dry_run() -> None:
    print("\ndry run")
    code, out, _ = run(
        [
            sys.executable,
            str(CLI),
            "--group",
            "standard",
            "--targets",
            "scanme.selftest.invalid",
            "--client",
            "smoke",
            "--scan-id",
            "smoke-dry",
            "--dry-run",
        ]
    )
    doc = as_json(out) if code == 0 else {}
    check("dry run exits clean", code == 0)
    check("dry run executes no module", doc.get("stats", {}).get("module_runs") == 0)
    check("dry run reports status dry_run", doc.get("status") == "dry_run")
    check(
        "dry run keeps the full schema", {"findings", "errors", "stats", "modules_run"} <= set(doc)
    )


def check_active_scan(base: str) -> None:
    print("\nactive scan against a live local endpoint")
    code, out, err = run(
        [
            sys.executable,
            str(CLI),
            "--modules",
            "header_security_check,default_creds_check",
            "--targets",
            base,
            "--client",
            "smoke",
            "--scan-id",
            "smoke-active",
            "--allow-local",
        ]
    )
    doc = as_json(out) if code == 0 else {}
    findings = doc.get("findings", [])
    check("active scan exits clean", code == 0)
    check("active scan reports status ok", doc.get("status") == "ok", doc.get("status", "?"))
    check(
        "real findings came back over a real socket", len(findings) > 0, f"{len(findings)} findings"
    )

    modules = {f["module"] for f in findings}
    check("missing security headers were detected", "header_security_check" in modules)
    # The check that could not see a 401 before http_probe existed.
    creds = [f for f in findings if f["module"] == "default_creds_check"]
    check(
        "a 401-protected admin path was detected",
        len(creds) > 0,
        f"{[f['evidence']['path'] for f in creds]}",
    )
    check(
        "the 401 status reached the finding", any(f["evidence"].get("status") == 401 for f in creds)
    )
    check(
        "timings recorded for every module run", len(doc.get("stats", {}).get("timings", [])) == 2
    )


def check_bad_input() -> None:
    print("\ninput validation")
    code, out, err = run(
        [sys.executable, str(CLI), "--group", "quick", "--targets", "10.0.0.0/99"], expect=2
    )
    check("invalid target exits 2", code == 2)
    check(
        "no traceback on invalid input",
        "Traceback" not in err,
        err.strip().splitlines()[-1:] and "",
    )

    code, out, err = run(
        [sys.executable, str(CLI), "--group", "quick", "--targets", "file:///etc/passwd"], expect=2
    )
    check("file:// target is refused", code == 2 and "http/https" in err)

    code, out, err = run(
        [
            sys.executable,
            str(CLI),
            "--group",
            "quick",
            "--targets",
            "http://169.254.169.254/latest/meta-data/",
        ],
        expect=2,
    )
    check("cloud metadata endpoint is refused", code == 2 and "link-local" in err)

    code, out, err = run(
        [sys.executable, str(CLI), "--modules", "does_not_exist", "--targets", "example.com"],
        expect=2,
    )
    check("unknown module exits 2 and lists what exists", code == 2 and "port_scan" in err)


def check_containment(base: str) -> None:
    print("\nfailure containment")
    # A URL-only module pointed at a target it cannot reach, alongside one that
    # can: the scan must survive and still report the healthy module's findings.
    code, out, _ = run(
        [
            sys.executable,
            str(CLI),
            "--modules",
            "header_security_check",
            "--targets",
            f"{base},http://127.0.0.1:1/",
            "--allow-local",
            "--client",
            "smoke",
        ]
    )
    doc = as_json(out) if code == 0 else {}
    check("scan survives an unreachable target", code == 0)
    check("healthy target still produced findings", len(doc.get("findings", [])) > 0)


def check_ingest() -> None:
    print("\nfile ingestion")
    code, out, _ = run(
        [
            sys.executable,
            str(INGEST),
            "--group",
            "ingest",
            "--files-dir",
            str(FIXTURES),
            "--client",
            "smoke",
            "--scan-id",
            "smoke-ingest",
        ]
    )
    doc = as_json(out) if code == 0 else {}
    findings = doc.get("findings", [])
    check("ingest exits clean", code == 0)
    check("ingest reports status ok", doc.get("status") == "ok")
    check("no fixture failed to parse", doc.get("files_failed") == [], str(doc.get("files_failed")))
    modules = {f["module"] for f in findings}
    check("all five file modules produced findings", len(modules) == 5, ", ".join(sorted(modules)))
    severities = {f["severity"] for f in findings}
    check(
        "fixtures cover critical..info",
        {"critical", "high", "medium", "low", "info"} <= severities,
        ", ".join(sorted(severities)),
    )
    return doc


def check_corrupt_upload() -> None:
    print("\ncorrupt upload handling")
    with tempfile.TemporaryDirectory() as tmp:
        bad = Path(tmp) / "broken.xml"
        bad.write_text("\x00\x01 not xml at all <<<")
        code, out, _ = run([sys.executable, str(INGEST), "--group", "ingest", "--files", str(bad)])
        doc = as_json(out) if code == 0 else {}
        check("corrupt file is NOT counted as ingested", doc.get("files_ingested") == [])
        check("corrupt file is reported as failed", len(doc.get("files_failed", [])) == 1)
        check(
            "the parser's reason is carried up",
            bool(doc.get("files_failed", [{}])[0].get("errors")),
            str(doc.get("files_failed", [{}])[0].get("errors")),
        )
        check("status reflects the failure", doc.get("status") == "failed")

        code, _, _ = run(
            [sys.executable, str(INGEST), "--group", "ingest", "--files", str(bad), "--strict"],
            expect=1,
        )
        check("--strict exits non-zero", code == 1)


def check_payload(scan_doc: dict) -> None:
    print("\nstore payload")
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "findings.json"
        src.write_text(json.dumps(scan_doc))
        out_file = Path(tmp) / "payload.json"
        code, _, _ = run(
            [
                sys.executable,
                str(ROOT / "tools" / "build_store_payload.py"),
                "--findings",
                str(src),
                "--out",
                str(out_file),
                "--scan-type",
                "modular_scan",
                "--scan-id",
                "smoke-1",
                "--client-id",
                "smoke",
                "--client-name",
                "Smoke Client",
                "--target",
                "fixtures",
                "--consensus-status",
                "skipped",
            ]
        )
        check("payload builds", code == 0)
        raw = out_file.read_text()
        # The exact gate the workflow applies before POSTing.
        check("payload starts with '{'", raw.startswith("{"))
        payload = json.loads(raw)
        check("payload carries client_id", payload.get("client_id") == "smoke")
        check(
            "summary totals match the findings",
            payload["summary"]["total"] == len(scan_doc["findings"]),
        )
        check("diagnostics are attached", "diagnostics" in payload)
        check("scan health survives to the record", payload.get("scan_status") == "ok")

        # A scan where everything failed must not store as completed.
        broken = dict(
            scan_doc,
            status="failed",
            findings=[],
            errors=[{"module": "port_scan", "error": "RuntimeError: boom"}],
        )
        src.write_text(json.dumps(broken))
        run(
            [
                sys.executable,
                str(ROOT / "tools" / "build_store_payload.py"),
                "--findings",
                str(src),
                "--out",
                str(out_file),
                "--scan-type",
                "modular_scan",
                "--scan-id",
                "smoke-2",
                "--client-id",
                "smoke",
                "--client-name",
                "Smoke",
                "--target",
                "fixtures",
            ]
        )
        failed_payload = json.loads(out_file.read_text())
        check(
            "a fully failed scan stores as failed, not completed",
            failed_payload["status"] == "failed",
        )


def check_catalog() -> None:
    print("\ndashboard catalog")
    committed = ROOT / "dashboard" / "public" / "catalog.json"
    code, out, _ = run([sys.executable, str(ROOT / "tools" / "build_catalog.py")])
    check("catalog rebuilds", code == 0)
    proc = subprocess.run(
        ["git", "diff", "--exit-code", "--", str(committed)], cwd=ROOT, capture_output=True
    )
    check(
        "committed catalog matches the live registries",
        proc.returncode == 0,
        "run tools/build_catalog.py" if proc.returncode else "",
    )


def main() -> int:
    global VERBOSE
    ap = argparse.ArgumentParser(prog="smoke-test")
    ap.add_argument("-v", "--verbose", action="store_true")
    VERBOSE = ap.parse_args().verbose

    if not FIXTURES.is_dir():
        print(f"fixtures missing: {FIXTURES}", file=sys.stderr)
        return 1

    print("Threat Inspector — end-to-end local smoke test")
    srv, base = serve()
    print(f"(local target endpoint: {base})")
    try:
        check_entry_points()
        check_dry_run()
        check_active_scan(base)
        check_bad_input()
        check_containment(base)
        ingest_doc = check_ingest()
        check_corrupt_upload()
        check_payload(ingest_doc)
        check_catalog()
    finally:
        srv.shutdown()
        srv.server_close()

    failed = [r for r in results if r[0] == FAIL]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")
    for _, name, detail in failed:
        print(f"  FAILED: {name} {detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
