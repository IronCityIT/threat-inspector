"""
ingest.py — the file-ingestion entry point (passive counterpart to cli.py).

Where cli.py drives active scanners against live targets, ingest.py drives
FileModules over uploaded scan exports. Same selection model, same JSON contract:
the findings it emits on stdout flow into the SAME analyze/store pipeline
(_consensus-store.yml → consensus-engine) — there is no second AI path for files.

  python3 module_framework/ingest.py --list-modules
  python3 module_framework/ingest.py --group ingest --files scan1.xml,scan2.csv \
      --client acme --scan-id 2026-07-09-01
  python3 module_framework/ingest.py --modules qualys_ingest --files-dir uploads/

When more than one selected module accepts a file's extension (e.g. .csv is
claimed by several), the tool's own content auto-detection breaks the tie so a
file is never mis-parsed.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

# Flat framework imports need module_framework/ on the path (script dir, when run
# as `python3 module_framework/ingest.py`, and explicitly for `-m`); the parsers
# need the tool's src/.
_HERE = Path(__file__).resolve().parent
_SRC = _HERE.parent / "src"
for _p in (str(_HERE), str(_SRC)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import registry  # noqa: E402
from base import FileModule, IngestReport  # noqa: E402

from threat_inspector.parsers import get_parser  # noqa: E402

log = logging.getLogger("icit.ingest")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="icit-ingest")
    p.add_argument(
        "--files",
        action="append",
        default=[],
        help="scan export file(s) (comma-separated, repeatable)",
    )
    p.add_argument(
        "--files-dir",
        action="append",
        default=[],
        help="directory of scan exports (recursively globbed by extension)",
    )
    sel = p.add_mutually_exclusive_group()
    sel.add_argument("--modules", help="comma list of file-module names to run")
    sel.add_argument("--group", help="named group: ingest | deep | ...")
    p.add_argument("--client", default="", help="client identifier (multi-tenant)")
    p.add_argument("--scan-id", default="", help="unique scan id")
    p.add_argument(
        "--list-modules",
        action="store_true",
        help="print available file modules and groups, then exit",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero if any file failed to parse "
        "(default: report the failures and keep the findings from the rest)",
    )
    p.add_argument(
        "--log-level",
        default=os.environ.get("ICIT_LOG_LEVEL", "info"),
        choices=("debug", "info", "warning", "error"),
        help="stderr log verbosity (default info)",
    )
    return p


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )


def ingest_file(module: FileModule, path: Path, ctx: dict) -> IngestReport:
    """Ingest one file through one module. Never raises.

    A malformed upload must not take down the batch: the other files a client
    sent are still worth something. Parser-level problems arrive in the report;
    an outright exception is converted into one here.
    """
    try:
        report = module.ingest_report(path, ctx)
    except Exception as e:  # noqa: BLE001 — containment is the point
        log.warning("%s failed on %s: %s", module.name, path.name, e)
        log.debug("traceback for %s/%s", module.name, path, exc_info=True)
        return IngestReport(errors=[f"{type(e).__name__}: {e}"])
    for problem in report.errors:
        log.error("%s could not parse %s: %s", module.name, path.name, problem)
    for warning in report.warnings:
        log.warning("%s on %s: %s", module.name, path.name, warning)
    log.info(
        "%s ingested %s: %d finding(s)%s",
        module.name,
        path.name,
        len(report.findings),
        "" if report.ok else " (WITH ERRORS)",
    )
    return report


def collect_files(files: list[str], dirs: list[str], known_exts: set[str]) -> list[Path]:
    """Gather explicit files plus every supported file under each directory."""
    out: list[Path] = []
    seen: set[Path] = set()

    def add(path: Path) -> None:
        rp = path.resolve()
        if rp not in seen and rp.is_file():
            seen.add(rp)
            out.append(rp)

    for entry in files:
        for part in entry.split(","):
            part = part.strip()
            if part:
                add(Path(part))
    for d in dirs:
        base = Path(d)
        if base.is_dir():
            for child in sorted(base.rglob("*")):
                if child.is_file() and child.suffix.lower() in known_exts:
                    add(child)
    return out


def resolve_module(path: Path, mods: list[FileModule]) -> FileModule | None:
    """Pick the one selected module that should ingest this file.

    One accepting module -> use it. Several (shared extension) -> defer to the
    tool's content auto-detection and match its scanner type back to a module.
    None -> the file is outside the current selection.
    """
    candidates = [m for m in mods if m.accepts(path)]
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]

    detected = get_parser(path)
    if detected is not None:
        want = detected.SCANNER_TYPE
        for m in candidates:
            parser = getattr(m, "PARSER", None)
            if parser is not None and parser.SCANNER_TYPE == want:
                return m
    # Stable fallback: first by name.
    return sorted(candidates, key=lambda m: m.name)[0]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _configure_logging(args.log_level)
    reg = registry.discover_files("file_modules")

    if args.list_modules:
        print(
            json.dumps(
                {"modules": registry.catalog(reg), "groups": sorted(registry.all_groups(reg))},
                indent=2,
            )
        )
        return 0

    try:
        mods = registry.select(
            reg,
            modules=[m.strip() for m in args.modules.split(",")] if args.modules else None,
            group=args.group,
            default_group="ingest",
        )
    except KeyError as e:
        print(f"selection error: {e}", file=sys.stderr)
        print(f"available modules: {', '.join(sorted(reg))}", file=sys.stderr)
        return 2

    known_exts = {e for m in mods for e in m.extensions}
    paths = collect_files(args.files, args.files_dir, known_exts)
    if not paths:
        print(
            "no input files — pass --files and/or --files-dir "
            f"(recognised extensions: {', '.join(sorted(known_exts))})",
            file=sys.stderr,
        )
        return 2

    ctx = {"client": args.client, "scan_id": args.scan_id}
    findings: list[dict] = []
    ingested: list[str] = []
    skipped: list[str] = []
    failed: list[dict] = []
    warnings: list[dict] = []
    started = time.monotonic()

    log.info(
        "ingest start: client=%s scan_id=%s files=%d modules=%s",
        args.client or "(unset)",
        args.scan_id or "(unset)",
        len(paths),
        ",".join(m.name for m in mods),
    )

    for path in paths:
        module = resolve_module(path, mods)
        if module is None:
            log.debug("no selected module accepts %s", path.name)
            skipped.append(str(path))
            continue
        report = ingest_file(module, path, ctx)
        findings.extend(f.to_dict() for f in report.findings)
        if report.warnings:
            warnings.append({"file": str(path), "module": module.name, "warnings": report.warnings})
        # A file that failed to parse is NOT an ingested file. Reporting it as
        # one is how a corrupt client upload used to pass for a clean, empty
        # scan export — same zero findings, no indication anything went wrong.
        if report.ok:
            ingested.append(str(path))
        else:
            failed.append({"file": str(path), "module": module.name, "errors": report.errors})

    if failed and not ingested:
        status = "failed"
    elif failed:
        status = "partial"
    else:
        status = "ok"

    duration = time.monotonic() - started
    log.info(
        "ingest %s: %d finding(s) from %d file(s), %d failed, %d skipped, %.1fs",
        status,
        len(findings),
        len(ingested),
        len(failed),
        len(skipped),
        duration,
    )

    print(
        json.dumps(
            {
                "client": args.client,
                "scan_id": args.scan_id,
                "modules_run": [m.name for m in mods],
                "file_count": len(ingested),
                "files_ingested": ingested,
                "files_skipped": skipped,
                "files_failed": failed,
                "warnings": warnings,
                "status": status,
                "findings": findings,
                "stats": {
                    "files_seen": len(paths),
                    "files_failed": len(failed),
                    "duration_seconds": round(duration, 2),
                },
            },
            indent=2,
        )
    )
    if failed and args.strict:
        print(f"--strict: {len(failed)} file(s) failed to parse", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
