"""
cli.py — the CLI-first entry point (access gate lives here).

  python3 module_framework/cli.py --list-modules
  python3 -m module_framework.cli --list-modules
  python3 module_framework/cli.py --group deep    --targets 10.0.0.0/30,example.com
  python3 module_framework/cli.py --modules a,b   --targets-file targets.txt
  python3 module_framework/cli.py --group standard --targets https://app.example.com \
      --client acme --scan-id 2026-07-08-01

Output is JSON on stdout — this is what gets POSTed to consensus-engine and then
the storeScanResults Cloud Function. Same JSON contract for every tool. Progress,
timings and failures go to stderr, so stdout stays a clean parseable document.

Exit codes: 0 = ran (see "status" in the JSON), 2 = bad invocation (nothing ran).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

# Both invocation styles have to work. `python3 module_framework/cli.py` puts this
# directory on sys.path automatically; `python3 -m module_framework.cli` puts the
# REPO ROOT there instead, and the flat imports below (`registry`, `targets` —
# which is also how every module imports `base`) would fail with
# ModuleNotFoundError. The docstring advertised the -m form while it was broken.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import registry  # noqa: E402
from base import Finding, ScanModule  # noqa: E402
from targets import Target, parse_targets_report  # noqa: E402

log = logging.getLogger("icit.scan")

# A module that hangs must not hang the whole scan. Modules already pass their own
# timeout to subprocesses, but nothing bounded a module that blocks in Python.
DEFAULT_MODULE_TIMEOUT = 900


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="icit-scan",
        description="Iron City modular security scan. Selection maps 1:1 to the dashboard.",
    )
    p.add_argument(
        "--targets",
        action="append",
        default=[],
        help="IP, CIDR, URL, domain or hostname (comma-separated, repeatable)",
    )
    p.add_argument(
        "--targets-file",
        action="append",
        default=[],
        help="file of targets, one per line (# comments allowed)",
    )
    sel = p.add_mutually_exclusive_group()
    sel.add_argument("--modules", help="comma list of module names to run")
    sel.add_argument("--group", help="named group: quick | standard | deep | ...")
    p.add_argument("--client", default="", help="client identifier (multi-tenant)")
    p.add_argument("--scan-id", default="", help="unique scan id")
    p.add_argument(
        "--list-modules", action="store_true", help="print available modules and groups, then exit"
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="validate targets and module selection, then exit without "
        "running any module (no network traffic, no findings)",
    )
    p.add_argument(
        "--allow-local",
        action="store_true",
        help="permit loopback and link-local targets (blocked by default: the "
        "link-local range holds the cloud instance-metadata endpoint)",
    )
    p.add_argument(
        "--strict-targets",
        action="store_true",
        help="refuse to scan anything if ANY target failed to parse "
        "(default: report the bad ones and scan the rest)",
    )
    p.add_argument(
        "--module-timeout",
        type=int,
        default=int(os.environ.get("ICIT_MODULE_TIMEOUT", DEFAULT_MODULE_TIMEOUT)),
        help=f"seconds one module gets for one target (default {DEFAULT_MODULE_TIMEOUT})",
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


def run_module(
    module: ScanModule, target: Target, ctx: dict, timeout: int
) -> tuple[list[Finding], str | None, float]:
    """Run one module against one target. Never raises.

    Returns (findings, error_message_or_None, elapsed_seconds). A module that
    blows up is contained here: its failure is recorded and the scan carries on.
    Before this existed, one raising module aborted main() and discarded every
    finding the previous modules had already produced.
    """
    started = time.monotonic()
    try:
        findings = module.run(target, ctx)
    except Exception as e:  # noqa: BLE001 — containment is the entire point
        elapsed = time.monotonic() - started
        log.warning("module %s failed on %s after %.1fs: %s", module.name, target.value, elapsed, e)
        log.debug("traceback for %s/%s", module.name, target.value, exc_info=True)
        return [], f"{type(e).__name__}: {e}", elapsed
    elapsed = time.monotonic() - started
    if elapsed > timeout:
        log.warning(
            "module %s on %s took %.1fs (over the %ss budget)",
            module.name,
            target.value,
            elapsed,
            timeout,
        )
    log.info("%s on %s: %d finding(s) in %.1fs", module.name, target.value, len(findings), elapsed)
    return findings, None, elapsed


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _configure_logging(args.log_level)
    reg = registry.discover("modules")

    if args.list_modules:
        print(
            json.dumps(
                {"modules": registry.catalog(reg), "groups": sorted(registry.all_groups(reg))},
                indent=2,
            )
        )
        return 0

    # ---- targets -------------------------------------------------------
    # Bad input is reported as a readable reason, never a library traceback.
    report = parse_targets_report(args.targets, args.targets_file, allow_local=args.allow_local)
    for problem in report.errors:
        log.error("target rejected: %s", problem)
    if report.errors and args.strict_targets:
        print(
            f"refusing to scan: {len(report.errors)} target(s) rejected (--strict-targets)",
            file=sys.stderr,
        )
        return 2
    if not report.targets:
        print(
            "no valid targets — pass --targets and/or --targets-file "
            "(IP, CIDR, http(s) URL, domain or hostname)",
            file=sys.stderr,
        )
        return 2
    targets = report.targets

    # ---- selection -----------------------------------------------------
    try:
        mods = registry.select(
            reg,
            modules=[m.strip() for m in args.modules.split(",") if m.strip()]
            if args.modules
            else None,
            group=args.group,
        )
    except KeyError as e:
        print(f"selection error: {e}", file=sys.stderr)
        print(f"available modules: {', '.join(sorted(reg))}", file=sys.stderr)
        return 2

    ctx = {"client": args.client, "scan_id": args.scan_id}
    findings: list[dict] = []
    errors: list[dict] = []
    timings: list[dict] = []
    scan_started = time.monotonic()

    log.info(
        "scan start: client=%s scan_id=%s targets=%d modules=%s dry_run=%s",
        args.client or "(unset)",
        args.scan_id or "(unset)",
        len(targets),
        ",".join(m.name for m in mods),
        args.dry_run,
    )

    # THE GUARD. m.run() is the only place a module touches the network, so a dry
    # run stops exactly here — after targets and selection have been validated for
    # real, before anything reaches a live host. Emitting an empty findings set is
    # the honest result: nothing was scanned, so nothing was found.
    if not args.dry_run:
        for t in targets:
            for m in mods:
                if not m.applies_to(t.kind):
                    log.debug("skip %s on %s (kind %s not supported)", m.name, t.value, t.kind)
                    continue
                got, err, elapsed = run_module(m, t, ctx, args.module_timeout)
                findings.extend(f.to_dict() for f in got)
                timings.append(
                    {
                        "module": m.name,
                        "target": t.value,
                        "seconds": round(elapsed, 2),
                        "findings": len(got),
                        "ok": err is None,
                    }
                )
                if err is not None:
                    errors.append({"module": m.name, "target": t.value, "error": err})
    else:
        log.info(
            "dry-run: validated %d target(s) and %d module(s); no module executed",
            len(targets),
            len(mods),
        )
        print(
            f"dry-run: validated {len(targets)} target(s) and "
            f"{len(mods)} module(s); no module executed",
            file=sys.stderr,
        )

    # ---- status --------------------------------------------------------
    # An empty findings list is ambiguous on its own: it can mean "clean scan" or
    # "every module blew up". Downstream (dashboard, consensus) needs to tell
    # those apart, so the run reports its own health.
    attempted = len(timings)
    failed = len(errors)
    if args.dry_run:
        status = "dry_run"
    elif attempted and failed == attempted:
        status = "failed"
    elif failed:
        status = "partial"
    else:
        status = "ok"

    duration = time.monotonic() - scan_started
    log.info(
        "scan %s: %d finding(s), %d/%d module-runs ok, %.1fs",
        status,
        len(findings),
        attempted - failed,
        attempted,
        duration,
    )

    # Schema is identical either way so every downstream consumer (workflow jq,
    # payload builder, dashboard) exercises the same path in a dry run.
    print(
        json.dumps(
            {
                "client": args.client,
                "scan_id": args.scan_id,
                "modules_run": [m.name for m in mods],
                "target_count": len(targets),
                "dry_run": args.dry_run,
                "status": status,
                "findings": findings,
                "errors": errors,
                "rejected_targets": report.errors,
                "stats": {
                    "module_runs": attempted,
                    "module_runs_failed": failed,
                    "duration_seconds": round(duration, 2),
                    "timings": timings,
                },
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
