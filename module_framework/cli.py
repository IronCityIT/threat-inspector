"""
cli.py — the CLI-first entry point (access gate lives here).

  python -m module_framework.cli --list-modules
  python -m module_framework.cli --group deep     --targets 10.0.0.0/30,example.com
  python -m module_framework.cli --modules a,b     --targets-file targets.txt
  python -m module_framework.cli --group standard  --targets https://app.example.com \
      --client acme --scan-id 2026-07-08-01

Output is JSON on stdout — this is what gets POSTed to consensus-engine and then
the storeScanResults Cloud Function. Same JSON contract for every tool.
"""
from __future__ import annotations

import argparse
import json
import sys

import registry
from targets import parse_targets


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="icit-scan")
    p.add_argument("--targets", action="append", default=[],
                   help="IP, CIDR, URL, domain or hostname (comma-separated, repeatable)")
    p.add_argument("--targets-file", action="append", default=[],
                   help="file of targets, one per line (# comments allowed)")
    sel = p.add_mutually_exclusive_group()
    sel.add_argument("--modules", help="comma list of module names to run")
    sel.add_argument("--group", help="named group: quick | standard | deep | ...")
    p.add_argument("--client", default="", help="client identifier (multi-tenant)")
    p.add_argument("--scan-id", default="", help="unique scan id")
    p.add_argument("--list-modules", action="store_true",
                   help="print available modules and groups, then exit")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    reg = registry.discover("modules")

    if args.list_modules:
        print(json.dumps({"modules": registry.catalog(reg),
                          "groups": sorted(registry.all_groups(reg))}, indent=2))
        return 0

    targets = parse_targets(args.targets, args.targets_file)
    if not targets:
        print("no valid targets", file=sys.stderr)
        return 2

    try:
        mods = registry.select(
            reg,
            modules=[m.strip() for m in args.modules.split(",")] if args.modules else None,
            group=args.group,
        )
    except KeyError as e:
        print(f"selection error: {e}", file=sys.stderr)
        return 2

    ctx = {"client": args.client, "scan_id": args.scan_id}
    findings = []
    for t in targets:
        for m in mods:
            if m.applies_to(t.kind):
                findings.extend(f.to_dict() for f in m.run(t, ctx))

    print(json.dumps({
        "client": args.client,
        "scan_id": args.scan_id,
        "modules_run": [m.name for m in mods],
        "target_count": len(targets),
        "findings": findings,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
