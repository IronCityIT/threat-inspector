# TASKS.md — ICIT Productization Queue (modular refactor)

Work in order, one product per branch, one PR per product. Obey CLAUDE.md —
build → PR → STOP, never merge, never deploy. Do not start the next product until
the current PR is open and clean.

The job is NOT to wrap clunky code in a dashboard. The job is to make each tool good:
review the existing Claude-generated Python, break the monolith into modules using the
shared framework in `module_framework/`, let modules be run individually or as a group,
take flexible target input, and then mirror all of that in the dashboard.

If a product's Python source is not in its repo, HALT on that product, record it in
`PRODUCTIZE_NOTES.md`, and move to the next.

---

## Task 0 — READ EVERYTHING FIRST (mandatory, before any build)

Do not scaffold blind. Before touching any product:
1. Read `ICIT-BUILD-INVENTORY.md` for the confirmed state of every system.
2. For every repo you have access to under `IronCityIT` (consensus-engine,
   ICIT-ThreatInspector, ICIT-DNSGuard, ICIT-AttackSimPro, and any ShadowScan/Surge/DXA
   repos), clone/checkout and read the actual code. Inventory: what each tool does today,
   its entry point, how it emits findings, hardcoded paths/creds, and its current deploy
   state (is the Firebase project live? does the workflow pass?).
3. Reconcile what you find against the inventory. Write the reconciliation into
   `PRODUCTIZE_NOTES.md` — including anything the inventory got wrong or that changed.
4. Only then start the queue. If a repo is inaccessible (private, no token), HALT on that
   item and report — do not fabricate its contents.

## AttackSim Pro tool expansion (separate, PR-only)

See `ASP-TOOL-EXPANSION.md`. ASP is live/sacred — this is a scoped, PR-only task on a
non-prod integration branch, walled off from the queue below. Do NOT run it against
`main` and do NOT deploy. It adds current open-source BAS tools (CALDERA, Stratus Red
Team, MAAD-AF, PurpleSharp, RTA, Infection Monkey, VECTR, flightsim) as new modules.

## Queue
1. Threat Inspector  — repo `ICIT-ThreatInspector`
2. ShadowScan        — repo TBD (confirm under IronCityIT; if absent, HALT + report)
3. Surge             — repo TBD
4. Dynamic Experience Analyzer — repo TBD

> AttackSim Pro is NOT in this queue. Live/sacred. Do not touch it.

---

## The same 8 steps apply to every product

For each tool, on branch `productize/<product>`:

1. **Review first.** Read the existing Python end to end. In `PRODUCTIZE_NOTES.md`, list
   every capability it currently has and every rough edge (monolithic flow, no input
   validation, hardcoded targets, tracebacks on bad input, no module selection). This
   review is a required deliverable, not optional.
2. **Adopt the framework.** Copy `module_framework/` (`targets.py`, `base.py`,
   `registry.py`, `cli.py`) into the tool unchanged. Delete `example_recon.py`.
3. **Modularize.** Turn each existing capability into a `ScanModule` in `modules/`.
   Re-house existing logic — do not rewrite from scratch and do not drop features.
4. **Groups.** Tag every module `quick` / `standard` / `deep`. Selection must work both
   ways: `--modules a,b,c` (individual) and `--group deep` (bundle).
5. **Input.** Confirm targets accept IP, CIDR, URL, domain, hostname, and `--targets-file`.
   The framework already does this — wire the tool's entry point to it; kill any old
   hardcoded/one-shape input path.
6. **Add modules.** Add the capability gaps you identified in step 1 as new modules
   (see per-tool starter lists below). Keep each module single-purpose.
7. **Dashboard mirrors the registry.** Module checkboxes + group presets + target box all
   read `registry.catalog()`. UI selection maps 1:1 to `--modules` / `--group`. White-label
   — no underlying tool names on any client-facing surface.
8. **Standard plumbing + gates.** Workflow calls `consensus-engine` via `workflow_call`;
   JSON output POSTs to `storeScanResults`; results carry `client_id`. Run quality gates,
   dry-run `workflow_dispatch`, open PR, STOP. Do NOT deploy or configure DNS — note the
   target domain in the PR for Bill.

---

## Per-tool starter module sets

These are starting points. First inventory the existing code (step 1); fold what exists
into modules, then add the missing ones. Confirm gaps against the real source, don't
blindly implement a module that already exists under another name.

### Threat Inspector (multi-scanner vuln aggregation)
Candidate modules: `port_scan`, `service_fingerprint`, `tls_cert_check`, `cve_lookup`,
`web_vuln_scan`, `subdomain_enum`, `header_security_check`, `default_creds_check`.
Groups: quick = ports+headers+tls; standard = + service/cve/subdomain; deep = everything
incl. web_vuln_scan.

### ShadowScan (deep/dark web monitoring)
Candidate modules: `credential_leak_lookup`, `domain_mention_monitor`,
`paste_site_scan`, `breach_db_lookup`, `brand_mention_monitor`, `typosquat_detect`.
Groups: quick = credential+breach lookups; deep = full crawl set.

### Surge (web/eCommerce performance optimization)
Candidate modules: `page_load_timing`, `core_web_vitals`, `asset_weight_audit`,
`cache_header_audit`, `render_blocking_audit`, `image_optimization_check`, `cdn_check`.
Groups: quick = timing+vitals; deep = full audit set.

### Dynamic Experience Analyzer (Puppeteer-based interaction analysis)
Candidate modules: `flow_walkthrough`, `form_interaction_test`, `js_error_capture`,
`console_warning_capture`, `broken_link_check`, `accessibility_snapshot`.
Node/Puppeteer dependency belongs in the workflow container. Puppeteer is a tool name —
keep it OFF client-facing surfaces.

---

## Per-run reporting (append to PRODUCTIZE_NOTES.md)
- Branch + PR link.
- Capability inventory from step 1, and which became modules vs. newly added.
- What was scaffolded vs. left for Bill (deploy, DNS, Auth0 app creation).
- Blockers, missing source, failed gates — plainly, not hidden.
