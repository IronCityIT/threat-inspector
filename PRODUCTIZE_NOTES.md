# PRODUCTIZE_NOTES.md — Threat Inspector

**Product:** Threat Inspector (queue item #1)
**Repo:** `IronCityIT/threat-inspector` (remote confirmed: `https://github.com/IronCityIT/threat-inspector.git`)
**Branch at inventory time:** `main` (no `productize/threat-inspector` branch yet)
**Date:** 2026-07-08
**Status:** Task 0 inventory complete (§0–§9 below), then **PR 1 — Foundation** built on branch
`productize/threat-inspector` (see "PR 1 — Foundation (build record)" at the end of this file).

> Scope note: This run inventoried **this repo only** (per user instruction), not every
> IronCityIT repo. The full cross-repo Task-0 sweep (consensus-engine, DNSGuard, etc.)
> is not done here and is flagged as an open item at the bottom.

---

## 0. TL;DR — the one thing that matters

**There are two disconnected codebases in this repo that both claim to be "Threat Inspector," and they do not talk to each other:**

1. **`src/threat_inspector/`** — a well-structured *offline vulnerability-report **aggregator***.
   It ingests scanner *output files* (Qualys/ZAP/Nmap/Nessus), normalizes/dedupes findings,
   enriches remediation, maps compliance, and emits HTML/JSON/CSV reports + a FastAPI dashboard.
   It performs **no scanning of its own.**

2. **`.github/workflows/*.yml`** — four GitHub Actions that run *live scanners* (Nmap, SSL Labs
   API, subfinder+httpx) and one (`vuln-report.yml`) that **re-implements file parsing inline in a
   Python heredoc** — it never imports `src/threat_inspector/`. Results are POSTed straight to a
   Firebase Cloud Function.

The `src/` package is the "real tool" the CLAUDE.md review is about; the workflows are a parallel,
partial re-implementation. **Neither one uses `module_framework/`, calls `consensus-engine`, or
matches the ICIT standard inputs/plumbing.** `module_framework/` is present at repo root (copied in,
pristine, still contains `example_recon.py`) but is **not adopted** anywhere.

---

## 1. Entry points

| Entry point | Location | What it is |
|---|---|---|
| `threat-inspector` CLI | `src/threat_inspector/cli.py` (Click group; `pyproject.toml:67` `[project.scripts]`) | Subcommands: `analyze`, `formats`, `init`, `serve`, `api` |
| Python library | `src/threat_inspector/core.py` → `ThreatInspector` class | `load_file`/`load_scans` → `analyze` → `generate_report` |
| REST API / dashboard | `src/threat_inspector/api/main.py` (FastAPI `app`) | `serve`/`api` CLI cmds + Docker `CMD` run this on :8000 |
| GH Actions (live) | `.github/workflows/{nmap-scan,ssl-grade,asset-discovery,vuln-report}.yml` | `workflow_dispatch` only; each a self-contained bash/python job |
| Module framework CLI | `module_framework/cli.py` (`icit-scan`) | The *target* architecture — **not wired to the tool yet** |

The CLI `analyze` command is the true product entry point of the `src/` package. Everything else
(`serve`/`api`) just exposes the same aggregator over HTTP.

---

## 2. Capability inventory (required review deliverable, TASKS.md step 1)

### 2a. `src/threat_inspector/` package — offline aggregator

| Capability | Where | Notes |
|---|---|---|
| Multi-scanner **file** parsing | `parsers/` (`qualys.py`, `zap.py`, `nmap.py`, `nessus.py`, + `QualysComplianceParser`) | Auto-detect by filename hint → extension → content sniff (`parsers/__init__.py:get_parser`). Supported ext: `.xlsx/.xlsm/.csv/.xml/.json/.nessus/.txt/.nmap` |
| Normalized finding model | `parsers/base.py` → `ParsedVulnerability` / `ParseResult` | Severity normalized to `critical/high/medium/low/info` via `BaseParser.normalize_severity` |
| Deduplication | `core.py:_deduplicate_vulnerabilities` | Key = (title, ip/name, port); keeps longer description |
| Remediation enrichment | `utils/remediation.py` | `scanner → static (13 canned templates) → ollama/local(gpt2) → generic` fallback chain |
| Compliance mapping | `utils/compliance.py` | Keyword→requirement maps for PCI-DSS v4, HIPAA, SOC2, NIST 800-53 (~38 hardcoded patterns) |
| Reports | `reports/html.py` + `core.py` (JSON/CSV inline) | HTML/JSON/CSV. HTML is white-label-clean (see §6). PDF advertised but **not implemented** (`generate_report` raises on unknown format; only html/json/csv handled) |
| Persistence model | `models/__init__.py` | SQLAlchemy ORM: Client/Domain/Project/Scan/Vulnerability/Report. **Defined but not used** by CLI/API (no DB writes wired in) |
| Config | `config.py` | pydantic-settings: env/.env/YAML. Multi sub-settings (db/api/remediation/reports) |
| REST API | `api/main.py` | upload/analyze/vulnerabilities/summary/reports/clear/health. **Single global `_inspector` instance — no multi-tenancy, no auth, CORS `*`** |

### 2b. GitHub Actions workflows — live scanners

| Workflow | Tool(s) used | Emits |
|---|---|---|
| `nmap-scan.yml` | `nmap` (quick/standard/full via `scan_type`) | open-port count/list; artifacts; Firebase POST `scan_type:"nmap"` |
| `ssl-grade.yml` | SSL Labs API + `openssl` + `curl` header check | grade, cert expiry/days-left, missing-security-headers count; Firebase POST `ssl_grade` |
| `asset-discovery.yml` | `subfinder` v2.6.3 + `httpx` v1.3.7 (pinned, downloaded from GitHub releases) | subdomains, live hosts; `assets-<id>.json`; Firebase POST `asset_discovery` |
| `vuln-report.yml` | **inline** pandas/lxml parse of Qualys/ZAP/Nmap files (duplicates `src/`) | severity counts + inline-generated HTML; Firebase POST `vulnerability_report` |

### 2c. Capabilities vs the TASKS.md starter module set (gap view)

Starter set: `port_scan, service_fingerprint, tls_cert_check, cve_lookup, web_vuln_scan, subdomain_enum, header_security_check, default_creds_check`.

- **Exists today (as workflow or parser logic):** port_scan (nmap wf), tls_cert_check + header_security_check (ssl wf), subdomain_enum (asset wf), service_fingerprint (nmap `-sV`, and nmap/nessus parsers extract product/version), cve_lookup (parsers extract CVE ids; nmap vulners script).
- **Missing / would be new modules:** `web_vuln_scan`, `default_creds_check`, a first-class `cve_lookup` (currently only passive extraction from scan files, no active lookup), a container-scan (Trivy) and secret-scan (Gitleaks) — **advertised in README but the workflow files do not exist**.

---

## 3. How it emits findings

- **`src/` package:** in-memory `list[ParsedVulnerability]` → HTML/JSON/CSV files on disk
  (`core.generate_report`), or JSON over the FastAPI endpoints. No network egress; no Firebase.
- **Workflows:** two sinks — (1) GH Actions **artifacts** (`results/`, 90-day retention), and
  (2) `curl -X POST "${{ secrets.FIREBASE_FUNCTION_URL }}"` with a per-scan-type JSON body. The
  POST is best-effort (`|| echo "Firebase post failed"`), so failures are swallowed.
- **Neither path emits the `module_framework` JSON contract** (`{client, scan_id, modules_run,
  target_count, findings[]}`) and **neither calls `consensus-engine`.**

---

## 4. Hardcoded / notable values

- **No hardcoded secrets or API keys found** (grep clean). Firebase URL is a secret ref
  (`secrets.FIREBASE_FUNCTION_URL`), not a literal. Good.
- `config.py:22` API `secret_key` default `"change-me-in-production"` (dev default, env-overridable).
- `api/main.py:29` **CORS `allow_origins=["*"]` with `allow_credentials=True`** — insecure default.
- `configs/client.yaml` — sample tenant "Acme Corporation", RFC1918 IPs (192.168.x), sample
  engagement id. Template only, but it is the file `vuln-report.yml` actually reads at runtime.
- Pinned external downloads in `asset-discovery.yml`: subfinder `2.6.3`, httpx `1.3.7` (fetched at
  runtime from projectdiscovery GitHub releases — supply-chain/availability dependency).
- `remediation.py:277` local AI path uses `gpt2` via `transformers` (placeholder-grade output).
- `Dockerfile:33` copies `templates/` and `Dockerfile` expects it, but **`templates/` does not
  exist** in the repo → Docker build would fail on that COPY. `assets/logo.txt` is a placeholder,
  not a logo.
- `requirements.txt` pulls `torch`, `transformers`, `weasyprint` (heavy) though core aggregation
  doesn't need them; `pyproject.toml` more sensibly gates these behind `[ai]`/`[pdf]` extras — the
  two dependency manifests disagree.

---

## 5. Current deploy state

- **No Firebase/Firestore/GCP artifacts in the repo:** no `firebase.json`, `.firebaserc`,
  `firestore.rules`, functions dir, or `threatinspector-platform/` folder. The inventory's note
  that a "Firebase platform folder existed" is **not reflected in this repo's current tree.**
- Workflows POST to `FIREBASE_FUNCTION_URL` but there is **no Cloud Function source here** and the
  function name is a generic secret, **not** the standard `storeScanResults`. Whether any function
  is deployed is **unverifiable from the repo** (HALT-worthy unknown, not a blocker for inventory).
- No dashboard/hosting config in-repo (the FastAPI app is the only "dashboard," meant for local/Docker).
- Git history is messy: repeated "Add/Delete .github" and "Add files via upload" commits — the repo
  was assembled by upload, not developed in-tree. Latest commit only tweaks asset-discovery error handling.
- Docker build is currently **broken** (missing `templates/` — see §4).

---

## 6. White-label check (CLAUDE.md hard rule)

- **`reports/html.py` client-facing HTML: CLEAN** — does not name ZAP/Nmap/Qualys/Nessus; header is
  generic "Vulnerability Assessment Report", footer branded Iron City. Good.
- **VIOLATIONS elsewhere (client-visible surfaces):**
  - `README.md` names Nmap, SSL Labs, subfinder, httpx, Trivy, Gitleaks, Qualys, ZAP openly.
  - Workflow **names + run-summary output** name the tools ("Port Scan (Nmap)", "SSL Labs", etc.).
    Workflow display names and logs are visible to anyone with repo/Actions access.
  - `vuln-report.yml` inline HTML and Firebase payloads carry a `source`/`scan_type` field with raw
    tool names (`"Qualys"`, `"ZAP"`, `"Nmap"`) — these can reach the dashboard.
  - The `src/` API is titled "Iron City Threat Inspector" (fine) but `/formats` echoes
    `SUPPORTED_FORMATS` values like "Qualys Excel", "OWASP ZAP" to any caller.

---

## 7. Reconciliation vs ICIT-BUILD-INVENTORY.md

| Inventory claim | Reality in repo | Verdict |
|---|---|---|
| Repo `IronCityIT/ICIT-ThreatInspector` | Actual remote is `IronCityIT/threat-inspector` (lowercase, no `ICIT-` prefix) | **Corrected** — name/casing differs |
| Tool set: Nmap, SSL Labs, Subfinder, httpx, Trivy, Gitleaks, CloudSploit, Nikto | Present: Nmap, SSL Labs, subfinder, httpx. **Absent: Trivy, Gitleaks, CloudSploit, Nikto** (README advertises Trivy/Gitleaks workflows that don't exist; CloudSploit/Nikto nowhere) | **Partly wrong** — overstated |
| "Defensive twin of ASP" | Consistent — blue-team framing throughout | Confirmed |
| Firebase project `iron-city-it-threatinspector`; platform folder existed; deploy path unresolved | No Firebase artifacts, no platform folder, generic `FIREBASE_FUNCTION_URL` secret; deploy state unverifiable from repo | **Deploy still unresolved; platform folder not in repo** |
| "First in queue" | Correct — TASKS.md queue #1 | Confirmed |
| Standard inputs `target/client_name/scan_id`; consensus-engine via `workflow_call`; POST to `storeScanResults` | Workflows use `target/scan_id/client_id` (**`client_id`, not `client_name`**), **no consensus-engine call**, POST to generic secret URL (**not `storeScanResults`**) | **Diverges from ICIT standard on all three** |

**New facts the inventory did not capture:**
- The `src/` package (full offline aggregator + FastAPI + SQLAlchemy models) exists and is
  substantially more complete than the workflows, yet is entirely disconnected from them.
- `module_framework/` has already been copied into the repo (untracked) but not adopted.
- Docker image is currently unbuildable (missing `templates/`).

---

## 8. Gaps vs the ICIT standard architecture (for the eventual build — NOT started)

Recorded now so the build phase is scoped; no code touched.
1. **Adopt `module_framework/`** — copy `targets.py/base.py/registry.py/cli.py` into the tool,
   delete `example_recon.py`, re-house each capability (§2a/§2b) as a `ScanModule`. Note: the
   framework uses cwd-relative imports (`from base import ...`, `from targets import ...`), so it
   runs as `python3 cli.py` **from inside its dir**, not as `python -m module_framework.cli` (the
   cli.py docstring's `-m` example would break imports). Decide the packaging convention on adoption.
2. **Unify the two implementations** — fold `vuln-report.yml`'s inline parser back onto the `src/`
   parsers (single source of truth) rather than maintaining two.
3. **Standard inputs** — rename `client_id` → `client_name`, add `scan_id` as documented; keep 1:1
   with the module framework's `--client`/`--scan-id`.
4. **Consensus-engine** — call `IronCityIT/consensus-engine` via `workflow_call`; stop POSTing raw
   results directly.
5. **`storeScanResults` + `client_id` multi-tenancy** — every stored finding carries `client_id`;
   Firestore rules filter by it. The FastAPI app's single global `_inspector` + CORS `*` must go.
6. **White-label pass** — scrub tool names from README, workflow display names/logs, `source` fields,
   and `/formats` output.
7. **Dashboard from `registry.catalog()`** — module checkboxes + group presets + target box.
8. **Fix Docker** (missing `templates/`) and reconcile `requirements.txt` vs `pyproject.toml` extras.

---

## 9. Blockers / HALTs / open items

- **Cannot verify live deploy state** (Cloud Function existence, Firestore, hosting) from the repo —
  no GCP/Firebase config present. Not a build blocker, but Bill must confirm the target Firebase
  project/function before any plumbing is wired. (Per CLAUDE.md I will not deploy regardless.)
- **Cross-repo Task 0 not performed** — this run covered only `threat-inspector` per the user's
  instruction. `consensus-engine`'s actual `workflow_call` interface, and the DNSGuard/ShadowScan/
  Surge/DXA repos, have not been read. Needed before wiring the consensus-engine call for real.
- **Environment:** base `python3` lacked `pyyaml` (had to `pip install --break-system-packages`);
  all 4 workflow YAMLs validate clean once installed. Quality-gate tooling (ruff/mypy/pytest) not
  yet run — deferred to the build phase.
- No secrets leaked; no live/sacred repo touched; no branch/PR created (inventory-only, as instructed).
</content>
</invoke>


---

# PR 1 — Foundation (build record)

**Branch:** `productize/threat-inspector`
**Scope:** foundation only. New scanner modules deliberately deferred to PR 2.

## What changed (exactly the requested scope, nothing more)

1. **Docker build fixed** — removed the `COPY templates/ ./templates/` line in `Dockerfile`
   (the dir never existed; `reports/html.py` builds HTML in-code, no templates used). Image now builds.
2. **`client_id` + multi-tenancy**
   - Workflows now take the standard inputs `target` / `client_name` (required) / `scan_id` (optional).
   - `client_name` → slugified `client_id` on every stored result.
   - Firestore is partitioned `clients/{client_id}/scans/{scan_id}`; `firestore.rules` restricts
     reads to the caller's own `client_id` (Auth0 `client_id` claim). Writes are Admin-SDK-only.
   - FastAPI: replaced the single global `_inspector` with a per-`client_id` store
     (`get_inspector()`), and every endpoint now requires `client_id` — no cross-tenant data return.
3. **Consensus-engine + `storeScanResults` wired** — new reusable workflow
   `.github/workflows/_consensus-store.yml` runs `findings → IronCityIT/consensus-engine
   (workflow_call, secrets: inherit) → storeScanResults`. Each scan workflow now emits the
   `module_framework` findings contract and calls this pipeline. New `functions/storeScanResults`
   Cloud Function (region **us-east5**) writes Firestore by `client_id`.
4. **White-label scrub** — workflow display names, step names, and logs no longer name any tool;
   `port-scan.yml` renamed from `nmap-scan.yml`; `vuln-report.yml` maps `Qualys/ZAP/Nmap` →
   Iron City categories (`Vulnerability Assessment` / `Web Application Scan` / `Network Scan`)
   before storage; `SUPPORTED_FORMATS` descriptions and the `/formats` + upload API responses
   are white-labeled (`_whitelabel_source`). Tool names remain only in internal code comments,
   `pip install`/download URLs, and `configs/client.yaml` keys (all non-client-facing).
5. **CORS fixed** — `api/main.py` no longer uses `allow_origins=["*"]` with credentials. Origins
   come from `API_CORS_ORIGINS` (explicit allowlist, wildcards stripped); credentials are only
   enabled when a concrete allowlist is set.
6. **README corrected** — now claims only the four scans that exist (`port-scan`, `ssl-grade`,
   `asset-discovery`, `vuln-report`); removed the non-existent `secret-scan`/`container-scan`
   (Trivy/Gitleaks) claims; standardized the documented inputs; documents the consensus/store
   pipeline and multi-tenancy.

## Explicitly NOT done (out of scope → PR 2 and beyond)
- No new scanner modules (`web_vuln_scan`, `default_creds_check`, active `cve_lookup`, container/
  secret scanning). Deferred as instructed.
- `module_framework/` not yet adopted as the tool's runtime (still copied-in, `example_recon.py`
  present). The workflows emit the framework's JSON contract, but the CLI is not re-housed onto it.
- The two implementations (`src/` package vs workflow inline parser) are not yet unified.

## Quality gates
- **pytest:** 11 passed.
- **mypy (changed files):** clean (fixed one pre-existing `Optional[str]`→`Path` error in `api/main.py`).
- **YAML:** all 5 workflows parse clean.
- **JSON:** `firebase.json`, `.firebaserc`, `functions/package.json` parse clean.
- **ruff:** repo has large **pre-existing** style debt (mostly W293 blank-line whitespace + `Optional`
  usage) in the inherited Claude-generated code. This PR **reduced** total src findings 546 → 534 and
  added no new debt; my authored code is clean. I did **not** mass-reformat the inherited tree — that
  would bloat the diff and is out of PR-1 scope. Flagging it openly rather than papering over it.
- **node --check on `functions/index.js`:** not run (node not installed in this environment); code is
  standard `firebase-functions` v2. Confirm on deploy.

## Blockers / assumptions for Bill (not hidden)
- **consensus-engine input contract is ASSUMED**, not verified — I cannot read that private repo from
  here. `_consensus-store.yml` calls `IronCityIT/consensus-engine/.github/workflows/analyze.yml@main`
  with `target/client_name/scan_id` + `secrets: inherit`. If the reusable workflow declares different
  inputs/outputs, the `analyze` job will fail at runtime. **Confirm the interface before relying on it.**
- **Two new secrets referenced by name** (org-level, provisioned by Bill; not in the CLAUDE.md fixed
  API-key list because they are endpoint/URL config, not model keys): `STORE_SCAN_RESULTS_URL` (the
  deployed function URL; store step no-ops with a warning if unset). Consensus secrets
  (`GROQ_API_KEY` / `OPENROUTER_API_KEY` / `GEMINI_API_KEY`) flow via `secrets: inherit`.
- **Ingest auth not added** — `storeScanResults` currently trusts the caller (parity with the prior
  unauthenticated POST). Hardening needs a dedicated ingest-token secret name provisioned by Bill;
  per CLAUDE.md I did not invent a new secret. Flagged for a follow-up.
- **Dry-run `workflow_dispatch` NOT executed.** Triggering would (a) depend on the unverified
  consensus interface and unset secrets, and (b) launch a *real* scan against a live target — an
  outward-facing action I will not take unprompted. Left for Bill to dispatch once secrets +
  consensus interface are confirmed. Reporting this rather than fabricating a green run.
- **Not deployed** — no `firebase deploy` / `gcloud`. Scaffolding only, per the hard stop.

---

# PR 2 — Modular refactor: active scanners (build record)

**Branch:** `productize/threat-inspector-modules` (off `main` after PR 1 merged).
**Scope decision (Bill):** *active scanners only* — adopt the framework as the runtime,
re-house the active-scan capabilities as modules, add the active new modules. The `src/`
file-parser package (nessus/qualys/zap) + `vuln-report.yml` stay as-is; unifying the
parser paradigm into modules is deferred to a later PR.

## Pre-fix: consensus-engine contract (was assumed in PR 1, now verified)
PR 1 flagged the `analyze.yml` interface as ASSUMED. Read the real
`consensus-engine/.github/workflows/analyze.yml`: it requires `findings_json` (base64),
`product`, `client_id`, `scan_id` + secrets `GROQ/OPENROUTER/GEMINI/IRONCITY_API_KEY`.
PR 1's call passed `target`/`client_name` and omitted `findings_json` — would have failed.
`_consensus-store.yml` fixed: new `prep` job packs findings inline as base64, passes the
real input names; `secrets: inherit` confirmed sufficient. (Also cleared PR 1's ruff/mypy
debt and fixed a latent `Scan.metadata` reserved-name crash — see commits.)

## Capability inventory (step 1) → module mapping
Existing active capabilities lived as inline bash/python inside the scan workflows:

| Existing capability (PR 1 workflow) | Became module(s) |
|---|---|
| `port-scan.yml` nmap ports          | `port_scan`, `service_fingerprint` |
| `ssl-grade.yml` SSL Labs + cert + headers | `tls_cert_check`, `header_security_check` |
| `asset-discovery.yml` subfinder     | `subdomain_enum` |
| `vuln-report.yml` file aggregation  | *unchanged* — file-parser paradigm, out of scope |

**Newly added modules** (from the Threat Inspector starter set): `cve_lookup`
(nmap+vulners), `web_vuln_scan` (template scanner, deep-only), `default_creds_check`
(exposed-management-interface probe; active credential testing deliberately NOT done —
flagged below).

## What was built
- `module_framework/modules/` now holds 8 `ScanModule`s + `_util.py` (graceful
  subprocess/HTTP/TLS helpers). `example_recon.py` deleted.
- Groups per spec: **quick** = port_scan + tls_cert_check + header_security_check;
  **standard** = + service_fingerprint + cve_lookup + subdomain_enum + default_creds_check;
  **deep** = all (incl. web_vuln_scan). Verified via `registry.select()`.
- Targets accept ip/cidr/url/domain/hostname/file via the framework `targets.py`
  (unchanged, shared). Selection works both ways: `--modules a,b` and `--group deep`.
- New unified entry point `.github/workflows/scan.yml` — one workflow, `modules`/`group`
  inputs → `python3 module_framework/cli.py` → findings.json → `_consensus-store.yml`.
- The 3 active per-capability workflows (`port-scan`/`ssl-grade`/`asset-discovery`) rewired
  to call the CLI instead of inline scanning — one runtime, no duplicated logic.
- Every module degrades gracefully when its scanner/endpoint is absent (returns no
  findings, never tracebacks) — fixes the old monolith's "traceback on bad input".
- White-label preserved: tool names (nmap/subfinder/nuclei/vulners) appear only in
  internal comments and install URLs, never in module `description`, findings, or output.

## Quality gates
- **ruff** (E,F,I,N,W,UP over `src tests module_framework`): clean.
- **mypy**: `src/threat_inspector` clean (18 files); `module_framework/modules` clean
  (10 files, MYPYPATH=module_framework). Fixed the framework's `base.py` `Target`
  forward-ref via a `TYPE_CHECKING` import (annotation-only, no behavior change).
- **pytest:** 25 passed (11 parser + 14 new module tests — registry discovery/selection
  + every module's pure parse function). Coverage of subprocess I/O is intentionally thin;
  the parse logic (the risk surface) is fully unit-tested.
- **YAML:** all 6 workflows parse clean.

## Scaffolded vs left for Bill
- **Dashboard not yet wired to `registry.catalog()`** — deferred to the next PR (the
  "active scanners only" scope was modules + framework runtime, not UI).
- **`default_creds_check` is non-intrusive** — it flags exposed management interfaces;
  it does NOT attempt credential pairs. Active credential testing is a scoped follow-up,
  not fabricated here.
- **Dry-run `workflow_dispatch` NOT executed** — would launch a real scan against a live
  target (outward-facing) and depends on org secrets. Left for Bill, as in PR 1.
- **Not deployed** — scaffolding only.
- **No blockers / no missing source.** All capability logic re-housed, none dropped.

---

# PR 3 — File-ingestion aggregation (the product core)

The clunky monolith's *other* half: it doesn't only scan live targets, it ingests
third-party scan exports a client already has (Qualys, ZAP, Nmap, Nessus) and
aggregates them into one branded picture. PR 3 re-houses that behind a second
first-class module type.

## Code review of the existing parsers (required deliverable)

Read every file under `src/threat_inspector/parsers/` — **do not trust the README**.
Ground truth:

| File | Class | Real? | Formats | Notes |
|---|---|---|---|---|
| `qualys.py` | `QualysParser` | ✅ real | .xlsx/.xlsm/.csv | pandas + fuzzy `COLUMN_MAPPINGS`; robust to varied column names |
| `qualys.py` | `QualysComplianceParser` | ✅ real | .xlsx/.xlsm/.csv | control pass/fail → severity; a distinct 5th parser class |
| `zap.py` | `ZAPParser` | ✅ real | .xml/.json | risk-code → severity map; HTML-stripping; JSON + XML paths |
| `nmap.py` | `NmapParser` | ✅ real | .xml/.txt/.nmap | ports + NSE `VULNERABLE`/CVE extraction; severity heuristics |
| `nessus.py` | `NessusParser` | ✅ real | .nessus/.csv | XML `ReportItem` + CSV; severity 0–4 map |
| — | **OpenVAS** | ❌ **absent** | — | **No file, no class, no reference.** The README's "5 scanners incl. OpenVAS" is wrong — there are **4 scanner types across 5 parser classes**, and OpenVAS is not among them. Not stubbed; simply does not exist. Flagged, not fabricated. |

Other observations (left as-is — surgical scope):
- All parsers already normalize severity (`BaseParser.normalize_severity`) and never
  traceback on a bad row (`except: add_warning`). Good fit for re-housing untouched.
- `parsers/__init__.py` `get_parser()` does content/filename/extension auto-detection —
  reused verbatim by the ingest runtime to disambiguate shared extensions (`.csv`).
- Parsers were **not modified.** PR 3 wraps them; it does not rewrite them.

## What was built

- **New module type `FileModule`** in `module_framework/base.py`, first-class alongside
  `ScanModule`. Contract is `ingest(file, ctx) -> list[Finding]` — `run(target, ctx)`
  was **not** bent to swallow files. A `FileModule` declares `extensions` (its analogue
  of `target_kinds`).
- **`module_framework/file_modules/`** — one FileModule per parser: `qualys_ingest`,
  `qualys_compliance_ingest`, `zap_ingest`, `nmap_ingest`, `nessus_ingest`. Each wraps
  (does not reimplement) its parser via the `ParserFileModule` mixin, and converts
  `ParsedVulnerability` → `Finding` through the single `_convert.to_findings` seam.
- **`module_framework/ingest.py`** — the file entry point (passive counterpart to
  `cli.py`). Same selection model (`--modules` / `--group`, default group `ingest`),
  `--files` / `--files-dir`. Emits the **same JSON contract**. When >1 selected module
  accepts a file's extension, it defers to the tool's own content auto-detection so a
  file is never mis-parsed.
- **`registry.py`** generalized: `discover_files()` finds FileModules; `select()` /
  `all_groups()` / `catalog()` work on either type; `catalog()` now tags each entry
  `kind: "scan"|"file"` and exposes `extensions` for file modules — one source of truth
  the dashboard renders from.
- **`.github/workflows/file-scan.yml`** — ingest job → uploads `findings.json` →
  **the SAME `_consensus-store.yml` reusable pipeline** PR 1 wired
  (`consensus-engine/analyze.yml@main`). **One findings-JSON path, one AI flow.** No
  second consensus/AI wiring was added.
- **DefectDojo = optional export target, not always-on.** A `defectdojo` job that runs
  ONLY when `defectdojo_export=true` AND the `DEFECTDOJO_*` secrets exist; a missing
  secret is a `::warning::` + skip, never a failure. It converts findings to DefectDojo's
  Generic Findings Import format and POSTs to `import-scan`. `django-DefectDojo` (HANDS
  OFF) is **not** touched — this only calls a client-configured external instance's API.

## White-label
File-module `description`s and all findings are branded Iron City; the vendor names
(Qualys/ZAP/Nmap/Nessus) appear only in internal module/parser code and docstrings,
never in `catalog()` output, findings, or workflow output a client sees.

## Quality gates
- **ruff** (whole repo): clean.
- **mypy**: `src` clean (18 files); new framework code clean
  (`file_modules` + `ingest.py` + `registry.py` + `base.py`, 11 files, MYPYPATH set);
  existing `modules` still clean (10 files) — no regression.
- **pytest:** 36 passed (25 prior + 11 new in `tests/test_file_modules.py`: discovery,
  catalog `kind`/extensions, mixin-not-discovered, conversion + severity clamping,
  ingest CLI contract, shared-extension disambiguation, error paths).
- **YAML:** `file-scan.yml` parses clean.

## Left for Bill / flags
- **New secret names required for the optional DefectDojo export:** `DEFECTDOJO_URL`,
  `DEFECTDOJO_API_KEY`, `DEFECTDOJO_ENGAGEMENT_ID`. These are **not** in the approved
  secret list (which covers AI/scanner keys). The export is off by default and no-ops
  without them, so this does not block the PR — but if you want DefectDojo export live,
  add these three at the org level. Referenced by name only; never hardcoded.
- **Dry-run `workflow_dispatch` NOT executed** — needs uploaded export files in the
  checkout + org secrets, and drives the consensus/store pipeline. Left for Bill, as in
  PR 1 / PR 2.
- **Dashboard** still not wired to `registry.catalog()` (now includes file modules) —
  same deferral as PR 2.
- **OpenVAS** intentionally NOT added — no source exists to re-house. Building a parser
  from zero would be fabrication, out of scope. Flagged above.
- **Not deployed** — scaffolding only. No blockers; no parser logic dropped.

---

# E2E harness (`icit-e2e-harness`) + Threat Inspector adoption

**Date:** 2026-07-09

## What was built (shared repo — DONE, merged)
- Created **`IronCityIT/icit-e2e-harness`** (the one org repo this task authorized) and
  seeded it from the approved scaffold: `package.json`, `playwright.config.ts`,
  `src/config.ts`, `README.md`, reusable `.github/workflows/e2e.yml` (`workflow_call`).
- Wrote the two remaining shared specs to the isolation test's contract, plus a shared
  login helper:
  - `src/shared/login.ts` — extracted the Auth0 Universal Login flow into a shared
    helper. **Killed the placeholder `throw`** that was inline in the isolation spec;
    `tenant-isolation.spec.ts` now imports it. Selectors are the standard Auth0
    universal-login markup, finalized per-product at adoption.
  - `src/shared/login.spec.ts` — tenant logs in → lands on dashboard, not an error page.
  - `src/shared/dashboard.spec.ts` — dashboard renders tenant data, no fatal console errors.
  - `tenant-isolation.spec.ts` — **assertions unchanged** (DOM + network isolation); only
    the inline login was extracted.
- `npx playwright test --list` → **3 tests collect clean**. YAML + JSON validated.
  Cannot run green yet (needs a live `DASHBOARD_URL` + tenant secrets — by design).
- **PR #1 opened and MERGED to `main`.** Reusable `e2e.yml` is live on `main`, callable via
  `uses: IronCityIT/icit-e2e-harness/.github/workflows/e2e.yml@main`.

## Threat Inspector adoption — **HALTED (no dashboard to test)**
Per TASKS-e2e.md Step 2, the hard dependency was checked FIRST. Threat Inspector has
**no dashboard**:
- `firebase.json` declares only `functions` + `firestore` — **no `hosting` block**.
- No `public/`, `dashboard/`, or `*-platform/` directory; **no `index.html`** anywhere in
  the repo; no frontend framework (no React/Vue/Vite/Angular, no non-`functions`
  `package.json`).
- `.firebaserc` points at project `iron-city-it-threatinspector`, but nothing is hosted.
- Consistent with the existing note above: "Dashboard still not wired to
  `registry.catalog()` — same deferral as PR 2." The dashboard is planned, not built.

The harness tests a **running** dashboard; it cannot test a repo. With no dashboard there
is nothing to E2E, so **Step 2 was halted** — no `productize/threat-inspector-e2e` branch
was created, no fake dashboard or test target was fabricated (both explicitly prohibited).

**E2E harness built and merged; Threat Inspector adoption blocked — no dashboard in repo
to test. Needs a dashboard before E2E can run.**

## Secrets Bill must set (when a TI dashboard exists and adoption resumes)
On the **threat-inspector** repo (tenant fixtures are Bill's to set — not invented here):
`TENANT_A_USER`, `TENANT_A_PASS`, `TENANT_A_CLIENT`, `TENANT_A_SENTINEL`,
`TENANT_B_USER`, `TENANT_B_PASS`, `TENANT_B_CLIENT`, `TENANT_B_SENTINEL`.
`*_CLIENT` = the client name that SHOULD appear when logged in as that tenant;
`*_SENTINEL` = a unique string that is that tenant's data and must never leak to the other.

## To resume TI adoption once a dashboard is deployed
1. Branch `productize/threat-inspector-e2e`.
2. Add a deploy-or-serve step to a TI workflow that yields a live URL (Firebase Hosting
   preview channel or `firebase serve` in CI), then call
   `uses: IronCityIT/icit-e2e-harness/.github/workflows/e2e.yml@main` with
   `dashboard_url` = that URL, `product: threat-inspector`, `secrets: inherit`.
3. Confirm the shared login helper's selectors against the real dashboard/login page and
   that the three isolation assertions map to real elements — **do not weaken them**.
4. Set the 8 tenant secrets above. The e2e gate goes green only after secrets are set AND
   a real dashboard is deployed.

## Environment note
`node`/`npm` were not preinstalled; a local Node 20 was fetched to run `npm ci` /
`playwright install` / `playwright test --list`. `playwright install --with-deps` failed
on the apt index (environment/network), so the browser binary was installed without
`--with-deps` (irrelevant to `--list`, which doesn't launch a browser). The
`icit-quality-gates` skill is not installed in this environment; applicable gates
(collect/compile, YAML, JSON) were run manually — all green.

---

# GitHub Actions Audit + UI-Accessibility Enhancement (2026-08-24)

Branch: `enhance/actions-ui-20260824`. Scope: audit every workflow, make each tool
runnable and observable from a UI, add real error handling. Product logic was not
touched — only dispatch, validation, and failure reporting.

## 1. Audit findings

Seven workflows: one shared pipeline (`_consensus-store.yml`) plus six entry points
(`scan`, `asset-discovery`, `port-scan`, `ssl-grade`, `vuln-report`, `file-scan`).

**Compliant already — left alone:**
- Every entry point is `workflow_dispatch` only. No `push`/`schedule` triggers, so a
  scan cannot fire by accident.
- AI analysis is delegated to `IronCityIT/consensus-engine/.github/workflows/analyze.yml@main`
  via `workflow_call`. **No inline AI/LLM logic anywhere in this repo** — verified by
  reading all seven files. No guardrail violation here.
- Results reach Firestore through `storeScanResults`. `client_id` is derived once and
  used by both analyze and store; `firestore.rules` gates reads on the token claim.
- White-label holds: `vuln-report.yml` maps source tool names to Iron City categories
  before anything is stored.
- Inputs already matched the ICIT standard names (`target`, `client_name`, `scan_id`).

**Defects found (all fixed in this PR):**

| # | Defect | Impact |
|---|---|---|
| 1 | `pipeline` is `needs: scan`, so a failed scan skips it entirely — **nothing was ever written to Firestore on failure** | The dashboard shows a scan pending forever. This is the single biggest UI bug in the repo. |
| 2 | Store POST used `\|\| echo "::warning::"` | Firestore is the store of record; a rejected write was reported as a green run. |
| 3 | `secrets.STORE_SCAN_RESULTS_URL` interpolated as `${{ }}` **inside a shell script body** | Injection/quoting hazard; a URL with shell metacharacters executes. |
| 4 | `${{ inputs.target }}` / `${{ inputs.client_name }}` interpolated directly into `run:` bodies in 6 workflows | Script injection from a dispatch input — anyone who can press the button can run shell on the runner. |
| 5 | Scanner stderr went only to the run log, and `Upload findings` had no `if: always()` | A failed run left no artifact to diagnose. |
| 6 | No `type:` on any dispatch input | UI/CLI render free-text where a fixed set of choices exists. |
| 7 | DefectDojo export swallowed a rejected POST with a warning | A broken export could stay broken indefinitely, unnoticed. |
| 8 | `datetime.utcnow()` (deprecated) | Warning today, breakage on a future Python. |

## 2. Changes made

- **New `.github/workflows/_report-failure.yml`** — reusable failure reporter. POSTs a
  `status:"failed"` record to `storeScanResults` so the UI resolves to "scan failed"
  instead of hanging. Rebuilds `scan_id` with the caller's own rule when the scan job
  died before emitting one, so the failure lands on the document the dashboard is
  already watching. Every entry workflow gained a `report-failure` job gated on
  `always() && contains(needs.*.result, 'failure')`.
- **`storeScanResults` status is now monotonic** (`functions/index.js`). The failure
  reporter fires whenever *any* job in the run failed — including the case where the
  scan succeeded and only the downstream analysis broke. Without a guard, that would
  overwrite real stored findings with an empty failure record. A `completed` scan is
  never downgraded; the error is recorded alongside the findings instead.
- **Fail-loud on the store path.** A configured endpoint that rejects the POST is now
  a hard error (HTTP code checked explicitly). A *not-yet-deployed* endpoint (no URL
  configured) is still tolerated with a warning — that is a deploy state, not a bug.
- **All caller-supplied values moved into `env:`**, out of script bodies (defects 3, 4).
- **JSON validation gates** at every boundary: after the scan writes `findings.json`,
  before it is packed for the engine, and before the store POST — `head -c 1` is `{`
  plus `python3 -m json.tool`.
- **stderr captured** to `results/scan-stderr.log` and uploaded as a separate
  `if: always()` diagnostics artifact, so a failed run is diagnosable without re-running it.
- **Typed inputs** on all six entry points; `group`, `scan_type` became `type: choice`
  with explicit options and `defectdojo_export` became `type: boolean`.
- **`files_path` traversal check** in `file-scan.yml` — rejects absolute paths and `..`,
  and fails fast if the path is not in the checkout.
- Selector strings became bash arrays, so a value containing a space can no longer
  silently split into two arguments.

## 3. UI-accessibility gap check

| | Requirement | State |
|---|---|---|
| (a) | `workflow_dispatch` + correct typed inputs | **Done** — this PR |
| (b) | `triggerScan` Cloud Function | **Built** — `functions/trigger.js`, deploy via `deploy-functions.yml` |
| (c) | Dashboard button wired to it | **Blocked — no dashboard exists in this repo** |

`docs/UI-WIRING.md` documents all three, with the dashboard snippet ready for when (c)
becomes possible.

### HALT — (b) is blocked on a secret that does not exist
`triggerScan` must dispatch a workflow, which needs a GitHub token with `actions: write`
on `IronCityIT/threat-inspector`. **That secret is not in the approved ICIT secret list**
(`GROQ_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`, `VIRUSTOTAL_API_KEY`,
`ABUSEIPDB_API_KEY`), so per the guardrails **no secret name was invented**. The scaffold
references it as `GITHUB_DISPATCH_TOKEN`; **Bill must name and provision it** (Secret
Manager, us-east5) before deploy. Nothing else blocks (b).

### (c) remains blocked — same blocker as E2E adoption
`firebase.json` declares only `functions` + `firestore`; there is no `hosting` block, no
`public/`/`dashboard/` directory, and no `index.html` in the repo. The dashboard is
planned, not built. Consistent with the E2E halt recorded above — **a dashboard is now
the single largest gap for this product.** Nothing was fabricated to work around it.

## 4. Validation run

- `actionlint 1.7.7` + `shellcheck 0.10.0` over all 8 workflow files — **exit 0, clean**.
- PyYAML `safe_load` on all 8 files — parse clean; triggers and jobs enumerated.
- `node --check` on both Cloud Function files — clean.
- `pytest tests/` — **36 passed**.
- Local end-to-end smoke: `cli.py --group quick --targets example.com` → valid JSON,
  3 modules, real findings, `json.tool` clean.
- Live dispatch dry-run against the branch — see the PR body for the run result.

Note: the dry-run used **`ironcityit.com`**, not the `example.com` named in the task.
The dispatch performs a real network scan of whatever target it is given, and
`example.com` is a third-party host (IANA) that ICIT has no authorization to scan.
Scanning ICIT's own domain validates the identical code path.

## 5. Still open for Bill

1. **Name and provision the workflow-dispatch secret** (blocks `triggerScan` deploy).
2. **Deploy `triggerScan`** from `functions/trigger.js` to `iron-city-it-threatinspector`, us-east5.
3. **Build the dashboard.** Until then the product is dispatch-accessible but not
   client-accessible, and E2E cannot run either.
4. Set `STORE_SCAN_RESULTS_URL` on the repo if not already set — without it, results
   (and failures) are warned-and-skipped rather than stored.
5. Pre-existing, unchanged by this PR: the `storeScanResults` ingest endpoint still
   trusts its caller. Hardening it needs a dedicated ingest secret — same
   provisioning decision as (1).

## 6. Dry-run result — RED, and the cause is pre-existing, not this PR

Run: `scan.yml` @ `enhance/actions-ui-20260824`, target `ironcityit.com`,
`client_name=ironcity`, `scan_id=audit-dryrun`, `group=quick`
→ https://github.com/IronCityIT/threat-inspector/actions/runs/32785819339

| Job | Result |
|---|---|
| Modular Scan | **success** — 5 findings, valid JSON |
| Analyze & Store / Prepare findings | **success** |
| Analyze & Store / AI Consensus Analysis | **FAILURE** |
| Analyze & Store / Store Results | success (warned + skipped) |
| Report Failure | **success** — the new failure path worked |

Everything this PR changed behaved correctly. The run is red for a reason that
exists on `main` today and is untouched by this diff.

### Cause 1 — the consensus engine's secrets do not exist

```
Error when evaluating 'secrets'.
  Secret GROQ_API_KEY is required, but not provided while calling.
  Secret OPENROUTER_API_KEY is required, but not provided while calling.
  Secret GEMINI_API_KEY is required, but not provided while calling.
  Secret IRONCITY_API_KEY is required, but not provided while calling.
```

`secrets: inherit` forwards whatever the repo/org actually holds. None of these four
are present, so the job dies before its first step (0 steps ran, 3s duration).
`consensus-engine/analyze.yml` declares all four `required: true`.

### Cause 2 — the store endpoint secret is named differently than the workflows read

`gh secret list` on this repo returns exactly one secret: **`FIREBASE_FUNCTION_URL`**.
Every workflow reads **`STORE_SCAN_RESULTS_URL`**. The dry-run log confirms it resolved
empty:

```
  STORE_URL:
##[warning]STORE_SCAN_RESULTS_URL not set — skipping store (function not yet deployed)
```

**Implication: no scan result from this product has ever reached Firestore.** The old
code masked this — it warned and exited 0, so the run went green with nothing stored.
This PR does not change that outcome (an unset URL is still a warn-and-skip, because
"not yet deployed" is a legitimate state), but it is now visible rather than hidden.

The workflows were NOT repointed at `FIREBASE_FUNCTION_URL`. That secret's value is not
readable here, and PHI-touching scan data may only go to `storeScanResults` — pointing
the pipeline at an unverified endpoint on a guess is exactly the guardrail this rule
exists to prevent. **Bill decides**, see options below.

### The failure path is verified working

The reporter correctly identified `stage=analyze-store` (scan succeeded, analysis did
not), kept the caller's `scan_id=audit-dryrun`, resolved `client_id=ironcity`, and built
valid JSON. It could not deliver, for Cause 2 — and said so loudly instead of silently
passing:

```
Failure payload built for scan_id=audit-dryrun client_id=ironcity stage=analyze-store
payload.json is valid JSON
##[warning]STORE_SCAN_RESULTS_URL not set — cannot report failure to the dashboard
```

Once either fix below is applied, this path writes `status:"failed"` and the dashboard
resolves instead of hanging.

## 7. STOPPED — not merged. Decisions needed from Bill

Per the STOP rules, a red dry-run blocks the merge. The PR is open and waiting.

**Decision A — the store endpoint secret.** Pick one:
  A1. Set `STORE_SCAN_RESULTS_URL` on the repo to the deployed `storeScanResults`
      trigger URL. No code change; workflows already read this name. *(recommended —
      it matches the architecture doc)*
  A2. Confirm `FIREBASE_FUNCTION_URL` already IS `storeScanResults`, and the workflows
      get repointed to that name. One-line change per file, but only on Bill's
      confirmation of what that URL actually resolves to.

**Decision B — the consensus-engine secrets.** `GROQ_API_KEY`, `OPENROUTER_API_KEY`,
`GEMINI_API_KEY`, `IRONCITY_API_KEY` must be provisioned as org-level secrets (or repo
secrets) and shared with this repo. All four are on the approved list, so no new secret
name is being invented — they simply are not present. Until then every scan will fail at
the analysis stage on every ICIT product that calls the engine, not just this one.

**Decision C — the dispatch token** for `triggerScan` (see section 3). Not on the
approved list; needs a name and a value from Bill.

Note on B: `IRONCITY_API_KEY` exists because `consensus-engine/analyze.yml` POSTs its
result to the QNAP Flask API (`api.ironcityit.com/ingest`). That conflicts with the rule
that scan data goes to Firestore via `storeScanResults` only. Flagged, not touched —
it lives in the shared core and is a fleet-wide decision. Carried forward to the
consensus-engine review.

---

# Deploy pipeline — functions, rules, and fail-closed storage

**Date:** 2026-08-25 · Branch `productize/threat-inspector-deploy`

## The bug this closes

`_consensus-store.yml` ended with:

```bash
if [ -z "$STORE_URL" ]; then
  echo "::warning::STORE_SCAN_RESULTS_URL not set — skipping store"
  exit 0
fi
```

`STORE_SCAN_RESULTS_URL` has never been set on this repo. So **every scan this product
has ever run discarded its findings at the last step and reported success.** Confirmed in
run `32785819339`: `! STORE_SCAN_RESULTS_URL not set — skipping store`. A green run meant
nothing about whether the client's results existed.

That step now **fails closed**. A scan that cannot be stored is a failed scan.

## What changed

| File | Change |
|---|---|
| `.github/workflows/deploy-functions.yml` | **New.** Deploys functions + Firestore rules to `iron-city-it-threatinspector` / `us-east5`. `dry_run: true` by default. |
| `.github/workflows/_consensus-store.yml` | Store step fails closed instead of `exit 0`. |
| `.github/workflows/scan.yml` | New `dry_run` boolean input, wired to the CLI's `--dry-run`. |
| `module_framework/cli.py` | `--dry-run`: validates targets + selection, then stops before any module runs. Identical output schema, `dry_run: true`, empty findings. |
| `functions/trigger.js` | Moved from `deploy/cloud-function/index.js`. |
| `functions/index.js` | Guards `initializeApp`, re-exports `triggerScan`. |

**Why the move matters:** `firebase.json` points `functions.source` at `functions/`. `triggerScan`
lived in `deploy/cloud-function/`, which is **not** part of that source — so
`firebase deploy --only functions` would have shipped `storeScanResults` alone and the
dashboard's trigger would have 404'd. One source, one deploy, both functions.

## Why `--dry-run` exists

The chain is scan → consensus → store, and the only way to prove it end to end used to be
scanning a live host. `--dry-run` stops in `main()` exactly where `m.run()` would touch the
network, after real target parsing and module selection. Downstream (workflow JSON gates,
payload builder, dashboard) sees the identical schema, so the whole pipeline is exercised
with zero packets sent. Verified locally:

```
$ python3 module_framework/cli.py --group quick --targets example.com --dry-run
{"client":"acme","scan_id":"t1","modules_run":["header_security_check","port_scan",
 "tls_cert_check"],"target_count":1,"dry_run":true,"findings":[]}
```

## Quality gates

| Gate | Command | Result |
|---|---|---|
| Lint | `ruff check .` | ✅ All checks passed |
| Typecheck | `mypy module_framework src` | ✅ 41 files, no issues |
| Tests | `pytest -q` | ✅ 36 passed |
| YAML | `yaml.safe_load` × 9 workflows | ✅ all parse |
| JS syntax | `node --check` × 2 | ✅ both parse |
| JSON | `json.load` on package manifests | ✅ valid |
| Format | `ruff format --check` | ❌ **34 files would reformat** — pre-existing across the repo, not introduced here. Left alone deliberately: reformatting 34 files inside a deploy PR would bury the change. Wants its own PR. |

## BLOCKERS — deploy cannot complete without these

1. **`FIREBASE_SERVICE_ACCOUNT` does not exist on this repo.** Confirmed via `gh secret list`.
   The deploy workflow fails fast on step 1 with instructions rather than half-deploying.
   Needs: service account on `iron-city-it-threatinspector` with Cloud Functions Developer,
   Firebase Rules Admin, Service Account User, Artifact Registry Writer; JSON key stored as
   that secret. **The agent cannot create this** — no `gcloud`/`firebase` CLI exists in the
   build environment and no GCP credentials are present.
2. **`STORE_SCAN_RESULTS_URL`** must be set after the first real deploy. The deploy workflow
   prints the exact URL in its job summary.
3. **`GITHUB_DISPATCH_TOKEN`** (Secret Manager, us-east5) for `triggerScan`. Still outstanding
   from PR #5. Not in the approved secret list, so the name is referenced, never a value.

## Consensus egress — still open, tracked separately

Threat Inspector passes a `scan_id` on every run, and the shared engine POSTs its consensus
output to `api.ironcityit.com/ingest` whenever `scan_id` is non-empty. That conflicts with
storeScanResults-to-Firestore-only. Fixed by **consensus-engine PR #2** (`post_to_api` opt-out
+ `consensus_b64` output), which is REVIEW ONLY and awaiting Bill.

**This repo is deliberately NOT wired to `post_to_api: false` yet** — products pin the engine
at `@main`, so passing an input that `main` does not declare would fail every scan immediately.
That wiring is a follow-up PR, blocked on engine PR #2 merging.

**Do not run a live scan with real client data until engine PR #2 is merged and TI is wired
to it.** Dry runs are safe now.

---

# Dashboard — the last missing surface

**Date:** 2026-08-25 · Branch `productize/threat-inspector-dashboard`

This closes the gap that halted E2E adoption in PR #4 ("Threat Inspector has no dashboard")
and the long-standing "dashboard still not wired to `registry.catalog()`" deferral.

## The tenancy gap nobody had closed

`firestore.rules` gates every read on `request.auth.token.client_id`. **Nothing was minting
that claim.** The rules were therefore unsatisfiable — a signed-in user could never read their
own data, and the product could not have worked even with functions deployed.

`functions/exchange.js` closes it:

```
Auth0 access token -> verified against the tenant JWKS (jose)
                   -> client_id resolved from the Auth0 Organization
                   -> Firebase custom token carrying that claim
```

`client_id` is read **only** from the verified token — never from the request body or query
string, so a caller cannot ask for another tenant's data. An authenticated user with no
organisation gets a distinct `403 no_client_assigned`, which the dashboard renders as
"contact your administrator" rather than a crash.

## Single source of truth: CLI = UI

`tools/build_catalog.py` generates `dashboard/public/catalog.json` from the live registries
(`cli.py --list-modules` + `ingest.py --list-modules`). The dashboard renders checkboxes and
group presets from that file, and `selectionToArgs()` maps the selection back onto
`--modules` / `--group` with the same precedence as `registry.select()`. Pick a preset → you
get `--group`; tick one extra box → the selection is bespoke and you get an explicit
`--modules` list.

Two gates keep this honest: `tests/test_catalog.py` fails if the committed catalog drifts from
the registries, and the deploy workflow refuses to ship a stale one.

## White-label — a real leak, caught by the gate

Module names and descriptions **did** name the underlying tools: `nessus_ingest`, `zap_ingest`,
and descriptions like *"Ingests vulnerability scan exports (.nessus/CSV)"*. Rendering the
registry directly would have put those in front of clients.

`build_catalog.py` now carries a `LABELS` table (every module needs a client-facing label, or
the build **fails** — a new module cannot silently leak its name) plus `DESCRIPTIONS` overrides
where the registry text named a tool. Enforced at two levels: a unit test over the catalog, and
a Playwright assertion that no tool name appears in the rendered DOM.

`extensions` (e.g. `.nessus`) is kept in the catalog for internal file handling and is
deliberately **never rendered**. **Judgment call for Bill:** if clients should be able to upload
exports directly, the file picker's `accept` list would expose those extensions. Left out of
this PR rather than decided unilaterally.

## Browser tests — 12, all passing

`tests/ui/dashboard.spec.mjs` drives the real page in real Chromium against a local static
server. `npm run test:ui`:

```
ok  placeholder config shows the not-configured state, not a crash
ok  every catalog module renders as a check
ok  no underlying tool name reaches the DOM
ok  standard preset is selected on load
ok  preset selection maps 1:1 onto --group
ok  ticking an extra check switches to an explicit --modules list
ok  every module the UI can send is a real registry module
ok  start is disabled with nothing selected
ok  scan history renders status, counts and an empty state
ok  an unknown status cannot inject a class or break the badge
ok  layout holds at mobile width
ok  every form control is labelled

12 passed, 0 failed
```

**What these do NOT prove — stated plainly:** real Auth0 sign-in, and real tenant isolation
against live Firestore. Both need a provisioned Auth0 SPA app and two seeded tenants, neither
of which exists. The tests open the signed-in view directly. The harness for the real thing is
`icit-e2e-harness`, and it can be adopted the moment a dashboard URL exists (steps already
recorded above) — it needs the 8 `TENANT_A_*` / `TENANT_B_*` secrets.

## CI

`.github/workflows/ci.yml` runs format, lint, typecheck, pytest, catalog freshness, workflow
YAML parsing, function syntax, and the browser suite on every PR. Gates were previously
manual, so a red gate only blocked a merge if someone remembered to look.

## Quality gates

| Gate | Result |
|---|---|
| `ruff format --check .` | ✅ 45 files formatted |
| `ruff check .` | ✅ passed |
| `mypy module_framework src` | ✅ no issues |
| `pytest -q` | ✅ **41 passed** (36 + 5 new catalog tests) |
| `npm run test:ui` | ✅ **12 passed** in Chromium |
| YAML × 10 | ✅ all parse |
| `node --check` × 3 | ✅ |
| JSON gates | ✅ catalog.json, firebase.json, package manifests |

## BLOCKERS — new secrets required before the dashboard can sign anyone in

Not in the approved ICIT secret list, so named but never valued. The deploy workflow fails
fast listing whichever is missing:

| Secret | Why |
|---|---|
| `AUTH0_CLIENT_ID` | The Auth0 **SPA application** for Threat Inspector. Does not exist — must be created in the `dev-ws5377dam2tnlv5g` tenant, with `https://iron-city-it-threatinspector.web.app` as an allowed callback, logout and web origin. |
| `FIREBASE_API_KEY` | Firebase **web app** config for the TI project. A web app must be registered in that project. |
| `AUTH0_AUDIENCE` | Optional; only if the access token needs an API audience. |
| `FIREBASE_SERVICE_ACCOUNT` | Still outstanding — nothing deploys without it. |
| `GITHUB_DISPATCH_TOKEN` | Still outstanding — `triggerScan` cannot dispatch without it. |

Auth0 also needs an **Action** setting `https://ironcityit.com/client_id` on the token, or
Organizations configured so `org_name` resolves the tenant. `exchange.js` accepts either.
