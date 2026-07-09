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
