# Threat Inspector — Developer Handoff

**Repository:** `IronCityIT/threat-inspector`
**This document written:** 2026-09-07
**Written against commit:** `0e70572` (main)
**Author:** autonomous SDLC agent (Claude Opus 5), on `icit-devbox`

---

## How to read this document

Every claim carries one of three labels. Nothing else is asserted.

| Label | Meaning |
|---|---|
| **VERIFIED** | A command was run in this environment and produced the stated output. The command is given so it can be re-run. |
| **TARGET** | Intended future state under the current architectural direction. Not built, not deployed. |
| **UNKNOWN** | Not established. No credential, no access, or no capture exists. **Not guessed.** |

If you are extending this document, keep that discipline. An unlabelled claim is a
defect in this file.

> **Architectural direction, 2026-09-07.** Firebase / Firestore / Firebase Hosting /
> GCP product storage is **RETIRED** from the ICIT target architecture. GitHub
> Actions remains the execution and orchestration layer. Persistent
> application, result, configuration and audit state moves to **self-hosted,
> NAS-backed infrastructure using MariaDB**; object and artifact files move to
> NAS-backed volumes. This document describes the Firebase estate as **current
> VERIFIED implementation**, and the self-hosted estate as **TARGET**. Nothing
> has been migrated. Nothing has been deleted. No deploy has been performed.

---

## 1. Purpose

Iron City Threat Inspector is the **defensive (blue-team)** product of the ICIT
suite: continuous external monitoring, asset discovery, and vulnerability
identification for managed clients.

It does two distinct jobs, and they share a findings model:

1. **Active scanning** — runs capability modules against a client's external
   surface (ports, services, TLS, HTTP security headers, exposed management
   interfaces, subdomains, known CVEs, web vulnerabilities).
2. **Ingestion** — normalises vulnerability scan exports a client uploads
   (network XML, vulnerability-scanner XML/CSV, web-application XML/JSON,
   spreadsheet exports) into the same findings model.

Both feed one pipeline: **findings → AI consensus analysis → persistent store →
dashboard**.

**White-label rule (VERIFIED, enforced by tests).** Underlying tool names
(nmap, subfinder, nuclei, ZAP, Nessus, Qualys, SSL Labs) must never appear on a
client-facing surface — dashboards, reports, or workflow output a client sees.
Internal code comments and module source may name them. A browser test feeds raw
error text containing tool names through the dashboard's degradation notice and
asserts none reaches the DOM.

---

## 2. Current verified implementation

### 2.1 Test and gate inventory — VERIFIED

Run on this box at commit `0e70572`:

| Gate | Command | Result |
|---|---|---|
| Format | `python3 -m ruff format --check .` | ✅ 65 files |
| Lint | `python3 -m ruff check .` | ✅ all checks passed |
| Types | `python3 -m mypy module_framework src` | ✅ 42 files, no issues |
| Unit + integration | `python3 -m pytest -q` | ✅ **452 passed** |
| End-to-end smoke | `python3 tools/smoke_test.py` | ✅ **44/44**, 0 skipped |
| Catalog freshness | `python3 tools/build_catalog.py && git diff --exit-code` | ✅ zero diff |
| Workflow YAML | `yaml.safe_load` × 10 | ✅ all parse |

CI (GitHub Actions, workflow `ci.yml`) runs seven jobs and was green on the last
four merges: **Lint/types/tests, End-to-end smoke test, Dashboard catalog is
current, Dashboard browser tests, Firestore rules (emulator), Workflow YAML
parses, Cloud Functions parse.**

JavaScript-side suites (VERIFIED as executed in CI, not re-run here today):
functions **27 passed**, dashboard browser **16 passed**, Firestore rules against
a real emulator **15 passed**.

Coverage at `0e70572`: **76% overall**. Notable per-file: `tls_cert_check` 98%,
`nessus` 91%, `zap` 89%, `core` 70%, `cli.py` **0%**, `models/__init__.py` **0%**.

### 2.2 What was fixed in the four merges of 2026-09-06 — VERIFIED

Each was reproduced against real listeners or real generated inputs before the fix,
and each carries regression tests that fail against the unfixed code.

| PR | Defect | Evidence |
|---|---|---|
| #13 | Unauthenticated REST API served any tenant's data to anyone naming them | 22 tests |
| #13 | A large scan lost every finding to a rejected Firestore write | 9 tests |
| #13 | Client-facing report interpolated six values with no escaping | 48 tests |
| #13 | A scan export carrying a CVSS score could not be reported at all | 32 tests |
| #13 | Exposed-management-interface check blind to a panel on a bare IP: `0 findings` over both HTTP and self-signed HTTPS against a live 401 listener | 12 tests |
| #13 | Six ways an uploaded export was silently reduced — BOM eating the first CSV column (worst case: **entire export ingested as zero findings, no error, no warning**), 128 KB field cap losing whole files, web risk-as-word grading a SQL injection *informational*, empty CVSS v3 shadowing v2, dropped CVEs, unread timestamps | 43 tests |
| #14 | Deduplication kept the longer *description*, so a critical RCE lost to an informational duplicate — the critical and its CVSS score left the report | 34 tests |
| #14 | Enrichment replaced a scanner's short specific fix with generic boilerplate | included above |
| #15 | A security header set to a value that does nothing (`max-age=0`, `ALLOWALL`, non-`nosniff`, `unsafe-url`, CSP with `'unsafe-inline'`) counted as protection | 36 tests |
| #16 | **An expired certificate on a live host produced no finding at all** — `fetch_cert` validated the peer and returned `None` on any failure, which `run()` read as "no expiry finding" | 48 tests |

The common shape: **silence read as success.** None of these crashed; none failed
a gate; all made the product report less than the truth.

### 2.3 Component map — VERIFIED

```
module_framework/           the product core; what the workflows actually run
  base.py                   ScanModule ABC, Finding dataclass, IngestReport
  cli.py                    scan entry point; module selection, target parsing,
                            failure containment, run-health status, JSON output
  registry.py               module discovery + catalog() (one source of truth
                            for the CLI and the dashboard)
  targets.py                IP / CIDR / URL / domain / hostname / file parsing
  ingest.py                 file-ingestion dispatch
  modules/                  active scan capabilities (8)
  file_modules/             export-ingestion capabilities (5)

src/threat_inspector/       the library + local REST API
  core.py                   ThreatInspector: load, deduplicate, enrich, summarise
  api/main.py               FastAPI app (what the Dockerfile runs)
  api/auth.py               bearer-token → tenant resolution
  parsers/                  nmap, nessus, zap, qualys export parsers
  reports/html.py           client-facing HTML report (escaped at every site)
  models/__init__.py        SQLAlchemy relational models — 0% coverage, nothing
                            imports them (see §4.1: these become the foundation)
  cli.py                    legacy console entry point — 0% coverage, unused
  utils/                    compliance mapping, remediation guidance

tools/                      build_catalog.py, build_store_payload.py, smoke_test.py
functions/                  Firebase Cloud Functions (RETIRING — see §5)
dashboard/public/           Firebase-hosted SPA (RETIRING — see §5)
.github/workflows/          10 workflows (see §7)
```

### 2.4 Scan modules — VERIFIED

| Module | Group(s) | Target kinds | External tool |
|---|---|---|---|
| `port_scan` | quick, standard, deep | ip, domain, hostname | nmap |
| `service_fingerprint` | standard, deep | ip, domain, hostname | nmap |
| `cve_lookup` | standard, deep | ip, domain, hostname | nmap (vulners NSE) |
| `tls_cert_check` | quick, standard, deep | domain, hostname, url | none (stdlib TLS) + SSL Labs API |
| `header_security_check` | quick, standard, deep | domain, hostname, url | none |
| `default_creds_check` | standard, deep | (all) | none |
| `subdomain_enum` | standard, deep | domain | subfinder |
| `web_vuln_scan` | deep | url | nuclei |

File-ingestion modules: `nmap_ingest`, `nessus_ingest`, `zap_ingest`,
`qualys_ingest`, `qualys_compliance_ingest`.

**VERIFIED defect, not yet fixed:** a module whose external tool is not installed
returns an empty list and is recorded as a *successful run with zero findings*.
Reproduced at `0e70572`:

```
$ python3 module_framework/cli.py --modules subdomain_enum --targets example.selftest.invalid
status: ok | findings: 0 | stats: {'module_runs': 1, 'module_runs_failed': 0}
```

`subfinder` is not installed on this box, so nothing was enumerated — and the run
reported `ok`. A fix exists on branch `feat/threat-inspector-capability-reporting`
(commit `5d37c67`, **unmerged, not reviewed against this architecture**); see §12.

---

## 3. Target architecture

### 3.1 Direction — TARGET

```
GitHub Actions workflow  (execution / orchestration — UNCHANGED)
  └─ calls IronCityIT/consensus-engine via workflow_call    (AI analysis)
       └─ POSTs results to a self-hosted ingest on ICIT NAS-backed infra
            └─ MariaDB, rows scoped by client_id            (multi-tenant)
                 └─ artifacts/objects on NAS-backed volumes
                      └─ self-hosted dashboard reads MariaDB, SSO login
```

What stays, what goes:

| Concern | Current (VERIFIED) | Target (TARGET) |
|---|---|---|
| Orchestration | GitHub Actions | GitHub Actions — **unchanged** |
| AI analysis | `consensus-engine` via `workflow_call` | unchanged — called, never copied |
| Result store | Firestore `clients/{id}/scans/{id}` | MariaDB on NAS-backed storage |
| Ingest endpoint | `storeScanResults` Cloud Function | self-hosted HTTP ingest |
| Artifacts | Firestore document fields (800 KB budget) | NAS-backed volume, DB holds the reference |
| Dashboard hosting | Firebase Hosting | self-hosted |
| AuthN | Auth0 → Firebase custom token | Auth0 (retained) → self-hosted session/JWT |
| AuthZ / tenancy | `firestore.rules` on `client_id` claim | DB-layer scoping + server-side authorization |
| Region | GCP us-east5 | ICIT NAS + owned hosts |

### 3.2 The self-hosted estate — VERIFIED reachability

Probed from `icit-devbox`, 2026-09-07T20:23Z. Read-only banner reads only; no
authentication attempted, nothing written.

| Host / endpoint | Evidence | Result |
|---|---|---|
| `192.168.1.177:3306` | TCP banner | **`5.5.5-10.5.8-MariaDB-log`** — MariaDB 10.5.8 live |
| `192.168.1.177:22` | TCP banner | `SSH-2.0-OpenSSH_10.3` |
| `192.168.1.177:80` | `HEAD /` | `302 → https://192.168.1.177:8081/` (Apache; QTS admin) |
| `192.168.1.177:443` | TCP connect | open |
| `192.168.1.177:8080` | `HEAD /` | `200 OK` |
| `api.ironcityit.com` | DNS | `104.21.94.15` (Cloudflare-fronted) |
| `api.ironcityit.com/` | `HEAD` | `404` (Flask default) |
| `api.ironcityit.com/ingest` | `GET` | `405 Method Not Allowed` → POST-only |
| `api.ironcityit.com/ingest` | `POST {}` unauthenticated | **`401 {"error":"Unauthorized"}` — fail-closed** |

That last row is the documented health check in
`ICIT-Infrastructure/hosts/qnap-nas-01/SERVICES.md` and it passes: the
self-hosted ingest is up and authenticating.

**The host is `qnap-nas-01`, QNAP TS-453D, `192.168.1.177`** (per
`ICIT-BUILD-INVENTORY.md`). It already runs IronClad/CISO Assistant, Iron Vault
(Passbolt), OpenBB, Jenkins, `ironcity-api` (Flask/MariaDB), a Cloudflare tunnel,
watchtower and Prowler. Shell is BusyBox. Backups: HBS3 → Google Drive, and
restic → Backblaze B2 bucket `ironkeep-fleet`.

### 3.3 What is NOT known about the target — UNKNOWN

These are the blockers. **None of them may be guessed.**

| Unknown | Why it matters | What would resolve it |
|---|---|---|
| MariaDB credentials, host-internal bind address, and whether 3306 is reachable from a GitHub-hosted runner | Nothing can be written or migrated without them | A credential in a secret, plus a decision on network path (tunnel vs. runner egress) |
| Existing `ironcity-api` MariaDB schema and database name | A new product schema must not collide with, or duplicate, what exists | A schema capture, or the `ironcity-api` source |
| The `/ingest` request contract — field names, auth header form, response shape | `consensus-engine` already POSTs here with `IRONCITY_API_KEY`; Threat Inspector would need the same contract | `ironcity-api` source, or a capture from `consensus-engine/analyze.yml` |
| Whether `/ingest` enforces per-tenant scoping and RBAC | Multi-tenancy is non-negotiable; an ingest that does not scope is not usable as-is | Source review of `ironcity-api` |
| Whether `ironcity-api` has a source repository at all | There is no `ironcity-api` repo in the `IronCityIT` org listing | Ask Bill; or capture from the host |
| NAS backup/restore procedure *for the application database specifically* | DR for product data | `restic` repo/tag/retention for this host — `SERVICES.md` lists this as "to be filled in from a capture" |
| What terminates TLS for `api.ironcityit.com` and how traffic reaches the host | Deployment and failure modes | Listed as uncaptured in the infra repo |
| Which NAS volume/share is intended for product artifacts | Object storage target | A decision |

`ICIT-Infrastructure/hosts/qnap-nas-01/SERVICES.md` states plainly at the top:
**"NOT CAPTURED. Expected shape. Ports and start commands unverified."**

### 3.4 Cross-repo conflict to resolve — VERIFIED, flagged not fixed

`IronCityIT/ICIT-Infrastructure/ARCHITECTURE.md` currently states, as the fleet
standard:

> "**Firestore is the store of record.** Not the QNAP Flask API. DNS Guard used to
> POST its report to QNAP and never write Firestore […] That is fixed."

That is the **opposite** of the current direction. It is also fleet-wide: it binds
AttackSimPro, DNS Guard, ShadowScan, Surge and DEA, not just this product.

`ICIT-Infrastructure` is **not** in the IN SCOPE list in `CLAUDE.md`
(`threat-inspector`, `shadowscan`, `surge`, `dynamic-experience-analyzer`,
`ICIT-DNSGuard`), so per the standing rule it is **HANDS OFF** and has not been
touched. **This needs Bill's decision and a fleet-wide update**, otherwise the
next agent to read `ARCHITECTURE.md` will re-introduce Firebase as target state.

---

## 4. Data model

### 4.1 Existing relational models — VERIFIED present, VERIFIED unused

`src/threat_inspector/models/__init__.py` — 139 statements, **0% coverage,
imported by nothing**. Previously flagged as dead code with an open
"delete, or build the persistence layer on it?" question.

**Under the new direction that question is answered: this is the foundation.**
It is already relational, already client-partitioned, and already uses
SQLAlchemy — which is a declared runtime dependency, alongside `alembic`.

```
clients (id PK, name UNIQUE, contact_email, contact_name, industry, notes,
         created_at, updated_at, is_active)
   ├─< domains        (id PK, client_id FK, name, ip_addresses JSON,
   │                   subnets JSON, description, is_active, created_at)
   └─< projects       (id PK, client_id FK, name, description,
                       start_date, end_date, status, created_at, updated_at)
          └─< scans   (id PK, project_id FK, filename, scanner_type, scan_date,
                       uploaded_at, file_hash SHA-256, raw_data_path,
                       status, error_message, metadata JSON)
                 └─< vulnerabilities
                       (id PK, scan_id FK, title, description, severity,
                        asset_name, asset_ip, asset_port, asset_url,
                        cve_id, cwe_id, cvss_score, cvss_vector, …)
```

**VERIFIED modelling mismatch that must be resolved before migration.** These
models key tenancy on `clients.id` — an autoincrement **integer**. The entire
live pipeline keys tenancy on `client_id` — a **slug string** derived from
`client_name` (`toClientId()` in `functions/index.js`, `resolveClientId()` in
`functions/exchange.js`, and the shell derivation in `_consensus-store.yml`, all
three producing the same lowercase-hyphen slug). A migration that does not
reconcile these will produce two incompatible notions of "tenant".

`raw_data_path` already exists and is the natural place for a **NAS-backed
artifact reference** — the DB holds the pointer, the volume holds the bytes.

### 4.2 The stored scan record — VERIFIED (current Firestore shape)

Produced by `tools/build_store_payload.py`, written by `storeScanResults` at
`clients/{client_id}/scans/{scan_id}`:

```
client_id, client_name, scan_id, scan_type, target,
status            "completed" | "failed"
scan_status       the scan's own health: ok | partial | failed | dry_run
summary           severity counts and totals
findings[]        module, target, severity, title, detail, evidence{}
consensus         { status }
diagnostics       { scan_status, modules_run[], target_count,
                    module_errors[], module_error_count,
                    files_failed[], rejected_targets[], stats{} }
error             present only on failure records
created_at        server timestamp
```

**Design decisions in this record that must survive any migration:**

- `status` is **monotonic**: a scan that already stored findings is never
  downgraded to `failed`. Workflows report failure whenever *any* job in the run
  failed — including runs where the scan succeeded and only downstream analysis
  broke. Clobbering those would lose real client data.
- `scan_status` is separate from `status` on purpose. An empty findings list means
  "nothing found" *or* "every capability failed", and a client must never be shown
  the first when it was the second.
- The record is **packed to an 800 KB budget**, most-severe-first, with true
  severity totals and truncation declared. Over ~2,000 findings the Firestore
  write was rejected outright and the client got *nothing* rather than a truncated
  report. **In MariaDB this constraint disappears** — findings become rows — which
  removes a whole class of data loss. This is a genuine gain from the migration.

---

## 5. Every Firebase / GCP reference, classified

**VERIFIED** — 33 non-vendor files, from
`grep -ril "firebase\|firestore\|gcp\|google-cloud\|gcloud\|cloud function"`
excluding `node_modules`.

Nothing in this table has been changed. Classification only.

### 5.1 MIGRATE — functional, must be replaced before Firebase is removed

| File | What it does | Target replacement |
|---|---|---|
| `functions/index.js` | `storeScanResults` — authenticated ingest, monotonic status, writes Firestore | Self-hosted ingest writing MariaDB |
| `functions/trigger.js` | `triggerScan` — dashboard → workflow dispatch, allow-listed workflows, tenant from verified claim | Self-hosted endpoint; keep the allow-list and the claim-derived tenant |
| `functions/exchange.js` | Auth0 token → Firebase custom token carrying `client_id` | Auth0 → self-hosted session/JWT; **`resolveClientId()` logic is architecture-independent and should be carried over verbatim** |
| `firestore.rules` | Tenant read isolation on `client_id` claim | DB-layer scoping + server-side authorization. **The 15 emulator tests encode the invariants and must be re-expressed, not dropped** |
| `dashboard/public/auth.js` | Auth0 SPA + Firebase SDK + Firestore live feed | Auth0 SPA + self-hosted API |
| `dashboard/public/config.js` | Runtime config placeholders incl. Firebase web config | Self-hosted config |
| `.github/workflows/_consensus-store.yml` | POSTs the payload to `storeScanResults`; **fails closed** if URL or token unset | Repoint to self-hosted ingest; **keep fail-closed** |
| `tools/build_store_payload.py` | Builds the record, packs to the Firestore budget | Keep the builder; the 800 KB packing becomes unnecessary |
| `.github/workflows/deploy-functions.yml` | Deploys functions, rules, hosting; injects dashboard config | Replace with self-hosted deploy |

### 5.2 RETIRE — pure Firebase platform artifacts, delete once §5.1 is replaced

`firebase.json` · `.firebaserc` · `functions/package.json` ·
`functions/package-lock.json` · `functions/node_modules/`

Note `firebase.json` also carries the dashboard's **security headers**
(`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`) and the SPA rewrite. Those are real controls —
they must be re-implemented on whatever serves the dashboard, or the migration is
a security regression. This product's own `header_security_check` module would
flag their absence.

### 5.3 MIGRATE (tests) — the invariants matter more than the implementation

`tests/functions/rules.test.mjs` (15 cross-tenant cases against a real emulator) ·
`tests/functions/auth.test.mjs` (15) · `tests/functions/tenancy.test.mjs` (12) ·
`tests/test_firestore_rules.py` · `tests/ui/dashboard.spec.mjs` ·
`tests/test_store_payload.py`

The rules tests assert: a tenant reads only its own client document, scan and scan
list; cross-tenant reads denied in **both** directions; unauthenticated reads
denied; a caller with no `client_id` claim denied; a forged claim grants only that
tenant; collections outside `clients/` denied by default; and **no client app may
write at all**. Every one of those is a property of the *product*, not of
Firestore. They must hold on MariaDB.

### 5.4 DOCUMENTATION — update text, no code impact

`README.md` · `docs/SDLC_STATUS.md` · `docs/UI-WIRING.md` ·
`PRODUCTIZE_NOTES.md` · `TASKS.md` · `ICIT-BUILD-INVENTORY.md` ·
`module_framework/README.md` · `examples/file-ingest-selftest/README.md`

### 5.5 NOT Firebase — matched on "gcp"/"cloud" incidentally

`src/threat_inspector/api/main.py` and `src/threat_inspector/api/auth.py` are the
**self-hosted** FastAPI surface. They are already tenant-scoped by bearer token
and are **closer to target state than anything in `functions/`**. See §9.

---

## 6. Execution flow — VERIFIED

### 6.1 Active scan

```
workflow_dispatch (or weekly schedule)
  → scan.yml
      → checkout, install requirements.txt, install nmap
      → python3 module_framework/cli.py --modules … / --group … --targets …
            targets parsed and validated (IP/CIDR/URL/domain/hostname/file)
            each module run inside run_module(): never raises, timed, contained
            → results/findings.json   (status: ok | partial | failed | dry_run)
      → JSON validated (first byte '{', python3 -m json.tool)
      → upload findings artifact
  → _consensus-store.yml (reusable)
      prep    : download artifact, derive client_id slug, base64-pack findings
      analyze : IronCityIT/consensus-engine/.github/workflows/analyze.yml@main
                inputs findings_json, product, client_id, scan_id; secrets: inherit
      store   : tools/build_store_payload.py → payload.json
                validate JSON → POST to STORE_SCAN_RESULTS_URL
                with Authorization: Bearer INGEST_TOKEN via --header @file
                (never argv — argv is visible in `ps` on the runner)
                FAILS CLOSED on unset URL/token, 401, 503, or any non-2xx
  → _report-failure.yml on failure
```

### 6.2 File ingestion

```
file-scan.yml → module_framework ingest → parsers/ → findings
              → same _consensus-store.yml pipeline
```

### 6.3 Local API

```
Dockerfile → uvicorn threat_inspector.api.main:app on 0.0.0.0:8000
  POST /api/v1/scans/upload      parse an uploaded export
  POST /api/v1/analyze           deduplicate, enrich, map compliance
  GET  /api/v1/vulnerabilities   filtered, worst-first
  GET  /api/v1/summary           severity counts
  every route resolves its tenant from the bearer token (api/auth.py)
```

---

## 7. GitHub Actions — VERIFIED

Execution layer. **Unchanged by the migration.**

| Workflow | Trigger | Purpose |
|---|---|---|
| `scan.yml` | dispatch, weekly cron | Modular scan; `--modules` or `--group` |
| `port-scan.yml` | dispatch | Port/service discovery |
| `ssl-grade.yml` | dispatch | TLS grading + security headers |
| `asset-discovery.yml` | dispatch | Subdomain/live-asset enumeration |
| `vuln-report.yml` | dispatch | Aggregate uploaded exports |
| `file-scan.yml` | dispatch | File-ingestion pipeline |
| `_consensus-store.yml` | `workflow_call` | Shared analyze + store |
| `_report-failure.yml` | `workflow_call` | Failure record |
| `ci.yml` | PR, push to main, dispatch | Seven quality gates |
| `deploy-functions.yml` | dispatch | Firebase deploy (**RETIRING**) |

Standard inputs, not to be renamed: `target` (required), `client_name`
(required), `scan_id` (optional).

**Consensus engine contract — VERIFIED against
`IronCityIT/consensus-engine/.github/workflows/analyze.yml@main`:** inputs
`findings_json` (base64, inline — *not* an artifact), `product`, `client_id`,
`scan_id`; `secrets: inherit`. Never assume this contract; re-verify it.

---

## 8. Configuration

| Where | What | Label |
|---|---|---|
| `configs/client.yaml` | Client name, domains/IPs/subnets, scan file paths, report settings | VERIFIED |
| `examples/config.yaml` | Example settings | VERIFIED |
| `src/threat_inspector/config.py` | Pydantic settings: `DATABASE_URL` (default `sqlite:///data/threat_inspector.db`), API host/port/CORS, remediation engine, report settings | VERIFIED |
| `docker-compose.yml` | Local container; SQLite volume; **a Postgres service is present but commented out** | VERIFIED |
| `dashboard/public/config.js` | Deploy-time placeholders | VERIFIED (RETIRING) |

`DATABASE_URL` is the natural seam for MariaDB — it already exists, is already
read from the environment, and already defaults to a file-backed database.

---

## 9. Access, authentication, RBAC

### 9.1 Local API — VERIFIED, and already at target shape

`src/threat_inspector/api/auth.py`. **The tenant is derived from the caller's
credential, never from the request.**

- `TI_API_TOKENS` maps `token → client_id`, as `token:client,token:client` or JSON.
- Presented tokens are compared with `hmac.compare_digest` against *every*
  configured token, so neither match position nor shared-prefix length leaks
  through response timing.
- A request that also names a `client_id` must name **its own**, or it is `403`.
  A stolen or shared token still cannot reach across tenants.
- **Secure by default:** with nothing configured the API returns `503` and refuses
  to serve tenant data. `TI_ALLOW_UNAUTHENTICATED=true` re-opens it for local
  development and logs at error level on every request.

Before this existed, `client_id` arrived as a plain query parameter with no
credential anywhere in the request — demonstrated against the running app:
`POST /api/v1/scans/upload?client_id=acme` stored 8 vulnerabilities, and
`GET /api/v1/vulnerabilities?client_id=acme` returned all 8, with no token,
header or session at any point.

### 9.2 Dashboard / Firestore — VERIFIED (RETIRING)

Auth0 (`dev-ws5377dam2tnlv5g.us.auth0.com`, Organizations) → `exchangeAuth0Token`
verifies the token against the tenant JWKS → mints a Firebase custom token
carrying `client_id` → `firestore.rules` gate every read on that claim.

`client_id` precedence: the namespaced claim `https://ironcityit.com/client_id`
set by an Auth0 Action, then `org_name`, then `org_id`. Taken **only** from the
verified token — never from body, query or header.

### 9.3 RBAC — UNKNOWN

There is **no role model** anywhere in this repository. Tenancy is enforced
(tenant A cannot read tenant B), but within a tenant every authenticated caller
has identical rights. There is no admin/analyst/read-only distinction, no
per-user scoping, and no notion of privilege on any surface.

Target state requires RBAC. **Its shape is a product decision and is not invented
here.**

### 9.4 Audit — UNKNOWN / NOT IMPLEMENTED

No audit table, no audit log, no append-only record of who triggered what, who
read what, or who changed configuration. Structured logs exist (`logger.info` in
functions, `log.info` in the runner) but they are operational logs, not an audit
trail, and they are not retained anywhere durable.

Target state requires auditability. **Not built.**

---

## 10. Security boundaries and posture

### 10.1 Enforced today — VERIFIED

| Boundary | Mechanism |
|---|---|
| Tenant read isolation | `firestore.rules` on the verified `client_id` claim; 15 emulator tests, both directions |
| Tenant isolation (local API) | Token → single `client_id`; mismatch is `403` |
| No client writes | `firestore.rules` `allow write: if false`; all writes via Admin SDK |
| Ingest authentication | Bearer `INGEST_TOKEN`, constant-time compare, `503` when unconfigured |
| Store fails closed | Unset URL/token, 401, 503 or any non-2xx fails the job |
| Workflow dispatch allow-list | `triggerScan` accepts only named workflows and inputs |
| Command injection | Fixed argv, `shell=False`; `client_name` passed via env, never interpolated into a script body |
| URL scheme allow-list | Fetch helpers re-check `http`/`https`; urllib also speaks `file://` and `ftp://` |
| Report injection | Every client-facing interpolation escaped; 48 tests |
| XXE / entity expansion | External entities refused; nested expansion contained; tests |
| Secret handling | Names only in the repo; ingest token passed via `--header @file`, never argv |
| Local-address guard | Scanning loopback/private ranges requires `--allow-local` |

### 10.2 Open risks — VERIFIED

1. **The repository is PUBLIC and `main` is NOT branch-protected.**
   ```
   $ gh api repos/IronCityIT/threat-inspector -q .visibility     → public
   $ gh api repos/IronCityIT/threat-inspector/branches/main/protection
     → 404 Branch not protected
   ```
   Anyone with write access can push directly to `main`, and CI is not a required
   check. Four PRs were merged today under an agent's own authority with no
   enforced review. `CLAUDE.md` forbids direct pushes to `main` by policy, but
   **nothing enforces it**. Recommend: enable branch protection requiring the CI
   check and at least one review. **This is a repository-settings change and has
   not been made.**

2. **`tls_cert_check` discloses client targets to a third party.** It sends the
   target hostname to the public SSL Labs API — revealing which hosts a client is
   having assessed. Unresolved product decision: keep, gate behind a flag, or drop.

3. **`utils/remediation.py` can generate text with a local `gpt2` model.**
   `CLAUDE.md` is explicit that AI analysis belongs to `consensus-engine`. The
   dependency is now optional; the code path arguably should go.

4. **12 moderate npm advisories** in the functions tree, resolvable only via
   `firebase-admin@14`. **The migration retires this tree entirely**, which
   removes the finding rather than fixing it.

5. **A missing external scanner reports as a clean result** (§2.4). Fix exists,
   unmerged.

---

## 11. Secrets — by NAME only

No value for any secret appears anywhere in this repository, and none appears in
this document.

### 11.1 Present on this repo — VERIFIED (`gh secret list`)

| Secret | Purpose |
|---|---|
| `GROQ_API_KEY` | consensus-engine provider |
| `OPENROUTER_API_KEY` | consensus-engine provider |
| `GEMINI_API_KEY` | consensus-engine provider |
| `IRONCITY_API_KEY` | **self-hosted QNAP ingest** — already used by `consensus-engine` |
| `STORE_SCAN_RESULTS_URL` | Firebase ingest endpoint (RETIRING) |
| `FIREBASE_FUNCTION_URL` | legacy, superseded (RETIRING) |

`IRONCITY_API_KEY` is the notable one: **the credential for the self-hosted
ingest already exists on this repository.** Its exact use against `/ingest` is
UNKNOWN (§3.3).

### 11.2 Absent — VERIFIED, blockers for the *Firebase* path

`FIREBASE_SERVICE_ACCOUNT` · `INGEST_TOKEN` · `AUTH0_CLIENT_ID` ·
`FIREBASE_API_KEY` · `GITHUB_DISPATCH_TOKEN` · `AUTH0_AUDIENCE` (optional)

Under the new direction **most of these should never be provisioned.** Only
`AUTH0_CLIENT_ID` (and possibly `AUTH0_AUDIENCE`) remain relevant, since Auth0 is
retained.

### 11.3 Operator-set, not repository secrets

| Name | Where | Purpose |
|---|---|---|
| `TI_API_TOKENS` | deployment environment | `token:client_id` pairs for the local API |
| `TI_ALLOW_UNAUTHENTICATED` | deployment environment | Local development ONLY; logs an error every request |
| `DATABASE_URL` | deployment environment | DB connection; **the MariaDB seam** |

### 11.4 Needed for the target — TARGET, none provisioned

A MariaDB DSN or credential, and whatever the self-hosted ingest requires beyond
`IRONCITY_API_KEY`. **Names not invented here** — they depend on decisions in
§3.3. Per `CLAUDE.md`, a secret outside the approved list requires Bill.

---

## 12. Enhancements and backlog

Ordered by value. Blocked items say what blocks them.

| # | Item | State |
|---|---|---|
| 1 | **Resolve the `ARCHITECTURE.md` conflict** (§3.4) — fleet-wide, blocks everyone | BLOCKED: HANDS OFF repo, needs Bill |
| 2 | **Capture the NAS ingest contract and MariaDB schema** (§3.3) | BLOCKED: no credential / no source |
| 3 | **Reconcile integer `clients.id` with the `client_id` slug** (§4.1) | Ready — design decision, no external dependency |
| 4 | **Self-hosted persistence layer**: schema + tenant-scoped repository + migrations, tested, *not deployed* | Ready — see §16 |
| 5 | **Re-express the 15 tenant-isolation invariants against the DB layer** (§5.3) | Follows #4 |
| 6 | **Merge capability reporting** (§2.4) — branch `feat/threat-inspector-capability-reporting` @ `5d37c67` | Ready, needs review against this architecture |
| 7 | **Enable branch protection on `main`** (§10.2.1) | BLOCKED: repository setting, needs Bill |
| 8 | Decide `tls_cert_check` third-party disclosure | BLOCKED: product decision |
| 9 | Decide `utils/remediation.py` gpt2 path | BLOCKED: product decision |
| 10 | Re-implement the dashboard security headers off `firebase.json` (§5.2) | Follows the hosting decision |
| 11 | Cover or remove `src/threat_inspector/cli.py` (0%, declared entry point, unused) | Ready |
| 12 | RBAC model (§9.3) | BLOCKED: product decision |
| 13 | Audit trail (§9.4) | BLOCKED: depends on #4 and #12 |
| 14 | Install `subfinder`/`nuclei` in the scan environment so those modules do real work | Ready |

---

## 13. Known defects and blockers

### 13.1 Defects — VERIFIED, open

| Defect | Impact | Reference |
|---|---|---|
| A missing external scanner reports as a clean scan | A scan can report "no findings" for a capability that never ran | §2.4; fix unmerged |
| `models/__init__.py` — 139 statements, 0% coverage, unused | Dead today; foundation under the new direction | §4.1 |
| `cli.py` — 145 statements, 0% coverage, declared entry point | Ships in the package, nothing calls it | §12 #11 |
| Integer vs. slug tenant identity | Two incompatible notions of "tenant" | §4.1 |
| Dashboard security headers live only in `firebase.json` | Retiring Firebase drops real controls | §5.2 |

### 13.2 Blockers — VERIFIED, recorded once

| Blocker | Exact evidence |
|---|---|
| No MariaDB credential | `192.168.1.177:3306` answers `5.5.5-10.5.8-MariaDB-log`; no credential in any secret or config available here |
| No `ironcity-api` source | Not in the `IronCityIT` repo listing (`gh repo list`, 40 repos, 2026-09-07) |
| NAS services never captured | `ICIT-Infrastructure/hosts/qnap-nas-01/SERVICES.md`: "**NOT CAPTURED.** Expected shape. Ports and start commands **unverified**." |
| No GCP/Firebase deploy credential | `FIREBASE_SERVICE_ACCOUNT` absent; no `gcloud`/`firebase` CLI on this box. Moot under the new direction |
| No local MariaDB/MySQL client, server, or `docker` | `which mysql mariadb mysqld docker` → none; `import pymysql` → ImportError |
| `main` not branch-protected | `gh api …/branches/main/protection` → 404 |

---

## 14. Operational runbooks

### 14.1 Run the gates locally — VERIFIED

```bash
python3 -m ruff format --check .
python3 -m ruff check .
python3 -m mypy module_framework src
python3 -m pytest -q                       # 452 passed
python3 tools/smoke_test.py                # 44/44, needs nmap for full coverage
python3 tools/build_catalog.py && git diff --exit-code -- dashboard/public/catalog.json
for f in .github/workflows/*.yml; do
  python3 -c "import yaml,sys;yaml.safe_load(open(sys.argv[1]))" "$f"; done
```

JavaScript side (installs first): `npm ci`, `(cd functions && npm ci)`,
`npx playwright install --with-deps chromium`, then `npm test`.
Firestore rules need Java **21** — not 17; firebase-tools refuses below 21, and
that is exactly what turned the first CI run on the hardening branch red.

### 14.2 Run a scan by hand — VERIFIED

```bash
python3 module_framework/cli.py --list-modules
python3 module_framework/cli.py --group quick --targets example.com \
    --client acme --scan-id acme-$(date +%s)
python3 module_framework/cli.py --modules port_scan --targets 127.0.0.1 --allow-local
```

`--dry-run` validates targets and selection and stops before any module touches
the network.

### 14.3 Check the self-hosted API is up — VERIFIED

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'Content-Type: application/json' --data '{}' \
  https://api.ironcityit.com/ingest        # expect 401 — up and authenticating
```

Returns `401 {"error":"Unauthorized"}` as of 2026-09-07T20:23Z. A `000`, `5xx`,
or anything that is not `401` means investigate.

### 14.4 Interpret a scan's status — VERIFIED

| `status` | Meaning |
|---|---|
| `ok` | Every attempted module ran without raising |
| `partial` | Some modules raised; others produced findings |
| `failed` | Every attempted module raised |
| `dry_run` | Nothing executed by design |

**An `ok` with zero findings does not currently mean "clean"** — see §2.4.

---

## 15. Rollback and disaster recovery

### 15.1 Code — VERIFIED

Every change lands through a PR onto `main`. `git revert` of the merge commit is
the rollback. Branch protection is **not** enabled (§10.2.1), so the discipline is
convention, not enforcement.

### 15.2 Current data store — VERIFIED / UNKNOWN

Firestore in `iron-city-it-threatinspector`. **UNKNOWN:** whether any backup,
export schedule, or PITR is configured for that project. Nothing in this
repository configures one. No deploy has ever succeeded from this repository
(`FIREBASE_SERVICE_ACCOUNT` has never been present), so the amount of live
product data there is also **UNKNOWN**.

### 15.3 Target data store — TARGET / UNKNOWN

The NAS has fleet backups — HBS3 → Google Drive and restic → Backblaze B2 bucket
`ironkeep-fleet` (`ICIT-BUILD-INVENTORY.md`). **UNKNOWN:** whether those cover a
MariaDB dump for the application database, the restic repo/tag/retention for this
host, and what the restore procedure is. `SERVICES.md` lists all of this as "to be
filled in from a capture".

**A migration must not proceed past writing data until DR for that data is
established.** Recording this as a gate, not an afterthought.

### 15.4 Migration safety — TARGET

Non-negotiable for any migration work:

1. **Dual-write before cut-over.** Never a one-way switch.
2. **No destructive migration.** Firebase artifacts are retired only after the
   replacement is verified in production.
3. **Reversible.** Every step revertible by a `git revert` plus a config change.
4. **Fail-closed preserved.** The store step must keep failing the job when it
   cannot store; a scan that cannot be stored is a failed scan.
5. **Tenant isolation proven before data lands** — the §5.3 invariants must pass
   against the new layer first.

---

## 16. Next implementation step — proposed

Backlog #3 + #4 (§12), because they are the only high-value items with **no
external blocker**:

- Reconcile tenant identity: the slug `client_id` becomes the stable tenant key.
- A tenant-scoped persistence layer built on the existing SQLAlchemy models,
  targeting MariaDB via `DATABASE_URL`, with migrations.
- Tests, including the §5.3 isolation invariants re-expressed at the DB layer.
- **Additive only.** Firebase untouched, nothing wired into the workflows,
  nothing deployed, no destructive change.

This is safe because it depends on no unknown: it defines *this product's own*
schema rather than guessing `ironcity-api`'s, and it runs against a local
file-backed database in CI. Whether Threat Inspector ultimately owns its own
MariaDB schema or POSTs to the shared `/ingest` is **UNKNOWN and a decision for
Bill** (§3.3) — but a tenant-scoped repository layer is needed either way.

---

## 17. Evidence and provenance

Every command in this section was run on `icit-devbox` on **2026-09-07**, against
`main` at **`0e70572`**.

| Claim | Command | Result |
|---|---|---|
| Test count | `python3 -m pytest -q` | 452 passed |
| Smoke | `python3 tools/smoke_test.py` | 44/44, 0 skipped |
| Lint/format/types | `ruff check .` / `ruff format --check .` / `mypy module_framework src` | clean; 65 files; 42 files |
| CI green | `gh pr view 16 --json statusCheckRollup` | 7/7 SUCCESS |
| Merges | `git log --oneline -6` | PRs #13, #14, #15, #16 on main |
| Repo public | `gh api repos/IronCityIT/threat-inspector -q .visibility` | `public` |
| No branch protection | `gh api …/branches/main/protection` | 404 Branch not protected |
| Repo secrets | `gh secret list` | 6 secrets, §11.1 |
| MariaDB live | TCP banner read `192.168.1.177:3306` | `5.5.5-10.5.8-MariaDB-log` |
| SSH live | TCP banner read `192.168.1.177:22` | `SSH-2.0-OpenSSH_10.3` |
| NAS web | `HEAD 192.168.1.177:80` | `302 → https://192.168.1.177:8081/`, Apache |
| Self-hosted API live | `POST https://api.ironcityit.com/ingest` unauthenticated | `401 {"error":"Unauthorized"}` |
| `/ingest` POST-only | `GET https://api.ironcityit.com/ingest` | `405 Method Not Allowed` |
| Firebase refs | `grep -ril "firebase\|firestore\|gcp\|…"` excluding vendor | 33 files, §5 |
| No `ironcity-api` repo | `gh repo list IronCityIT --limit 40` | absent |
| NAS uncaptured | `ICIT-Infrastructure/hosts/qnap-nas-01/SERVICES.md` | "NOT CAPTURED… unverified" |
| Architecture conflict | `ICIT-Infrastructure/ARCHITECTURE.md` | "Firestore is the store of record." |
| No local DB tooling | `which mysql mariadb mysqld docker`; `import pymysql` | none; ImportError |
| Capability defect | `cli.py --modules subdomain_enum --targets example.selftest.invalid` | `status: ok`, 0 findings |

**Not done, and not claimed:** no deploy, no destructive migration, no write to
MariaDB, no write to the NAS, no authentication attempt against any host, no
third-party scan. Every network probe above was a read-only banner or an
unauthenticated request to an ICIT-owned endpoint.
