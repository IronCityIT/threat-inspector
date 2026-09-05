# SDLC Status — Threat Inspector

**Branch:** `feat/threat-inspector-hardening`
**Last verified:** 2026-09-05 (third pass — completion and gap closure)
**Scope of this branch:** completion and hardening of the local end-to-end
product. **Nothing here has been merged or deployed.**

This document records what is *verified*, what is *asserted but unproven*, and
what is *blocked on something only a human can provision*. A claim only appears
in the "verified" column if a command in this document produced it.

---

## 1. How to verify this branch

Every gate, in the order CI runs them. All commands are from the repo root.

```bash
# Python: format, lint, types, tests
ruff format --check .
ruff check .
mypy module_framework src
python3 -m pytest -q

# End-to-end: real subprocesses, real sockets, real fixtures.
# Install nmap first, or the four external-scanner checks SKIP rather than pass.
sudo apt-get install -y nmap
python3 tools/smoke_test.py

# JavaScript. Order matters: the function tests import functions/index.js, so
# the function dependencies must be installed before `npm test` at the root.
npm ci
(cd functions && npm ci && npm audit --audit-level=high)
for f in functions/*.js dashboard/public/*.js; do node --check "$f"; done
npx playwright install --with-deps chromium     # first run only
npm test                                        # functions (27) + browser (16)

# Firestore rules, behaviourally. Needs Java + firebase-tools; skips loudly
# without them. The install is slow (730 packages, ~6m) but it does complete —
# this now runs and passes here, see §2.
npm install --no-save firebase-tools @firebase/rules-unit-testing firebase
npm run test:rules

# Dependency advisories
pip-audit -r requirements.txt -r requirements-dev.txt
(cd functions && npm audit --audit-level=high)

# Dashboard catalog must match the live registries
python3 tools/build_catalog.py && git diff --exit-code -- dashboard/public/catalog.json

# Workflow YAML
for f in .github/workflows/*.yml; do
  python3 -c "import yaml,sys;yaml.safe_load(open(sys.argv[1]))" "$f"; done
```

---

## 2. Verified state

| Gate | Command | Result |
|---|---|---|
| Format | `ruff format --check .` | ✅ 60 files formatted |
| Lint | `ruff check .` | ✅ all checks passed |
| Types | `mypy module_framework src` | ✅ 42 files, no issues |
| Unit + integration | `python3 -m pytest -q` | ✅ **279 passed** |
| End-to-end smoke | `python3 tools/smoke_test.py` | ✅ **44/44 checks**, 0 skipped |
| Function auth + tenancy | `npm run test:functions` | ✅ **27 passed** (15 auth + 12 tenancy) |
| Dashboard browser | `npm run test:ui` | ✅ **16 passed** in Chromium |
| Firestore rules (behaviour) | `npm run test:rules` | ✅ **15 passed** against a real Firestore emulator — see below |
| Workflow YAML | `yaml.safe_load` × 10 | ✅ all parse |
| JS syntax | `node --check` × 6 | ✅ all parse |
| Catalog freshness | `build_catalog.py` + `git diff` | ✅ zero diff |
| Functions lockfile | `npm ci --dry-run` | ✅ resolves (241 packages pinned) |
| Python advisories | `pip-audit -r requirements*.txt` | ✅ **no known vulnerabilities** |
| Functions advisories | `npm audit --audit-level=high` | ✅ passes — **12 moderate** remain, see §6.7 |

Test count went **41 → 337** (279 pytest + 27 function + 16 browser + 15
emulator rules), plus 44 end-to-end smoke checks. Every one of those was
executed on this branch; nothing in the table above is asserted from code
review alone.

### The rules tests have now actually run

This was the largest outstanding gap in the previous pass — the cross-tenant
rules tests existed but had never executed, so "no cross-tenant leakage" was an
argument from code review. `firebase-tools` installed on the fourth attempt
(730 packages, 6m), and `npm run test:rules` stood up a real Firestore emulator
(cloud-firestore-emulator v1.22.0 on Java 21), loaded the committed
`firestore.rules`, seeded two tenants and tried to read across them:

```
firestore.rules (emulator)
  ok   a tenant can read its own client document / scan / scan list
  ok   a tenant CANNOT read another tenant's client document
  ok   a tenant CANNOT read another tenant's scan
  ok   a tenant CANNOT list another tenant's scans
  ok   the isolation holds in both directions
  ok   an unauthenticated caller can read nothing
  ok   a signed-in caller with NO client_id claim can read nothing
  ok   a forged client_id claim only grants that tenant, not others
  ok   a tenant CANNOT write its own scan / client document
  ok   a tenant CANNOT write into another tenant
  ok   an unauthenticated caller CANNOT write
  ok   collections outside clients/ are denied by default

15 passed, 0 failed
```

Tenant isolation is now a demonstrated property of the deployed rules, not a
claim about them. **This also runs in CI** — run `33968442543`, job "Firestore
rules (emulator)": the emulator starts, all 15 cases run, none skip.

### CI has now executed on this branch, and it caught something local runs could not

The first CI run on this branch (`33968345912`) went **red**. Six of seven jobs
passed; the rules job failed in 37s without ever starting the emulator:

    Error: firebase-tools no longer supports Java version before 21.
           Please install a JDK at version 21 or above.

`ci.yml` pinned `java-version: '17'`. The suite passes locally because the
ambient JDK here happens to be 21, so the one gate that had never run in CI was
the one broken in CI — the exact failure mode this document warned about in the
previous pass. Fixed in `58ba692`; run `33968442543` is green on all seven jobs. The writes are denied at the rules layer by design — the
ingest path writes with the Admin SDK through `storeScanResults`, which
authenticates its caller separately.

### Fresh-environment validation — DONE

The committed tree was cloned clean (`git clone --branch
feat/threat-inspector-hardening`) and inspected: 104 tracked files, no
`node_modules`, `.venv`, `__pycache__` or `.coverage` tracked.

A fresh virtualenv was then built from the declared requirements alone:

    python3 -m venv .venv
    .venv/bin/python3 -m pip install -r requirements.txt -r requirements-dev.txt
    # PIP_EXIT=0, 234 packages, 87m wall / 1m40s CPU (this machine is I/O-bound)

Against that isolated interpreter — `sys.prefix` inside the venv,
`include-system-site-packages = false`:

| Check | Result |
|---|---|
| Every declared runtime dep imports | ✅ pandas, fastapi, pydantic-settings, lxml, openpyxl, jinja2, click, rich, uvicorn, sqlalchemy, httpx, dateutil, tabulate, markdown, yaml, dotenv, alembic |
| torch / transformers / nltk / scikit-learn / ollama | ✅ **absent** — confirming they are not runtime dependencies |
| `python3 -m pytest -q` | ✅ **182 passed** |
| `python3 tools/smoke_test.py` | ✅ **44 passed, 0 failed, 0 skipped** |

So the declared runtime set is sufficient for the whole product, and the ML
stack removed in `e6142e3` is demonstrably not needed by any code path the
tests or the end-to-end smoke test reach.

> Recovery note, for anyone reproducing this: the venv had to be repaired
> mid-session. An earlier `rm -rf` of the scratch clone partially failed on this
> filesystem, deleting `bin/python3` and `pyvenv.cfg` while leaving
> `site-packages` intact; both were recreated by hand. That is an artefact of
> the environment, not of the project, and the isolation was re-verified
> (`sys.prefix` and a 234-entry `site-packages`) before the runs above.

### What the smoke test actually proves

`tools/smoke_test.py` is the answer to "do not claim success from mocks alone".
It runs the real entry points as **subprocesses** and asserts the JSON contract
at each hop. Nothing in it is stubbed. In particular it stands up a live HTTP
server on loopback and scans it over real sockets, so the active path is proven
without ever pointing the product at a third party.

```
entry points (3)      both catalogs; `python -m module_framework.cli`
dry run (4)           executes nothing, keeps the full schema
active scan (7)       real findings over a real socket, incl. a 401-protected
                      admin path detected through a real HTTP response
real scanners (4)     port_scan and service_fingerprint driven through ACTUAL
                      nmap 7.94 against a listener the test owns on 127.0.0.1
input validation (5)  exit 2, no traceback; file:// and the cloud metadata
                      endpoint refused; unknown module lists what exists
containment (2)       an unreachable target does not sink the scan
ingestion (5)         all five file modules, critical..info severity coverage
corrupt upload (5)    reported failed with the parser's reason; --strict exits 1
store payload (7)     byte-level '{' gate, summary totals, diagnostics, and a
                      fully failed scan storing as failed rather than completed
catalog (2)           rebuilds and matches the committed file
```

A check that cannot run is reported as `SKIPPED (NOT PROVEN)` and counted
separately, never as a pass. With nmap absent the four scanner checks skip and
the summary line says `40 passed, 0 failed, 4 skipped`.

### Only authorized targets are ever scanned

Every active-scan check in this repo points at `127.0.0.1`, at a listener the
test process starts and owns. Nothing here scans a third party, and the loopback
guard means those checks must pass `--allow-local` explicitly to do it. The
ingest fixtures are unroutable by construction (`10.255.255.0/24`,
`*.selftest.invalid` — RFC 2606).

### Performance

| Measurement | Before | After |
|---|---|---|
| `ingest.py` import | 28.2s | 3.1s |
| Full pytest suite | 70.0s | ~21s |

pandas is now imported inside the three methods that read a spreadsheet, and
`threat_inspector`'s two public names resolve lazily (PEP 562).

---

## 3. What this branch fixed

Each item was reproduced against the code before being changed.

| # | Defect | Evidence it was real |
|---|---|---|
| 1 | Test suite passed only by alphabetical accident — no `conftest.py`, so `test_file_modules.py` put `src/` on `sys.path` as a side effect of sorting first | `pytest tests/test_parsers.py` alone → `ModuleNotFoundError: No module named 'threat_inspector'`, aborting the **entire** run |
| 2 | Every entry point paid ~28s of import cost before doing any work | `python3 -X importtime` — pandas 21s via `parsers/qualys.py`, pydantic-settings via `__init__` → `core` → `config` |
| 3 | No per-module error isolation: one raising module aborted the scan and discarded findings already collected | injected a raising module; `RuntimeError` escaped `main()` |
| 4 | Raw tracebacks on bad input — called out in TASKS.md as a rough edge, still present | `--targets 10.0.0.0/99` → bare `ValueError` stack trace from `ipaddress` |
| 5 | `file://`, `ftp://`, `gopher://` accepted as URL targets; modules pass `target.value` straight to a URL opener | `parse_targets(['file://localhost/etc/passwd'])` returned a valid URL Target |
| 6 | Cloud instance-metadata endpoint accepted as a scan target | `http://169.254.169.254/latest/meta-data/` parsed clean |
| 7 | `javascript:alert(1)` classified as a valid hostname | `parse_targets` returned `kind='hostname'` |
| 8 | `default_creds_check` could not detect what it exists to detect: `http_head` collapses every non-2xx/3xx to `None`, so the module hardcoded `200 if headers else None` and never saw a 401/403 | `evaluate()`'s `404 or >= 500` branch was unreachable from the real caller |
| 9 | An empty findings list was ambiguous — "clean scan" and "everything failed" were byte-identical | both produced identical JSON |
| 10 | Corrupt uploads reported as successfully ingested | `ZAPParser().parse(broken.xml).errors` held the exact reason; `to_findings()` read only `vulnerabilities` and discarded it |
| 11 | Store payload hardcoded `"status": "completed"` for every run | a fully failed scan was stored, and shown, as completed with 0 findings |
| 12 | Payload logic was an untestable inline heredoc in `_consensus-store.yml` | now `tools/build_store_payload.py` with 18 tests |
| 13 | `storeScanResults` accepted **anonymous** writes into any client's Firestore partition | the file's own header comment admitted it: "currently trusts its caller" |
| 14 | `functions/` had no `package-lock.json`; `npm ci \|\| npm install` always degraded to `npm install` | flagged in PRODUCTIZE_NOTES.md, never fixed |
| 15 | `python -m module_framework.cli`, documented in the module's own docstring, crashed | `ModuleNotFoundError: No module named 'registry'` |

Second validation pass:

| # | Defect | Evidence it was real |
|---|---|---|
| 16 | **The local REST API had no authentication at all.** `client_id` was a plain query parameter, so naming a tenant was enough to read their uploaded scan data. It ships in the Dockerfile bound to `0.0.0.0:8000` with docker-compose publishing that port. | `POST /api/v1/scans/upload?client_id=acme` → 200, 8 vulnerabilities; `GET /api/v1/vulnerabilities?client_id=acme` → 200, all 8 returned. No token, header or session anywhere in the transcript. |
| 17 | Firestore documents were unbounded, and a rejected write loses the **whole** scan rather than the excess | 5,000 realistic findings → 2,595,454 bytes against a 1,048,576-byte limit. The ceiling is ~2,000 findings, reachable by a /24 sweep. |
| 18 | `requirements.txt` mandated a GPU compute stack the scanner never calls | CI log of run 33554719630: torch 526.6 MB + 10 CUDA wheels ≈ **1,715 MB per job**, on three jobs. torch, nltk and scikit-learn are imported nowhere in the repo. |
| 19 | The external-scanner modules had no test against a real scanner — only against captured output | An nmap output-format change would have passed every gate and silently returned zero findings. |
| 20 | `firestore.rules` and `exchangeAuth0Token` — the entire tenancy boundary — had **zero** tests | Nothing asserted that a tenant cannot read another's scans, or that `client_id` cannot come from the request. |

Third pass:

| # | Defect | Evidence it was real |
|---|---|---|
| 21 | **`.gitignore` hid a whole source package from every quality gate.** The runtime output directory was ignored as `reports/`, unanchored, and that pattern matches a directory of that name at ANY depth — so it was swallowing `src/threat_inspector/reports/`. ruff honours .gitignore when it walks, so the package had never been linted or formatted, and it held the only file in the repo at 0% coverage. | Anchoring the pattern took `ruff check .` from "All checks passed" to **53 errors**, and `ruff format --check` from 56 files to 60. |
| 22 | **The client-facing HTML report interpolated six values with no escaping.** `client_name` and `project_name` come from the request body of POST /api/v1/reports/generate; severity, port and compliance mappings come from the scan file a client uploaded. | Every one landed verbatim in the output: `client_name='<script>alert("client")</script>'` reached `<title>`, and `severity='high"><script>alert(1)</script>'` broke out of a class attribute AND rendered as text. |
| 23 | **An expired certificate could parse as nothing to report.** `_days_until` used strptime's `%Z`, which accepts only "GMT", "UTC" and the local machine's own zone name; every other rendering returned `None`, and `run()` reads `None` as "no expiry finding". | `_days_until("Jun  1 12:00:00 2027 +0000")`, `"... 2027"` and `"... 2027 CEST"` all returned `None`. A cert expired since 2020 in any of those forms produced no finding at all. |
| 24 | **A scan export carrying a CVSS score could not be reported.** `cvss_score` is declared `float | None`; the network-scan parser assigned the XML table cell — text — straight through. | `generate_html_report(...)` → `ValueError: Unknown format code 'f' for object of type 'str'`. POST /api/v1/reports/generate fails outright for that client. The other two parsers already coerced. |
| 25 | **`module_framework` was absent from `--cov` entirely.** The product core CLAUDE.md mandates was not measured, so a regression in it could not show up as lost coverage. | `addopts` read `--cov=threat_inspector` only. Measured, the framework is 73–100%; the shortfall was measurement, not tests. |

### Security hardening, specifically

- **URL scheme allowlist** (http/https) enforced in `targets.py` *and* re-checked
  in the fetch helpers, because modules build URLs themselves (`base + "/admin"`).
- **Loopback / link-local refused by default**, `--allow-local` to opt back in.
  RFC1918 is deliberately still scannable — a client's internal range is the
  product's actual job.
- **Authenticated ingest.** `storeScanResults` requires a bearer token compared
  in constant time (`crypto.timingSafeEqual`), and is **secure by default**: with
  no token configured it returns 503 rather than accepting anonymous writes.
- **Reproducible function dependencies** — lockfile committed, `npm ci` only, and
  `npm audit --audit-level=high` in CI.
- **The API tenant now comes from the credential.** A bearer token maps to
  exactly one `client_id`; where the request also names a tenant (query string,
  or body field on analyze/reports) it is checked against the token and a
  mismatch is a 403, not a quiet redirect to the caller's own data. Secure by
  default: unconfigured, the API returns 503 for tenant data while `/health`
  keeps answering. This is the same property `exchangeAuth0Token` enforces on
  the Firestore side.
- **A rejected Firestore write can no longer lose a scan.** The record is packed
  to an 800 KB budget, most-severe findings first, with per-finding text
  clamped; severity totals are computed before truncation so they stay true, and
  `summary.truncated` declares the difference.
- **~1.7 GB of unused GPU stack removed from the scan runner's dependency set.**
  On a security product whose runner handles client data, every installed
  package is supply-chain surface.

> One note on the auth guard, because it is easy to get wrong: `TargetError`
> subclasses `ValueError`, so the first cut of the local-address check wrapped
> `_check_ip` in `except ValueError` and silently swallowed its own rejection —
> the metadata endpoint still passed. It is now parse-first/check-second, with a
> test that asserts `169.254.169.254` is refused.

---

## 4. Not proven — stated plainly

These are **not** covered by any gate in this repo, and no claim is made about them.

| Area | Why it is unproven | What would prove it |
|---|---|---|
| Real Auth0 sign-in | No SPA application exists in the tenant. Browser tests open the signed-in view directly, and `jwtVerify` against the live JWKS is never exercised. | `AUTH0_CLIENT_ID` + an SPA app (§5). |
| A real deploy | Blocked on `FIREBASE_SERVICE_ACCOUNT` (§5). No deploy attempted from this branch. | The secrets in §5. |
| The authenticated ingest path end to end | `verifyIngest()` is unit-tested in isolation (15 cases). The full POST → 401/503/200 round trip needs a deployed function or the emulator. | A deploy, or the emulator once available. |
| `cve_lookup`, `subdomain_enum`, `web_vuln_scan` against live hosts | Their parsers are unit-tested against captured output, but subfinder and nuclei are not installed, so the modules degrade to "capability unavailable". That degradation path IS exercised; the live path is not. `port_scan` and `service_fingerprint` no longer belong on this list — they now run through real nmap 7.94 in the smoke test. | Installing those two scanners in the smoke environment, as was done for nmap. |
| Consensus engine integration | `_consensus-store.yml` calls `IronCityIT/consensus-engine@main`. Not run from this branch. | A dispatched workflow run. |

---

## 5. Blocked on secrets / external provisioning

Referenced **by name only**. No value for any of these appears anywhere in the
repo, per the ICIT secret policy. Each is needed before a deploy can succeed.

| Secret | State | Needed for |
|---|---|---|
| `INGEST_TOKEN` | ❌ **NEW — does not exist** | `storeScanResults` refuses anonymous writes. Create in Secret Manager on `iron-city-it-threatinspector` (us-east5), grant the functions runtime SA `roles/secretmanager.secretAccessor`, and store the same value as a repo secret so the scan workflows can authenticate. `deploy-functions.yml` fails fast without it. |
| `FIREBASE_SERVICE_ACCOUNT` | ❌ missing | Any deploy at all. Needs Cloud Functions Developer, Firebase Rules Admin, Service Account User, Artifact Registry Writer. |
| `AUTH0_CLIENT_ID` | ❌ missing | Dashboard sign-in. The SPA application does not exist in the `dev-ws5377dam2tnlv5g` tenant. |
| `FIREBASE_API_KEY` | ❌ missing | Dashboard Firebase web config. |
| `GITHUB_DISPATCH_TOKEN` | ❌ missing | `triggerScan` cannot dispatch a workflow. |
| `AUTH0_AUDIENCE` | ❌ missing (optional) | Only if the access token needs an API audience. |
| `TI_API_TOKENS` | ⚙️ **operator-set, not a repo secret** | The local REST API refuses to serve tenant data without it. Format `'<token>:<client_id>,...'`, set on whatever runs the container. Not a GitHub secret — it belongs to the deployment, not the build. `TI_ALLOW_UNAUTHENTICATED=true` bypasses it for local development ONLY and logs an error on every request. |
| `STORE_SCAN_RESULTS_URL` | ✅ **set 2026-08-29** | Present. Note: PRODUCTIZE_NOTES.md still lists this as outstanding — that entry is stale, confirmed via `gh secret list`. |

Auth0 additionally needs an Action setting `https://ironcityit.com/client_id` on
the token, or Organizations configured so `org_name` resolves the tenant.
`exchange.js` accepts either.

**The agent cannot provision any of these** — there is no `gcloud`/`firebase`
CLI and no GCP credentials in this environment.

---

## 6. Known gaps, deliberately not addressed here

Each is a real issue with a reason for being out of scope on this branch.

1. **`tls_cert_check` sends the target hostname to a third-party grading API.**
   `https://api.ssllabs.com/api/v3/analyze?host=...` discloses which hosts a
   client is having assessed. That is a data-handling decision (and arguably a
   contractual one), not a bug to quietly change — it needs a call from Bill on
   whether to keep it, gate it behind a flag, or drop it.
2. ~~**`tls_cert_check._days_until` parses `notAfter` with `%Z`.**~~ **FIXED**
   in this pass — a numeric offset is honoured as given, a trailing zone name is
   dropped and the rest read as UTC (RFC 5280 requires Zulu time, so a zone name
   is a rendering artefact), and `None` is returned only for a genuinely
   unparseable timestamp. 17 tests, one per rendering.
3. **`default_creds_check` probes a fixed list of admin paths over HTTPS for
   `ip`-kind targets**, where certificate validation will usually fail. It is
   almost certainly under-reporting against bare IPs.
4. **No rate limiting or politeness delay** between probes. Fine for the current
   path counts; would matter if the admin-path list grows.
5. **`scan.yml` installs scanners by downloading pinned release zips over the
   network with no checksum verification.** A supply-chain gap in the workflow.
   Wants pinned digests, which needs a decision on where to record them.
6. ~~**Firestore documents are unbounded.**~~ **FIXED** in this pass — the record
   is now packed to an 800 KB budget, most-severe first, with the full severity
   totals preserved and truncation declared. What remains open is that the
   complete finding set for a truncated scan lives only in the build artifact;
   paging large result sets into subcollections is still a design question.
7. **12 moderate npm advisories in the function dependency tree**, all
   transitive and none directly imported by this repo:
   - `qs` (DoS / array-limit bypass) via `express` → `body-parser`, pulled in by
     `firebase-functions`.
   - `uuid` (missing buffer bounds check in v3/v5/v6) via `firebase-admin`,
     `google-gax`, `gaxios`, `teeny-request`.

   `npm audit fix --force` resolves them by installing **firebase-admin@14**, a
   major version bump across the entire function runtime. That is a deliberate
   upgrade with its own testing, not something to fold into a hardening branch —
   especially with no deployed environment to verify against. The CI gate is set
   at `--audit-level=high`, so these do not block, and they are recorded here
   rather than silenced. **Recommend a dedicated dependency-upgrade PR.**
8. **`utils/remediation.py` generates security remediation text with gpt2.**
   Beyond being poor quality for the purpose, CLAUDE.md is explicit that AI
   analysis belongs to consensus-engine and must not be duplicated in a product.
   This pass made the dependency optional; the code path arguably should be
   removed outright. **Product decision for Bill, not one to take unilaterally.**
9. **The API's tenant store is in-memory.** `_inspectors` is a process-local
   dict, so uploaded scan data does not survive a restart and does not work
   behind more than one replica. Fine for the single-container deployment
   docker-compose describes; a blocker for anything larger.
10. **`TI_API_TOKENS` is a static shared-secret table.** It correctly binds a
    token to one tenant, but there is no rotation, expiry or revocation story.
    A real deployment should move to the same Auth0-issued JWTs the dashboard
    uses, validating the `client_id` claim exactly as `exchange.js` does.
11. **`src/threat_inspector/models/__init__.py` is 139 statements of SQLAlchemy
    that nothing imports.** Not a test gap — dead code. It is plausibly the
    unbuilt half of gap 9 (the API's tenant store is in-memory), so it is
    flagged rather than deleted: if persistence is coming, this is the schema
    to build on; if it is not, the models and the `sqlalchemy`/`alembic`
    dependencies should go. **Product decision for Bill.**
12. **`src/threat_inspector/cli.py` is a declared console entry point
    (`threat-inspector = threat_inspector.cli:main`) at 0% coverage.** It ships
    in the package but nothing in the product path calls it — the Dockerfile
    runs the API and the workflows run `module_framework`. Worth either
    covering or dropping from `[project.scripts]`; both need a call on whether
    the legacy CLI is still a supported surface.
13. **The smoke test's scanner checks depend on a free port in nmap's top-1000.**
    If every candidate is occupied, they skip rather than fail — correct, but it
    means a busy machine yields less coverage than it appears to.

---

## 7. Commits on this branch

| Commit | What it closes |
|---|---|
| `efea69a` | Test-order fragility; 9× import-time reduction |
| `cac4335` | Module failure containment; input validation; scheme + local-address guards; run health |
| `3d707a1` | HTTP status preserved so `default_creds_check` can see a 401/403 |
| `1b7526c` | Corrupt uploads no longer pass for clean, empty ingests |
| `321465f` | Scan health reaches the client; payload builder extracted and tested |
| `bcdd04b` | Realistic fixtures + 40-check end-to-end smoke test, wired into CI |
| `0917ce8` | Authenticated ingest; reproducible function deps; first status doc |

Second validation pass:

| Commit | What it closes |
|---|---|
| `b2b20de` | Firestore document-size risk — the record is packed to fit rather than rejected |
| `52e858e` | Tenancy boundary tests: `exchangeAuth0Token` resolution + `firestore.rules` invariants |
| `e6142e3` | ~1.7 GB of unused GPU stack removed from the scan runner's dependency set |
| `964beb6` | External scanners exercised through real nmap; pip-audit and function suites in CI |
| `e006b4d` | The API tenant now comes from the credential, not the query string |
| `b6e7c81` | Behavioural cross-tenant rules tests (written; run by CI, not here) |
| `5e0c934` | Fresh-environment validation correction |

Third pass:

| Commit | What it closes |
|---|---|
| `db55f4c` | Client-facing report escaped at every interpolation site; `.gitignore` no longer hides the package from lint, format and coverage |
| `b8b8a56` | An expired certificate is reported whatever the notAfter rendering |
| `cd4b3b8` | A scan export with a CVSS score can be reported; ingestion-path parsers covered; `module_framework` measured |
| *branch tip* | This document |

---

## 8. Definition-of-done check against CLAUDE.md

`threat-inspector` is an **IN SCOPE** repo (full autonomy, may merge and deploy).
This branch deliberately stops short of both, because the task that produced it
said no production merge or deploy.

- ✅ Work is on an isolated branch, never pushed to `main`.
- ✅ Quality gates run, results reported in full — no gate is hidden, and §4 says
  plainly what is *not* proven.
- ✅ White-label maintained: a browser test feeds raw error text containing tool
  names through the degradation notice and asserts none reaches the DOM; the API
  suite asserts the same for every field the product derives.
- ✅ Secrets referenced by name only; the new ones are flagged in §5.
- ✅ Scanner modules were run **only** against `127.0.0.1` listeners the tests
  own. No third party was scanned at any point.
- ✅ **PR opened** against `main` — see the branch's pull request.
- ✅ **CI green** — run `33968442543`, all seven jobs, including the rules
  emulator job. The first run was red and is described in §2.
- ⏸️ **Not merged, not deployed.** `threat-inspector` is IN SCOPE and CLAUDE.md
  permits both once gates are green, which they now are in CI as well as
  locally. Merging is left to Bill on this branch because the task that produced
  it said no production merge or deploy; a deploy is blocked outright regardless
  on the §5 secrets, none of which this environment can provision.

### The one thing to read if you read nothing else

Across the three passes, four findings would each have been serious in
production:

1. **The REST API had no authentication.** It ships in the Dockerfile on
   `0.0.0.0:8000`, holds client vulnerability data, and served any tenant to
   anyone who named them. Fixed, with 22 tests.
2. **A large scan lost every finding.** Over ~2,000 findings the Firestore write
   was rejected outright, so the client got nothing rather than a truncated
   report. Fixed, with 9 tests.
3. **The client-facing report interpolated six values with no escaping**, from
   the request body and from uploaded scan files alike. Fixed, with 48 tests.
4. **A scan export carrying a CVSS score could not be reported at all** — the
   report raised `ValueError` and the client got nothing. Fixed, with 32 tests
   across the ingestion path.

The third and fourth share a cause worth naming: **a `.gitignore` pattern was
hiding a whole source package from lint, format and coverage.** `reports/` was
meant for the runtime output directory, but unanchored it matches a directory
of that name at any depth, and ruff honours .gitignore when it walks. The
package with the injection bug in it was the one package no gate could see.
When a gate reports "all checks passed", it is worth knowing what it was
allowed to look at.

Both of those gaps are now closed: the rules tests run against a real emulator,
and CI has executed on this branch and is green across all seven jobs. The
closing is worth keeping, though, because the first CI run was **red** for a
reason no local run could surface — the runner pinned JDK 17 and firebase-tools
requires 21. Local evidence and a green pipeline are not the same thing, and on
this branch the difference was exactly one job wide.

What remains genuinely unproven is unchanged and listed in §4: real Auth0
sign-in, a real deploy, the authenticated ingest round trip, and the three
modules whose external scanners are not installed.
