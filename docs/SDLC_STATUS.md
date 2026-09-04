# SDLC Status — Threat Inspector

**Branch:** `feat/threat-inspector-hardening`
**Last verified:** 2026-09-04
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

# End-to-end: real subprocesses, real sockets, real fixtures
python3 tools/smoke_test.py

# JavaScript. Order matters: the function tests import functions/index.js, so
# the function dependencies must be installed before `npm test` at the root.
npm ci
(cd functions && npm ci && npm audit --audit-level=high)
for f in functions/*.js dashboard/public/*.js; do node --check "$f"; done
npx playwright install --with-deps chromium     # first run only
npm test                                        # functions (15) + browser (16)

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
| Format | `ruff format --check .` | ✅ 52 files formatted |
| Lint | `ruff check .` | ✅ all checks passed |
| Types | `mypy module_framework src` | ✅ 41 files, no issues |
| Unit + integration | `python3 -m pytest -q` | ✅ **136 passed** |
| End-to-end smoke | `python3 tools/smoke_test.py` | ✅ **40/40 checks** |
| Function auth | `npm run test:functions` | ✅ **15 passed** |
| Dashboard browser | `npm run test:ui` | ✅ **16 passed** in Chromium |
| Workflow YAML | `yaml.safe_load` × 10 | ✅ all parse |
| JS syntax | `node --check` × 6 | ✅ all parse |
| Catalog freshness | `build_catalog.py` + `git diff` | ✅ zero diff |
| Functions lockfile | `npm ci --dry-run` | ✅ resolves (241 packages pinned) |
| Functions audit | `npm audit --audit-level=high` | ✅ passes — **12 moderate** advisories remain, see §6.7 |

Test count went from **41 → 167** (136 pytest + 15 function + 16 browser).

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
input validation (5)  exit 2, no traceback; file:// and the cloud metadata
                      endpoint refused; unknown module lists what exists
containment (2)       an unreachable target does not sink the scan
ingestion (5)         all five file modules, critical..info severity coverage
corrupt upload (5)    reported failed with the parser's reason; --strict exits 1
store payload (7)     byte-level '{' gate, summary totals, diagnostics, and a
                      fully failed scan storing as failed rather than completed
catalog (2)           rebuilds and matches the committed file
```

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

> One note on the auth guard, because it is easy to get wrong: `TargetError`
> subclasses `ValueError`, so the first cut of the local-address check wrapped
> `_check_ip` in `except ValueError` and silently swallowed its own rejection —
> the metadata endpoint still passed. It is now parse-first/check-second, with a
> test that asserts `169.254.169.254` is refused.

---

## 4. Not proven — stated plainly

These are **not** covered by any gate in this repo, and no claim is made about them.

| Area | Why it is unproven |
|---|---|
| Real Auth0 sign-in | No SPA application exists in the tenant. Browser tests open the signed-in view directly. |
| Real cross-tenant isolation against live Firestore | Needs two seeded tenants and a deployed project. `firestore.rules` is reviewed, not exercised. |
| A real deploy | Blocked on `FIREBASE_SERVICE_ACCOUNT` (§5). No deploy has been attempted from this branch. |
| The authenticated ingest path end to end | `verifyIngest()` is unit-tested in isolation. The full POST → 401/503/200 round trip needs a deployed function, or the Firebase emulator, which is not installed here. |
| External scanner modules (`port_scan`, `service_fingerprint`, `cve_lookup`, `subdomain_enum`, `web_vuln_scan`) against live hosts | Their **parsers** are unit-tested against captured output. The tools themselves (nmap, subfinder, nuclei) are not installed locally, so these modules degrade to "capability unavailable" and return no findings. That degradation path is exercised; the live-scan path is not. |
| Consensus engine integration | `_consensus-store.yml` calls `IronCityIT/consensus-engine@main`. Not run from this branch. |

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
2. **`tls_cert_check._days_until` parses `notAfter` with `%Z`**, which only
   accepts `GMT`. Any other timezone abbreviation yields `None` and the expiry
   finding is silently skipped. Real, narrow, and wants its own change with a
   fixture per format.
3. **`default_creds_check` probes a fixed list of admin paths over HTTPS for
   `ip`-kind targets**, where certificate validation will usually fail. It is
   almost certainly under-reporting against bare IPs.
4. **No rate limiting or politeness delay** between probes. Fine for the current
   path counts; would matter if the admin-path list grows.
5. **`scan.yml` installs scanners by downloading pinned release zips over the
   network with no checksum verification.** A supply-chain gap in the workflow.
   Wants pinned digests, which needs a decision on where to record them.
6. **Firestore documents are unbounded.** `diagnostics` is capped at 50 errors,
   but `findings` is not — a very large scan could still exceed the 1 MiB limit.
   Needs a chunking design, not a patch.
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
| *branch tip* | Authenticated ingest; reproducible function deps; docs |

---

## 8. Definition-of-done check against CLAUDE.md

`threat-inspector` is an **IN SCOPE** repo (full autonomy, may merge and deploy).
This branch deliberately stops short of both, because the task that produced it
said no production merge or deploy.

- ✅ Work is on an isolated branch, never pushed to `main`.
- ✅ Quality gates run, results reported in full — no gate is hidden, and §4 says
  plainly what is *not* proven.
- ✅ White-label maintained: a browser test feeds raw error text containing tool
  names through the new degradation notice and asserts none reaches the DOM.
- ✅ Secrets referenced by name only; the one new secret is flagged in §5.
- ⏸️ **Not merged, not deployed** — deliberate, per the task.
- ⏸️ No PR opened yet.
