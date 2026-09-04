# 🛡️ Iron City Threat Inspector

**Advanced Threat Detection for Proactive Security**

[![License](https://img.shields.io/badge/license-Proprietary-red.svg)]()
[![Platform](https://img.shields.io/badge/platform-GitHub%20Actions-blue.svg)]()
[![Security](https://img.shields.io/badge/security-Enterprise%20Grade-green.svg)]()

---

## Overview

Iron City Threat Inspector is a **Blue Team defensive** platform for continuous monitoring,
asset discovery, and vulnerability identification — finding weaknesses before attackers do.
Scans run as GitHub Actions, results are analyzed by the Iron City AI consensus engine, and
findings are stored per-client and surfaced on the Threat Inspector dashboard.

---

## 🔧 Available Scans

Only the scans below exist in this repository today. (Additional capabilities — e.g. container
and secret scanning — are planned as separate modules and are **not** yet present.)

| Workflow | Purpose | Risk Level |
|----------|---------|------------|
| `port-scan.yml` | Port & service discovery | 🟢 Safe |
| `ssl-grade.yml` | TLS/SSL certificate & transport grading + security headers | 🟢 Safe |
| `asset-discovery.yml` | Subdomain & live-asset enumeration | 🟢 Safe |
| `vuln-report.yml` | Aggregate uploaded scan exports into normalized findings | 🟢 Safe |

Every scan feeds the shared pipeline: **findings → AI consensus analysis → `storeScanResults`
(Firestore, partitioned by client)**.

---

## 🚀 Usage

All scans are triggered via `workflow_dispatch` with the standard inputs `target`,
`client_name` (required), and `scan_id` (optional — auto-generated if omitted).

### Via GitHub CLI

```bash
# Port scan
gh workflow run port-scan.yml \
  -f target="192.168.1.1" \
  -f client_name="acme" \
  -f scan_id="acme-$(date +%s)"

# TLS/SSL grade
gh workflow run ssl-grade.yml \
  -f target="example.com" \
  -f client_name="acme"

# Asset discovery
gh workflow run asset-discovery.yml \
  -f target="example.com" \
  -f client_name="acme"

# Aggregate uploaded scan exports
gh workflow run vuln-report.yml \
  -f target="example.com" \
  -f client_name="acme"
```

### Via GitHub API

```bash
curl -X POST \
  -H "Authorization: token $GITHUB_PAT" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/IronCityIT/threat-inspector/actions/workflows/port-scan.yml/dispatches \
  -d '{"ref":"main","inputs":{"target":"192.168.1.1","client_name":"acme"}}'
```

---

## 🖥️ Running scans locally

Both entry points emit the same JSON document on stdout; progress, timings and
failures go to stderr, so stdout stays parseable.

```bash
# What can run?
python3 module_framework/cli.py --list-modules
python3 module_framework/ingest.py --list-modules

# Validate targets and selection without sending a single packet
python3 module_framework/cli.py --group standard --targets example.com --dry-run

# Active scan: individual modules, or a named group
python3 module_framework/cli.py --modules port_scan,tls_cert_check \
  --targets 10.0.0.0/30,https://app.example.com \
  --client acme --scan-id acme-$(date +%s)

# Ingest uploaded scan exports
python3 module_framework/ingest.py --group ingest \
  --files-dir examples/file-ingest-selftest --client acme
```

Targets accept an IP, a CIDR range, an http(s) URL, a domain, a hostname, or a
`--targets-file` (one per line, `#` comments allowed).

### Useful flags

| Flag | Effect |
|---|---|
| `--dry-run` | Validate targets and selection, run nothing. No network traffic. |
| `--strict-targets` | Refuse the whole batch if any target is invalid (default: report and scan the rest). |
| `--allow-local` | Permit loopback and link-local targets. Blocked by default. |
| `--module-timeout` | Seconds one module gets per target. Also `ICIT_MODULE_TIMEOUT`. |
| `--log-level` | `debug` shows per-module tracebacks. Also `ICIT_LOG_LEVEL`. |
| `--strict` (ingest) | Exit non-zero if any uploaded file failed to parse. |

### Reading the result

Every run reports its own health, so an empty findings list is never ambiguous:

| `status` | Meaning |
|---|---|
| `ok` | Everything selected ran. No findings means nothing was found. |
| `partial` | Some capabilities failed. `errors` says which, and why. |
| `failed` | Nothing ran successfully. **Not** a clean result. |
| `dry_run` | Validation only; no capability executed. |

`stats.timings` carries per-module duration and finding counts, and
`rejected_targets` lists anything that failed validation with a plain reason.

---

## ✅ Verifying a change

```bash
python3 -m pytest -q                # unit + integration suite
python3 tools/smoke_test.py         # end-to-end, real sockets, real fixtures
ruff format --check . && ruff check . && mypy module_framework src

# JavaScript. Install the function deps first — the function tests import
# functions/index.js, which needs firebase-functions.
npm ci && (cd functions && npm ci)
npm test                            # function auth + dashboard browser tests
```

`tools/smoke_test.py` stands up a local HTTP server and scans it, ingests the
committed fixtures, and builds a store payload — so it fails if the pieces stop
being wired together, which unit tests alone cannot catch. See
`docs/SDLC_STATUS.md` for current verified state and open blockers.

---

## 📁 Repository Structure

```
threat-inspector/
├── .github/workflows/
│   ├── port-scan.yml          # Port & service discovery
│   ├── ssl-grade.yml          # TLS/SSL grading + security headers
│   ├── asset-discovery.yml    # Subdomain & asset enumeration
│   ├── vuln-report.yml        # Aggregate uploaded scan exports
│   └── _consensus-store.yml   # Shared: AI consensus → storeScanResults
├── functions/                 # storeScanResults ingest, triggerScan, Auth0 exchange
├── firestore.rules            # Multi-tenant read rules (filter by client_id)
├── src/threat_inspector/      # Parser library, CLI, and local API
├── configs/client.yaml        # Client configuration template
├── module_framework/          # Modular scan framework (modules/ + file_modules/)
├── dashboard/public/          # Firebase-hosted dashboard (renders catalog.json)
├── examples/                  # Synthetic ingest fixtures (unroutable by design)
├── tools/                     # build_catalog, build_store_payload, smoke_test
└── docs/SDLC_STATUS.md        # Verified state, evidence, and open blockers
```

---

## ⚙️ Configuration

Edit `configs/client.yaml` before running the vulnerability-report aggregation:

```yaml
client:
  name: "Acme Corporation"
  engagement_id: "ENG-2024-001"

domains:
  - name: "acme.com"
    ips: ["192.168.1.10", "192.168.1.11"]
    subnets: ["192.168.1.0/24"]

scan_files:
  qualys: "scans/qualys_report.xlsx"
  zap: "scans/zap_scan.xml"
  nmap: "scans/nmap_results.txt"
```

---

## 🔒 Security & Multi-Tenancy

- Scans are **operator-triggered** via `workflow_dispatch`. The one exception is
  `scan.yml`, which also carries a weekly baseline schedule against the Iron City
  baseline target — never a client's estate, which always requires an explicit dispatch.
- `client_name` is required and resolves to a `client_id` on every stored result.
- Firestore data is partitioned as `clients/{client_id}/scans/{scan_id}`; security rules
  restrict dashboard reads to the caller's own client (gated on Auth0 organization).
- `storeScanResults` **authenticates its caller** with a bearer token and refuses to
  serve at all when unconfigured. It writes into client partitions, so an anonymous
  caller could otherwise inject findings into any tenant.
- **Loopback and link-local targets are refused** unless `--allow-local` is passed. The
  link-local range holds the cloud instance-metadata endpoint, and a scan on a hosted
  runner must not be steerable into reading its own credentials.
- **URL targets are restricted to http/https.** Modules pass targets to a URL opener
  that also speaks `file://`.
- No credentials are stored in workflows — secrets are referenced by name only.

---

## 📊 Results

Scan results are:
1. Saved as GitHub Action artifacts (90-day retention).
2. Analyzed by the Iron City AI consensus engine.
3. Stored in Firestore via the `storeScanResults` Cloud Function, keyed by `client_id`.
4. Displayed on the Threat Inspector dashboard (Auth0 login, per-client).

---

## License

Proprietary - Iron City IT Advisors © 2024
</content>
