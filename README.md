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

## 📁 Repository Structure

```
threat-inspector/
├── .github/workflows/
│   ├── port-scan.yml          # Port & service discovery
│   ├── ssl-grade.yml          # TLS/SSL grading + security headers
│   ├── asset-discovery.yml    # Subdomain & asset enumeration
│   ├── vuln-report.yml        # Aggregate uploaded scan exports
│   └── _consensus-store.yml   # Shared: AI consensus → storeScanResults
├── functions/                 # storeScanResults Cloud Function (Firestore ingest)
├── firestore.rules            # Multi-tenant read rules (filter by client_id)
├── src/threat_inspector/      # Aggregation library, CLI, and local API/dashboard
├── configs/client.yaml        # Client configuration template
└── module_framework/          # Shared modular scan framework (adoption in progress)
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

- All scans are **workflow_dispatch-triggered** — no unattended default runs.
- `client_name` is required and resolves to a `client_id` on every stored result.
- Firestore data is partitioned as `clients/{client_id}/scans/{scan_id}`; security rules
  restrict dashboard reads to the caller's own client (gated on Auth0 organization).
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
