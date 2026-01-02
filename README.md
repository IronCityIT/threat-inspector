# 🛡️ Iron City Threat Inspector

**Advanced Threat Detection for Proactive Security**

[![License](https://img.shields.io/badge/license-Proprietary-red.svg)]()
[![Platform](https://img.shields.io/badge/platform-GitHub%20Actions-blue.svg)]()
[![Security](https://img.shields.io/badge/security-Enterprise%20Grade-green.svg)]()

---

## Overview

Iron City Threat Inspector is your first line of defense against sophisticated cyber threats. With advanced algorithms and detailed analysis, Threat Inspector identifies vulnerabilities that traditional systems might miss. Get actionable insights and real-time threat intelligence to fortify your defenses and stay ahead of potential attacks.

**This is a Blue Team defensive tool** - focused on continuous monitoring, asset discovery, and vulnerability identification before attackers find them.

---

## 🔧 Available Scans

| Workflow | Purpose | Risk Level |
|----------|---------|------------|
| `nmap-scan.yml` | Port scanning & service detection | 🟢 Safe |
| `ssl-grade.yml` | TLS/SSL certificate grading | 🟢 Safe |
| `asset-discovery.yml` | Subdomain & asset enumeration | 🟢 Safe |
| `secret-scan.yml` | Exposed secrets detection | 🟢 Safe |
| `container-scan.yml` | Docker/container vulnerabilities | 🟢 Safe |
| `vuln-parse.yml` | Parse Qualys/ZAP/Nmap scan files | 🟢 Safe |

---

## 🚀 Usage

### Via GitHub CLI

```bash
# Port Scan
gh workflow run nmap-scan.yml \
  -f target="192.168.1.1" \
  -f scan_id="client-$(date +%s)" \
  -f client_id="acme"

# SSL Grade
gh workflow run ssl-grade.yml \
  -f target="example.com" \
  -f scan_id="client-$(date +%s)" \
  -f client_id="acme"

# Asset Discovery
gh workflow run asset-discovery.yml \
  -f target="example.com" \
  -f scan_id="client-$(date +%s)" \
  -f client_id="acme"

# Parse Vulnerability Scans
gh workflow run vuln-parse.yml \
  -f scan_id="client-$(date +%s)" \
  -f client_id="acme"
```

### Via GitHub API

```bash
curl -X POST \
  -H "Authorization: token $GITHUB_PAT" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/IronCityIT/ICIT-ThreatInspector/actions/workflows/nmap-scan.yml/dispatches \
  -d '{"ref":"main","inputs":{"target":"192.168.1.1","scan_id":"abc123","client_id":"acme"}}'
```

---

## 📁 Repository Structure

```
ICIT-ThreatInspector/
├── .github/
│   └── workflows/
│       ├── nmap-scan.yml        # Port scanning
│       ├── ssl-grade.yml        # TLS/SSL grading
│       ├── asset-discovery.yml  # Subdomain enumeration
│       ├── secret-scan.yml      # Gitleaks secret detection
│       ├── container-scan.yml   # Trivy container scanning
│       └── vuln-parse.yml       # Parse scan files & generate reports
├── configs/
│   └── client.yaml              # Client configuration template
├── scripts/
│   ├── parse_qualys.py          # Qualys parser
│   ├── parse_zap.py             # ZAP XML parser
│   ├── parse_nmap.py            # Nmap parser
│   └── generate_report.py       # HTML report generator
├── scans/                       # Upload scan files here
├── outputs/                     # Generated reports
└── README.md
```

---

## ⚙️ Configuration

Edit `configs/client.yaml` before running vulnerability parsing:

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

## 🔒 Security

- All scans are **CLI-triggered only** (no defaults = no free rides)
- `scan_id` required to track and validate requests
- `client_id` for multi-tenant reporting
- Results stored in Firebase with 90-day retention
- No credentials stored in workflows

---

## 📊 Results

Scan results are:
1. Saved as GitHub Action artifacts (90-day retention)
2. Posted to Firebase Cloud Function
3. Displayed on the Threat Inspector dashboard

---

## License

Proprietary - Iron City IT Advisors © 2024
