# ICIT Build Inventory — Confirmed From Project History

Reconstructed from a full search sweep of this project's chat history (not the memory
summary). Each item notes status and the last point it was confirmed. "Confirmed"
means it appears in an actual retrieved chat; "unconfirmed since" means I have no
record after that date and Claude Code should re-verify against the live repo/host.

> I cannot read private `IronCityIT` repo code from here. Anything marked "verify in
> repo" is a Task 0 job for the agent on the box (see TASKS.md).

---

## Core platform / shared services

**AI Consensus Engine** — repo `IronCityIT/consensus-engine`, workflow `.github/workflows/analyze.yml`.
Called by products via `workflow_call`. Started as a 10-model Colab prototype (Jan),
grew to the 15-model weighted vote. Repo confirmed to exist with the workflow (2/16).
Same 3 secrets: `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`. Open: confirm
end-to-end test actually passed on each product (DNS Guard chat flagged this was never
verified — products fall back to raw analysis if the engine call fails).

**Auth0** — tenant `dev-ws5377dam2tnlv5g.us.auth0.com`, Organizations for multi-tenant SSO. Confirmed.

**GCP** — region us-east5. Note from history: an early GCP project had billing closed
after ~$302 burn; deployments run under `ironcity-attacksimpro`, `iron-city-it-threatinspector`,
`icit-dnsguard`, `ironcityit-runner`. Two Google accounts were in play (gannonfb58 and
blaukaitis cloudshell) — verify which owns each Firebase project before deploying.

---

## Products

**AttackSim Pro** — `asp.ironcityit.com`. LIVE / sacred. Offensive BAS product.
Built from ~19 open-source repos on DigitalOcean (~$74/mo). Tool set: ZAP, Nuclei,
Nikto, WPScan, authenticated scans, Metasploit, Empire, Veil, Atomic Red Team, MITRE
ATT&CK emulation; findings → consensus engine → Firebase dashboard with risk grades
(A+–D) and compliance mapping (NIST, CIS, PCI-DSS, HIPAA, SOC2, OWASP). Empire/Veil/
Metasploit gated behind written client authorization. **This is the target of the tool
expansion — see ASP-TOOL-EXPANSION.md.**

**ICIT Sentinel SIEM** — `sentinel.ironcityit.com`. LIVE / sacred. Wazuh 4.14.4 +
OpenSearch + Logstash "Beast Mode" v6.0 (11-stage pipeline) on DigitalOcean
`165.227.249.122`. Multi-tenant Stage-11 routing. Tenants confirmed: ironcity,
heatherwhite, sagespine, cyber-discovery (+ Southern Breeze, Angel's per memory).
Full runbook in project instructions. Not part of the GH-Actions product queue.

**Command Center Portal** — `portal.ironcityit.com`. LIVE / sacred. Auth0 Organizations,
multi-tenant, `/run` triggers product workflows. Hosted Vercel (history) — confirm.

**IronClad Compliance** — CISO Assistant white-label on QNAP (frontend `icit-ironclad-frontend:v3.17.1`).
NOT a GH-Actions product. Only outstanding item noted: branding-completeness audit
(scan for residual "CISO Assistant" strings, confirm gold oklch ramp + logo).

**Threat Inspector** — `IronCityIT/ICIT-ThreatInspector`, Firebase project
`iron-city-it-threatinspector`. Defensive twin of ASP. Tool set: Nmap, SSL Labs,
Subfinder, httpx, Trivy, Gitleaks, CloudSploit, Nikto. Firebase platform folder existed
(`threatinspector-platform/`) but deployment path/account was unresolved as of Jan
("which Cloud Shell account/folder"). **Verify current deploy state in repo — first in queue.**

**DNS Guard** — `IronCityIT/ICIT-DNSGuard`, Firebase `icit-dnsguard`. v4.0 built
(session isolation, AI integration, SMB email-security focus, A+–F grade). Workflow
`dns-analysis.yml` calls consensus-engine. As of 2/16 it was mid-deploy (`firebase.json`
not yet located in the pushed dir). Inputs: domain (req), client_name, scan_id,
enable_subdomains, enable_threat_intel. Cloud Function `triggerDNSScan` does HubSpot
contact + workflow trigger + Firestore. **Verify live state in repo.**

**ShadowScan** — deep/dark-web monitoring. Python complete, NOT productized. Uses
`VIRUSTOTAL_API_KEY`. A 6/19 session already wrote a Claude Code prompt to productize it
onto the standard arch. Repo TBD under IronCityIT.

**Surge** — web/eComm performance optimization. Python complete, NOT productized.
6/19 prompt exists. Repo TBD.

**Dynamic Experience Analyzer** — Puppeteer/Selenium web-interaction analysis. Python
complete, NOT productized. **Has a real prior code review (1/09):** Selenium-based;
tests Login/PageLoad/HTTPS/Mobile/Checkout/404/AccessControl/Performance; problems =
hardcoded Windows paths (`Z:/`,`L:/`), hardcoded creds, no multi-tenant, no config UI,
timing chart shows 0, perf tests are placeholders. Recommended: migrate Selenium→Playwright.
6/19 prompt exists. Repo TBD.

**IronSight Forensics** — planned, architecture only, not started. AI forensics
(Volatility, YARA, Plaso). `forensics.ironcityit.com` target.

**Continuity Guard** — planned, BC/DR IaC. Not started.

---

## MSP delivery infrastructure

**NetLock RMM** — `ICIT-RMM-01`, Hetzner CPX31, Ubuntu 24.04, `5.78.208.138`.
v3.0.0.0g "Astaroth", Docker + MySQL 8.0, compose `/home/netlock/docker-compose.yml`.
Console `rmm.support.ironcityit.com`; agent endpoints `agent.support.ironcityit.com:443`
(all 5 backend fields) + `relay.support.ironcityit.com:443`. Angel's Distributing
cutover done 7/1 — 15 devices enrolled/authorized at DB level. A vendor Members-Portal
license bug locked the console during cutover; resolved by vendor Nico Mak (TKT-44550245)
via compose down/up. Custom ticket-intake poller `/opt/icit/ticket-intake.py` (IMAP →
MySQL, UID high-water mark + Message-ID dedup). Open: SMTP ack emails not sent (Gmail
465 SSL); image-tag pinning off `:latest`; watchtower restart policy → `no`; offline
license grace mode from Nico; pending kernel update + reboot.

**Dograh "Sam" voice agent** — `ICIT-Frontline-01`, Hetzner, `5.78.185.200`. Dograh
(Pipecat) in Docker + `icit-edge` FastAPI. v2 workflow LIVE (33,546 bytes, tag
`v2-2026-06-25`, 10 nodes/12 edges), confirmed clean via run 27 (`user_qualified`).
Target `workflow_definitions.workflow_json` for live changes. LLM Groq
`llama-3.3-70b-versatile` (free-tier 503s → Developer tier pending; OpenRouter failover
chosen as safety net). Twilio `+14125326043`. Transfer tool: native `transfer_call`
exists but 2 confirmed bugs (Conference startConferenceOnEnter patched via sed but likely
lost in migration; caller leg never redirected into conference — never fixed). Agreed
path = blind-transfer rewrite, deferred pending live `provider.py`. Open: rotate all keys
in `user_configurations.id=1`; A2P 10DLC opt-in rejection; Sam voice/name change.

**QNAP TS-453D** — `192.168.1.177`. Hosts IronClad/CISO Assistant, Iron Vault (Passbolt
white-label, `vault.ironcityit.com`), OpenBB, Jenkins, ironcity-api (Flask/MariaDB),
Cloudflare tunnel, watchtower, Prowler, `icit-devbox` (Claude Code, Max/Opus).
BusyBox shell. HBS3→Google Drive + restic→Backblaze B2 (`ironkeep-fleet`).

**CanIPhish** — `aware.ironcityit.com`. White-label. Sage Spine on Gmail DMI.
Cloudflare proxy OFF for SaaS-issued CNAMEs.

**Backups** — Backblaze B2 restic, bucket `ironkeep-fleet`, per-host cron
(RMM 02:30, Frontline 03:00, Sentinel 03:30 UTC), Google Chat failure alerts.

---

## Clients (confirmed)
Angel's Distributing (RMM + voice; ~14 users/13 endpoints, FortiGate 60F, M365,
Zoho; JAWS screen-reader constraint), Heather White Accounting (SIEM/O365),
Sage Spine (SIEM, HIPAA CE), Cyber Discovery Solutions (SIEM, forensics),
Southern Breeze Heating & Air (SIEM GWorkspace).

---

## Honest gaps
- Exact current deploy state of Threat Inspector, DNS Guard, Command Center hosting:
  last touched Jan–Feb, not re-confirmed. Agent must verify in repo (Task 0).
- Whether consensus-engine end-to-end actually passes per product: never verified in history.
- ShadowScan/Surge/DXA source repo locations: "TBD" — agent inventories or Bill points.
