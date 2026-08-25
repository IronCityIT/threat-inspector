# Threat Inspector — UI Wiring

How the product becomes startable from a dashboard, and what is still missing.

A tool counts as "accessible from the UI" only when all three of these hold:

| | Requirement | State |
|---|---|---|
| (a) | `workflow_dispatch` with correct typed inputs | **Done** — all 6 workflows, in this repo |
| (b) | A trigger Cloud Function (`triggerScan`) | **Scaffolded** — `functions/trigger.js`, deployed by `deploy-functions.yml`, needs `GITHUB_DISPATCH_TOKEN` |
| (c) | A dashboard button/route wired to that function | **Blocked** — this repo has no dashboard |

## (a) Dispatchable workflows

Each accepts the ICIT standard inputs (`target`, `client_name`, `scan_id`) with
explicit types, so the GitHub UI, the `gh` CLI, and the trigger function all agree
on the contract.

| Workflow file | Purpose | Extra inputs |
|---|---|---|
| `scan.yml` | Modular scan (the main entry point) | `modules` (string), `group` (choice: quick/standard/deep) |
| `asset-discovery.yml` | Asset enumeration | — |
| `port-scan.yml` | Network exposure | `scan_type` (choice: quick/standard/full) |
| `ssl-grade.yml` | Transport security posture | — |
| `vuln-report.yml` | Aggregate uploaded exports | — |
| `file-scan.yml` | File ingestion | `files_path`, `modules`, `group` (choice: ingest/deep), `defectdojo_export` (boolean) |

`scan.yml` is the one the dashboard should drive: its `modules` / `group` inputs map
1:1 onto `registry.catalog()`, which is the same catalog the module checkboxes and
group presets render from. One source of truth for CLI and UI.

```bash
# The catalog the dashboard should render from:
python3 module_framework/cli.py --list-modules
```

## (b) Trigger Cloud Function — scaffolded, NOT deployed

`functions/trigger.js` implements `triggerScan` as an `onCall` function in
**us-east5**. It:

1. reads `client_id` from the **verified auth token claim** (never the request body,
   so a caller cannot queue a scan into another tenant),
2. mints a server-side `scan_id`,
3. writes `clients/{client_id}/scans/{scan_id}` with `status: "queued"` so the scan
   appears in the UI immediately,
4. dispatches the workflow, and
5. marks the record `failed` if the dispatch itself fails.

The workflow then overwrites that record via `storeScanResults` with `completed` or
`failed`. `storeScanResults` treats status as monotonic — a completed scan is never
downgraded to failed — so a partial failure cannot erase stored findings.

### BLOCKER — a secret must be provisioned before deploy

Dispatching a workflow needs a GitHub token with `actions: write` on
`IronCityIT/threat-inspector`. **That secret is not in the approved ICIT secret list,
so its name was not invented by the agent.** It is referenced in the scaffold as
`GITHUB_DISPATCH_TOKEN`. Bill must decide the real name and provision it in Secret
Manager (us-east5) before deploy. Nothing else blocks (b).

Deploy (Bill, once the secret exists):

```bash
# from repo root, with the trigger function merged into the functions codebase
firebase deploy --only functions:triggerScan --project iron-city-it-threatinspector
```

## (c) Dashboard trigger — blocked, no dashboard exists

`firebase.json` declares only `functions` and `firestore` — there is **no `hosting`
block**, no `public/` or `dashboard/` directory, and no `index.html` anywhere in the
repo. There is nothing to wire a button into. This is the same blocker recorded in
`PRODUCTIZE_NOTES.md` for E2E adoption.

When the dashboard is built, this is the wiring. Module checkboxes and group presets
must be rendered from `registry.catalog()` output, not hardcoded.

```js
// dashboard/src/startScan.js
import { getFunctions, httpsCallable } from "firebase/functions";
import { getFirestore, doc, onSnapshot } from "firebase/firestore";

// us-east5 — must match the function's region or the call 404s.
const functions = getFunctions(app, "us-east5");
const triggerScan = httpsCallable(functions, "triggerScan");

/**
 * Start a scan and stream its status back to the UI.
 * clientId is NOT passed — the function reads it from the Auth0-minted token.
 */
export async function startScan({ target, modules, group, onUpdate }) {
  const { data } = await triggerScan({
    workflow: "scan",
    target,
    modules,          // e.g. ["port_scan", "tls_cert_check"] — from the catalog
    group,            // e.g. "standard" — ignored when modules is set
  });

  // Live status: queued -> completed | failed. Because the workflow always
  // writes a terminal state (its report-failure job guarantees it), this
  // subscription never hangs on "queued".
  const db = getFirestore(app);
  const ref = doc(db, "clients", data.client_id, "scans", data.scan_id);
  return onSnapshot(ref, (snap) => onUpdate(snap.data()));
}
```

```jsx
// dashboard/src/ScanButton.jsx
<button onClick={() => startScan({ target, modules: selected, group, onUpdate: setScan })}>
  Run scan
</button>

{scan?.status === "queued"    && <Spinner label="Scan running…" />}
{scan?.status === "completed" && <Findings items={scan.findings} summary={scan.summary} />}
{scan?.status === "failed"    && <Error message={scan.error?.message} />}
```

The `failed` branch is the one the workflow changes in this PR make reachable.
Before them, a scan that died mid-run wrote nothing at all and the UI sat on
`queued` forever.

Auth: the dashboard signs in through Auth0
(`dev-ws5377dam2tnlv5g.us.auth0.com`, Organizations), exchanges for a Firebase custom
token carrying the `client_id` claim, and `firestore.rules` gates every read on that
claim. No cross-tenant reads, no cross-tenant triggers.
