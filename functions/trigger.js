/**
 * Iron City Threat Inspector — triggerScan Cloud Function
 *
 * Closes UI-accessibility gap (b): the dashboard cannot start a scan without a
 * server-side trigger, because dispatching a GitHub workflow requires a token
 * that must never reach the browser.
 *
 *   dashboard button -> triggerScan (this function)
 *                         -> writes clients/{client_id}/scans/{scan_id} status:"queued"
 *                         -> POST /actions/workflows/{file}/dispatches
 *                            -> scan workflow runs
 *                               -> storeScanResults overwrites the record
 *                                  with status:"completed" (or "failed")
 *
 * The queued record is written FIRST and on purpose: it is what makes a scan
 * visible in the dashboard the instant the button is pressed, and it is the
 * record the workflow's failure reporter updates if the run dies.
 *
 * Region: us-east5 (Columbus) — ICIT standard, no exceptions.
 *
 * MULTI-TENANCY: client_id is read from the VERIFIED auth token claim, never
 * from the request body. A caller cannot queue a scan into another tenant.
 *
 * ---------------------------------------------------------------------------
 * REQUIRES A SECRET BILL MUST PROVISION.
 * Dispatching a workflow needs a GitHub token with `actions:write` on
 * IronCityIT/threat-inspector. That secret is not in the approved ICIT list, so
 * its value is not invented here — it is referenced as GITHUB_DISPATCH_TOKEN and
 * must exist in Secret Manager (us-east5) before this function will deploy.
 * See PRODUCTIZE_NOTES.md.
 * ---------------------------------------------------------------------------
 */

const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const logger = require("firebase-functions/logger");
const { initializeApp, getApps } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

if (!getApps().length) initializeApp();
const db = getFirestore();

const REGION = "us-east5";
const REPO = "IronCityIT/threat-inspector";

// See the HALT note above — provisioned by Bill, not by the agent.
const GITHUB_DISPATCH_TOKEN = defineSecret("GITHUB_DISPATCH_TOKEN");

/**
 * Workflows the dashboard is allowed to start, and the inputs each accepts.
 * This is an allow-list on purpose: an arbitrary workflow_file from the browser
 * would let a caller run anything in the repo.
 *
 * Keep in sync with .github/workflows/ and with registry.catalog() — the CLI,
 * this trigger, and the dashboard must offer the same selection.
 */
const DISPATCHABLE = {
  scan: { file: "scan.yml", inputs: ["target", "client_name", "scan_id", "modules", "group"] },
  "asset-discovery": { file: "asset-discovery.yml", inputs: ["target", "client_name", "scan_id"] },
  "port-scan": { file: "port-scan.yml", inputs: ["target", "client_name", "scan_id", "scan_type"] },
  "ssl-grade": { file: "ssl-grade.yml", inputs: ["target", "client_name", "scan_id"] },
  "vuln-report": { file: "vuln-report.yml", inputs: ["target", "client_name", "scan_id"] },
};

exports.triggerScan = onCall(
  { region: REGION, secrets: [GITHUB_DISPATCH_TOKEN] },
  async (request) => {
    const auth = request.auth;
    if (!auth) {
      throw new HttpsError("unauthenticated", "Sign-in required.");
    }

    // The tenant is whoever the token says it is. Never the request body.
    const clientId = String(auth.token.client_id || "").trim();
    if (!clientId) {
      throw new HttpsError(
        "permission-denied",
        "No client is associated with this account."
      );
    }

    const data = request.data || {};
    const workflow = DISPATCHABLE[String(data.workflow || "scan")];
    if (!workflow) {
      throw new HttpsError("invalid-argument", "Unknown scan type.");
    }

    const target = String(data.target || "").trim();
    if (!target) {
      throw new HttpsError("invalid-argument", "A target is required.");
    }

    // scan_id is minted server-side so the dashboard can poll for it immediately
    // and two tenants can never collide on one document.
    const scanId = `ti-${clientId}-${Date.now()}`;
    const ref = db
      .collection("clients")
      .doc(clientId)
      .collection("scans")
      .doc(scanId);

    const inputs = { target, client_name: clientId, scan_id: scanId };
    if (workflow.inputs.includes("modules") && data.modules) {
      inputs.modules = Array.isArray(data.modules) ? data.modules.join(",") : String(data.modules);
    }
    if (workflow.inputs.includes("group") && data.group) inputs.group = String(data.group);
    if (workflow.inputs.includes("scan_type") && data.scan_type) {
      inputs.scan_type = String(data.scan_type);
    }

    // Queued record first: the scan is visible in the UI before the dispatch
    // round-trip, and a dispatch that fails below is recorded as failed rather
    // than vanishing.
    await ref.set({
      client_id: clientId,
      client_name: clientId,
      scan_id: scanId,
      scan_type: String(data.workflow || "scan"),
      target,
      status: "queued",
      summary: { total: 0 },
      findings: [],
      requested_by: auth.uid,
      created_at: FieldValue.serverTimestamp(),
    });

    const url =
      `https://api.github.com/repos/${REPO}/actions/workflows/` +
      `${workflow.file}/dispatches`;

    let response;
    try {
      response = await fetch(url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${GITHUB_DISPATCH_TOKEN.value()}`,
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ ref: "main", inputs }),
      });
    } catch (err) {
      // A dispatch that never left the building still has to resolve in the UI.
      logger.error("dispatch request threw", { scan_id: scanId, err: String(err) });
      await ref.set(
        { status: "failed", error: { stage: "dispatch", message: "Scan could not be started." } },
        { merge: true }
      );
      throw new HttpsError("unavailable", "Scan could not be started.");
    }

    if (!response.ok) {
      const detail = await response.text().catch(() => "");
      // Internal detail goes to logs only — the client sees a generic message
      // and never the upstream provider's response.
      logger.error("workflow dispatch rejected", {
        scan_id: scanId,
        status: response.status,
        detail: detail.slice(0, 500),
      });
      await ref.set(
        { status: "failed", error: { stage: "dispatch", message: "Scan could not be started." } },
        { merge: true }
      );
      throw new HttpsError("internal", "Scan could not be started.");
    }

    logger.info("scan dispatched", {
      client_id: clientId,
      scan_id: scanId,
      workflow: workflow.file,
    });

    // scan_id + client_id are what the dashboard subscribes to for live status.
    return { scan_id: scanId, client_id: clientId, status: "queued" };
  }
);
