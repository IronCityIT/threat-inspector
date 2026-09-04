/**
 * Iron City Threat Inspector — Cloud Functions
 *
 * storeScanResults: ingest endpoint for scan results produced by the GitHub
 * Actions scan workflows (after AI consensus analysis). Every result is written
 * under its client_id so tenants are physically partitioned in Firestore:
 *
 *     clients/{client_id}/scans/{scan_id}
 *
 * Region: us-east5 (Columbus) — ICIT standard, no exceptions.
 *
 * Deployed by .github/workflows/deploy-functions.yml. The ingest endpoint
 * currently trusts its caller; hardening it with a dedicated ingest secret is
 * flagged in PRODUCTIZE_NOTES.md (a new secret name must be provisioned — not
 * invented here).
 */

const { onRequest } = require("firebase-functions/v2/https");
const logger = require("firebase-functions/logger");
const { initializeApp, getApps } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

// Guarded: trigger.js is loaded from this same deploy and also initialises.
if (!getApps().length) initializeApp();
const db = getFirestore();

const REGION = "us-east5";

/** Normalize a client name into a stable, path-safe client_id slug. */
function toClientId(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

exports.storeScanResults = onRequest(
  { region: REGION, cors: false },
  async (req, res) => {
    if (req.method !== "POST") {
      res.status(405).json({ error: "method_not_allowed" });
      return;
    }

    const body = req.body || {};
    // client_id is derived from the standard client_name input; accept either.
    const clientId = toClientId(body.client_id || body.client_name);
    const scanId = String(body.scan_id || "").trim();

    if (!clientId) {
      res.status(400).json({ error: "client_id (or client_name) is required" });
      return;
    }
    if (!scanId) {
      res.status(400).json({ error: "scan_id is required" });
      return;
    }

    const record = {
      client_id: clientId,
      client_name: body.client_name || null,
      scan_id: scanId,
      scan_type: body.scan_type || "unknown",
      target: body.target || null,
      status: body.status || "completed",
      // The scan's own health, distinct from whether the RUN completed. An empty
      // findings list means "nothing found" or "every capability failed", and a
      // client must not be shown the first when it was the second.
      scan_status: body.scan_status || null,
      // Which capabilities ran, which degraded, and why. Iron City module ids
      // only — never an underlying scanner's name.
      diagnostics: body.diagnostics || null,
      summary: body.summary || {},
      findings: Array.isArray(body.findings) ? body.findings : [],
      consensus: body.consensus || null,
      // Present only on failure records; lets the dashboard render "scan failed"
      // with a reason instead of leaving the scan pending forever.
      error: body.error || null,
      created_at: FieldValue.serverTimestamp(),
    };

    try {
      // Physically partition by client_id. Firestore rules (firestore.rules)
      // additionally gate dashboard reads to the caller's own client_id.
      const ref = db
        .collection("clients")
        .doc(clientId)
        .collection("scans")
        .doc(scanId);

      // Status is monotonic: a scan that already stored findings must never be
      // downgraded to "failed". The workflows report a failure whenever ANY job
      // in the run failed, which includes the case where the scan itself
      // succeeded and only the downstream analysis broke — that run has already
      // written real findings here, and clobbering them would lose client data.
      // The failure is still recorded, as a non-fatal error on the record.
      if (record.status === "failed") {
        const existing = await ref.get();
        if (existing.exists && existing.get("status") === "completed") {
          await ref.set(
            { error: body.error || { message: "a stage of this run failed" } },
            { merge: true }
          );
          logger.warn("failure report ignored — scan already completed", {
            client_id: clientId,
            scan_id: scanId,
          });
          res
            .status(200)
            .json({ status: "already_completed", client_id: clientId, scan_id: scanId });
          return;
        }
      }

      await ref.set(record, { merge: true });

      logger.info("stored scan result", {
        client_id: clientId,
        scan_id: scanId,
        scan_type: record.scan_type,
        findings: record.findings.length,
      });

      res.status(200).json({ status: "stored", client_id: clientId, scan_id: scanId });
    } catch (err) {
      logger.error("failed to store scan result", err);
      res.status(500).json({ error: "store_failed" });
    }
  }
);

// triggerScan lives in trigger.js but must be exported from the functions entry
// point, otherwise `firebase deploy --only functions` would ship storeScanResults
// alone and the dashboard would have nothing to call.
exports.triggerScan = require("./trigger").triggerScan;

// The Auth0 -> Firebase bridge. Without it firestore.rules can never be
// satisfied, because nothing else mints the client_id claim they gate on.
exports.exchangeAuth0Token = require("./exchange").exchangeAuth0Token;
