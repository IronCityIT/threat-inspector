/**
 * Validation of scan_id before it is used as a Firestore document id.
 *
 * Firestore rejects ids that contain "/", are "." or "..", match __.*__, or exceed
 * 1500 bytes. Passing one to doc() throws, which storeScanResults previously
 * surfaced as a 500 "store_failed". Validating up front returns a 400 instead.
 * The rules are exactly Firestore's, so no id Firestore accepts is rejected here.
 */

const MAX_ID_BYTES = 1500;

/** Returns null when valid, otherwise a short reason. */
function scanIdProblem(scanId) {
  if (!scanId) return "scan_id is required";
  if (scanId.includes("/")) return "scan_id must not contain '/'";
  if (scanId === "." || scanId === "..") return "scan_id must not be '.' or '..'";
  if (/^__.*__$/.test(scanId)) return "scan_id must not match __.*__";
  if (Buffer.byteLength(scanId, "utf8") > MAX_ID_BYTES) return "scan_id is too long";
  return null;
}

module.exports = { scanIdProblem, MAX_ID_BYTES };
