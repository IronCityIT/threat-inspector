/**
 * exchangeAuth0Token — the bridge between Auth0 and Firestore's tenancy model.
 *
 * firestore.rules gate every read on `request.auth.token.client_id`. Nothing was
 * minting that claim, so the rules were unsatisfiable and the dashboard could
 * never read its own data. This function closes that gap:
 *
 *   Auth0 access token  ->  verified against the tenant's JWKS
 *                       ->  client_id resolved from the Auth0 Organization
 *                       ->  Firebase custom token carrying that claim
 *
 * The client_id is taken ONLY from the verified token. A caller cannot ask for
 * another tenant's id: it is never read from the request body or query string.
 *
 * Region: us-east5 (Columbus) — ICIT standard, no exceptions.
 */

const { onRequest } = require("firebase-functions/v2/https");
const logger = require("firebase-functions/logger");
const { initializeApp, getApps } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { createRemoteJWKSet, jwtVerify } = require("jose");

if (!getApps().length) initializeApp();

const REGION = "us-east5";
const AUTH0_DOMAIN = process.env.AUTH0_DOMAIN || "dev-ws5377dam2tnlv5g.us.auth0.com";
const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE || "";

// Namespaced claim is the preferred source — an Auth0 Action sets it explicitly.
// Falling back to the Organization means SSO tenants work without a custom Action.
const CLIENT_CLAIM = "https://ironcityit.com/client_id";

const ISSUER = `https://${AUTH0_DOMAIN}/`;
const jwks = createRemoteJWKSet(new URL(`${ISSUER}.well-known/jwks.json`));

/** Normalize into the same slug shape storeScanResults and triggerScan use. */
function toClientId(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/**
 * Resolve the tenant from VERIFIED token claims, and from nothing else.
 *
 * This is the whole tenancy boundary in one function. It takes only the payload
 * of a signature-verified Auth0 token: it has no access to the request, so
 * there is no path by which a body field, query string or header could name a
 * tenant. Extracted so that property can be tested directly rather than
 * inferred by reading the handler.
 *
 * Precedence: the namespaced claim an Auth0 Action sets explicitly, then the
 * Organization name, then the Organization id.
 */
function resolveClientId(claims) {
  return toClientId(claims[CLIENT_CLAIM] || claims.org_name || claims.org_id);
}

exports.exchangeAuth0Token = onRequest(
  { region: REGION, cors: true },
  async (req, res) => {
    if (req.method !== "POST") {
      res.status(405).json({ error: "method_not_allowed" });
      return;
    }

    const header = req.get("Authorization") || "";
    const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
    if (!token) {
      res.status(401).json({ error: "missing_token" });
      return;
    }

    let claims;
    try {
      const verified = await jwtVerify(token, jwks, {
        issuer: ISSUER,
        ...(AUTH0_AUDIENCE ? { audience: AUTH0_AUDIENCE } : {}),
      });
      claims = verified.payload;
    } catch (err) {
      // Signature, issuer, audience or expiry — all are "not a valid session".
      logger.warn("token verification failed", { reason: String(err && err.code) });
      res.status(401).json({ error: "invalid_token" });
      return;
    }

    // From the verified token only — never from req.body or req.query.
    const clientId = resolveClientId(claims);
    if (!clientId) {
      // Authenticated but unassigned. Deliberately distinct from 401 so the
      // dashboard can tell the user to contact an administrator.
      logger.warn("no tenant on token", { sub: claims.sub });
      res.status(403).json({ error: "no_client_assigned" });
      return;
    }

    try {
      const uid = `auth0:${claims.sub}`;
      // This claim is what firestore.rules reads. Nothing else grants tenancy.
      const firebaseToken = await getAuth().createCustomToken(uid, { client_id: clientId });
      logger.info("minted tenant token", { client_id: clientId, sub: claims.sub });
      res.status(200).json({
        firebase_token: firebaseToken,
        client_id: clientId,
        client_name: claims.org_name || clientId,
      });
    } catch (err) {
      logger.error("custom token mint failed", err);
      res.status(500).json({ error: "mint_failed" });
    }
  }
);

// Exported for tests (tests/functions/tenancy.test.mjs). Not an HTTP surface.
exports._internal = { toClientId, resolveClientId, CLIENT_CLAIM, ISSUER };
