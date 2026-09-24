/**
 * Audience policy for exchangeAuth0Token, kept free of Firebase and jose so it
 * can be unit-tested without the emulator.
 *
 * The audience is REQUIRED. Without one:
 *   - security: jwtVerify skips the aud check, so any JWT the shared Auth0 tenant
 *     signs (another product's API token, an ID token for any app) is accepted;
 *   - function: the SPA SDK issues an opaque access token when no audience is
 *     requested, which can never verify, so sign-in fails for every user.
 * Both are avoided by failing closed when AUTH0_AUDIENCE is unset.
 *
 * Tenant resolution stays in exchange.js (resolveClientId), unchanged.
 */

/** Returns null when the configuration is usable, otherwise a reason. */
function configProblem(audience) {
  if (!String(audience || "").trim()) return "AUTH0_AUDIENCE is not set";
  return null;
}

/** Options for jose's jwtVerify. Always includes the audience. */
function verifyOptions(issuer, audience) {
  const problem = configProblem(audience);
  if (problem) throw new Error(problem);
  return { issuer, audience: audience.trim() };
}

module.exports = { configProblem, verifyOptions };
