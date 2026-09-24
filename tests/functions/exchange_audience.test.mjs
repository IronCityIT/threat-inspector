/**
 * exchangeAuth0Token — audience is required, and triggerScan ids never collide.
 *
 * With AUTH0_AUDIENCE unset the exchange used to call jwtVerify without an
 * audience, so any JWT the shared Auth0 tenant signs verified (another
 * product's API token, an ID token for any app). It also meant the SPA SDK got
 * an opaque access token that can never verify, and the dashboard reported that
 * as "not linked to a client organisation". Real RS256 tokens are signed here
 * with a locally generated key; nothing talks to Auth0 or Firestore.
 */

import assert from "node:assert/strict";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const require = createRequire(import.meta.url);

process.env.GCLOUD_PROJECT = process.env.GCLOUD_PROJECT || "test-project";
process.env.FIREBASE_CONFIG =
  process.env.FIREBASE_CONFIG || JSON.stringify({ projectId: "test-project" });
delete process.env.AUTH0_AUDIENCE;

let jose, exchange;
try {
  jose = require(path.join(ROOT, "functions", "node_modules", "jose"));
  exchange = require(path.join(ROOT, "functions", "exchange.js"));
} catch (e) {
  if (e.code === "MODULE_NOT_FOUND") {
    console.error("\nFunction dependencies are not installed.\n  cd functions && npm ci\n");
    process.exit(1);
  }
  throw e;
}
const { configProblem, verifyOptions } = require(path.join(ROOT, "functions", "exchange_policy.js"));
const { mintScanId, scanIdProblem } = require(path.join(ROOT, "functions", "scan_id.js"));

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push([true, name]);
    console.log(`  ok   ${name}`);
  } catch (e) {
    results.push([false, name]);
    console.log(`  FAIL ${name}\n       ${e.message}`);
  }
}

const ISSUER = "https://tenant.example/";
const AUDIENCE = "https://api.threat-inspector/";
const { publicKey, privateKey } = await jose.generateKeyPair("RS256");
const jwks = jose.createLocalJWKSet({ keys: [{ ...(await jose.exportJWK(publicKey)), kid: "k1", alg: "RS256" }] });
const sign = (aud) =>
  new jose.SignJWT({ org_name: "acme" })
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuer(ISSUER)
    .setAudience(aud)
    .setSubject("auth0|u1")
    .setExpirationTime("5m")
    .sign(privateKey);

console.log("\nexchangeAuth0Token audience");

await test("an unset or blank audience is a configuration problem", () => {
  for (const aud of [undefined, null, "", "   "]) {
    assert.equal(configProblem(aud), "AUTH0_AUDIENCE is not set");
    assert.throws(() => verifyOptions(ISSUER, aud));
  }
});

await test("legacy issuer-only options accepted a token minted for another app", async () => {
  const foreign = await sign("https://api.some-other-app/");
  await jose.jwtVerify(foreign, jwks, { issuer: ISSUER }); // did not throw: the defect
});

await test("required audience rejects another app's token and accepts ours", async () => {
  const foreign = await sign("https://api.some-other-app/");
  await assert.rejects(jose.jwtVerify(foreign, jwks, verifyOptions(ISSUER, AUDIENCE)), {
    code: "ERR_JWT_CLAIM_VALIDATION_FAILED",
  });
  const ours = await sign(AUDIENCE);
  await jose.jwtVerify(ours, jwks, verifyOptions(ISSUER, AUDIENCE));
});

await test("handler fails closed with 500 when AUTH0_AUDIENCE is unset", async () => {
  const out = {};
  const res = {
    status(code) { out.status = code; return this; },
    json(payload) { out.body = payload; return this; },
    set() { return this; }, setHeader() {}, getHeader() {}, on() {},
  };
  const auth = "Bearer x.y.z";
  const req = { method: "POST", body: {}, headers: { authorization: auth }, get: (h) => (h.toLowerCase() === "authorization" ? auth : undefined), header: () => undefined };
  await exchange.exchangeAuth0Token(req, res);
  assert.equal(out.status, 500);
  assert.deepEqual(out.body, { error: "exchange_misconfigured" });
});

console.log("\ntriggerScan scan ids");

await test("two ids minted in the same millisecond differ and are valid", () => {
  const a = mintScanId("acme", 1727200000000);
  const b = mintScanId("acme", 1727200000000);
  assert.match(a, /^ti-acme-1727200000000-[0-9a-f]{8}$/);
  assert.notEqual(a, b);
  assert.equal(scanIdProblem(a), null);
});

await test("legacy id scheme collided in the same millisecond", () => {
  const legacy = (clientId, now) => `ti-${clientId}-${now}`;
  assert.equal(legacy("acme", 1727200000000), legacy("acme", 1727200000000));
});

const failed = results.filter(([ok]) => !ok).length;
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
