/**
 * storeScanResults authentication.
 *
 * This endpoint writes into a client's Firestore partition, so an
 * unauthenticated caller could inject findings into ANY tenant. These tests
 * cover the gate itself: the secure-by-default refusal, the bearer check, and
 * the constant-time comparison.
 *
 * verifyIngest/safeEqual are pulled from functions/index.js via `_internal`.
 * Requiring index.js initialises firebase-admin, which is why the suite stubs
 * the credential lookup rather than reaching for one.
 */

import assert from "node:assert/strict";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const require = createRequire(import.meta.url);

// firebase-admin needs a project to initialise against; nothing here talks to it.
process.env.GCLOUD_PROJECT = process.env.GCLOUD_PROJECT || "test-project";
process.env.FIREBASE_CONFIG = process.env.FIREBASE_CONFIG || JSON.stringify({ projectId: "test-project" });

// index.js requires firebase-functions, which lives under functions/node_modules.
// Without a clear message here the failure is a raw MODULE_NOT_FOUND stack.
let _internal;
try {
  ({ _internal } = require(path.join(ROOT, "functions", "index.js")));
} catch (e) {
  if (e.code === "MODULE_NOT_FOUND") {
    console.error(
      "\nFunction dependencies are not installed.\n" +
        "  cd functions && npm ci\n"
    );
    process.exit(1);
  }
  throw e;
}
const { verifyIngest, safeEqual, toClientId } = _internal;

/** Minimal stand-in for an Express request. */
function req(authorization) {
  return { get: (name) => (name.toLowerCase() === "authorization" ? authorization : undefined) };
}

const results = [];

/**
 * Run one case with the function's own structured logging muted.
 *
 * verifyIngest logs at error/warn on every rejection — which is the point of it
 * — so an un-muted run buries the results under a dozen JSON log lines. The
 * output is captured, not discarded: it is replayed when a case fails.
 */
function test(name, fn) {
  const captured = [];
  const realOut = process.stdout.write.bind(process.stdout);
  const realErr = process.stderr.write.bind(process.stderr);
  const sink = (chunk) => (captured.push(String(chunk)), true);
  process.stdout.write = sink;
  process.stderr.write = sink;
  let error = null;
  try {
    fn();
  } catch (e) {
    error = e;
  } finally {
    process.stdout.write = realOut;
    process.stderr.write = realErr;
  }
  if (error) {
    results.push([false, name]);
    console.log(`  FAIL ${name}\n       ${error.message}`);
    for (const line of captured) process.stderr.write(line);
  } else {
    results.push([true, name]);
    console.log(`  ok   ${name}`);
  }
}

console.log("\nstoreScanResults auth");

// ---- secure by default --------------------------------------------------

test("refuses to serve when no token is configured", () => {
  delete process.env.ALLOW_UNAUTHENTICATED_INGEST;
  const denied = verifyIngest(req("Bearer anything"), "");
  assert.equal(denied.status, 503);
  assert.equal(denied.error, "ingest_not_configured");
});

test("an unconfigured endpoint refuses even an empty bearer", () => {
  delete process.env.ALLOW_UNAUTHENTICATED_INGEST;
  assert.equal(verifyIngest(req(undefined), undefined).status, 503);
});

test("the migration override is opt-in and explicit", () => {
  process.env.ALLOW_UNAUTHENTICATED_INGEST = "true";
  assert.equal(verifyIngest(req(undefined), ""), null, "override should allow the call");
  delete process.env.ALLOW_UNAUTHENTICATED_INGEST;
});

test("the override only accepts the exact string 'true'", () => {
  for (const value of ["1", "yes", "TRUE", ""]) {
    process.env.ALLOW_UNAUTHENTICATED_INGEST = value;
    assert.equal(verifyIngest(req(undefined), "").status, 503, `'${value}' must not enable it`);
  }
  delete process.env.ALLOW_UNAUTHENTICATED_INGEST;
});

// ---- bearer check -------------------------------------------------------

const SECRET = "s3cret-token-value";

test("a correct bearer token is accepted", () => {
  assert.equal(verifyIngest(req(`Bearer ${SECRET}`), SECRET), null);
});

test("the scheme is case-insensitive and tolerates padding", () => {
  assert.equal(verifyIngest(req(`  bearer   ${SECRET}`), SECRET), null);
});

test("a wrong token is rejected with 401", () => {
  const denied = verifyIngest(req("Bearer wrong-token-value"), SECRET);
  assert.equal(denied.status, 401);
  assert.equal(denied.error, "unauthorized");
});

test("a missing Authorization header is rejected", () => {
  assert.equal(verifyIngest(req(undefined), SECRET).status, 401);
});

test("a token without the Bearer scheme is rejected", () => {
  assert.equal(verifyIngest(req(SECRET), SECRET).status, 401);
});

test("a token that is a prefix of the secret is rejected", () => {
  assert.equal(verifyIngest(req(`Bearer ${SECRET.slice(0, -1)}`), SECRET).status, 401);
});

test("a token that merely starts with the secret is rejected", () => {
  assert.equal(verifyIngest(req(`Bearer ${SECRET}extra`), SECRET).status, 401);
});

// ---- constant-time comparison -------------------------------------------

test("safeEqual matches identical values", () => {
  assert.equal(safeEqual("abc", "abc"), true);
});

test("safeEqual rejects different values", () => {
  assert.equal(safeEqual("abc", "abd"), false);
});

test("safeEqual handles a length mismatch without throwing", () => {
  // crypto.timingSafeEqual throws on unequal lengths; that must not escape.
  assert.equal(safeEqual("short", "a-much-longer-value"), false);
  assert.equal(safeEqual("", "x"), false);
});

// ---- client id slug -----------------------------------------------------

test("client ids are slugified to a safe Firestore path segment", () => {
  assert.equal(toClientId("Acme Corporation"), "acme-corporation");
  assert.equal(toClientId("  ACME__Corp!!  "), "acme-corp");
  assert.equal(toClientId("../../etc/passwd"), "etc-passwd");
  assert.equal(toClientId(""), "");
  assert.equal(toClientId(null), "");
});

const failed = results.filter(([ok]) => !ok);
console.log(`\n${results.length - failed.length} passed, ${failed.length} failed\n`);
process.exit(failed.length ? 1 : 0);
