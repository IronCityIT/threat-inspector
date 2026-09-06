/**
 * Tenant boundary — exchangeAuth0Token.
 *
 * firestore.rules gate every read on `request.auth.token.client_id`, and this
 * function is the ONLY thing that mints that claim. If it can be persuaded to
 * put someone else's tenant on a token, the rules are decoration.
 *
 * The property under test: the tenant is derived from the VERIFIED token
 * payload and from nothing else. resolveClientId() takes only claims — it has
 * no access to the request — so a body field, query string or header has no
 * path to influence it. These tests pin that, plus the slug normalisation that
 * has to agree with storeScanResults or a tenant would read from a partition
 * nothing writes to.
 *
 * NOT covered here: JWT signature verification itself. That is `jose`'s
 * jwtVerify against the live Auth0 JWKS, which needs the tenant. See
 * docs/SDLC_STATUS.md §4.
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

let exchange;
let store;
try {
  exchange = require(path.join(ROOT, "functions", "exchange.js"))._internal;
  store = require(path.join(ROOT, "functions", "index.js"))._internal;
} catch (e) {
  if (e.code === "MODULE_NOT_FOUND") {
    console.error("\nFunction dependencies are not installed.\n  cd functions && npm ci\n");
    process.exit(1);
  }
  throw e;
}
const { resolveClientId, toClientId, CLIENT_CLAIM } = exchange;

const results = [];
function test(name, fn) {
  try {
    fn();
    results.push([true, name]);
    console.log(`  ok   ${name}`);
  } catch (e) {
    results.push([false, name]);
    console.log(`  FAIL ${name}\n       ${e.message}`);
  }
}

console.log("\ntenant boundary (exchangeAuth0Token)");

// ---- the tenant comes from the token, and only the token ----------------

test("the namespaced claim decides the tenant", () => {
  assert.equal(resolveClientId({ [CLIENT_CLAIM]: "acme" }), "acme");
});

test("the Organization name is used when no explicit claim is set", () => {
  assert.equal(resolveClientId({ org_name: "Globex Inc" }), "globex-inc");
});

test("the Organization id is the last resort", () => {
  assert.equal(resolveClientId({ org_id: "org_ABC123" }), "org-abc123");
});

test("the explicit claim wins over the organisation", () => {
  const claims = { [CLIENT_CLAIM]: "acme", org_name: "Globex", org_id: "org_x" };
  assert.equal(resolveClientId(claims), "acme");
});

test("org_name wins over org_id", () => {
  assert.equal(resolveClientId({ org_name: "Globex", org_id: "org_x" }), "globex");
});

test("a token with no tenant resolves to nothing", () => {
  // The handler turns this into 403 no_client_assigned, deliberately distinct
  // from 401 so the dashboard can say "contact your administrator".
  assert.equal(resolveClientId({ sub: "auth0|123" }), "");
  assert.equal(resolveClientId({}), "");
});

test("request-supplied fields cannot name a tenant", () => {
  // resolveClientId only ever sees verified claims. Even if an attacker's token
  // payload carried these names, they are not the ones consulted.
  const hostile = {
    sub: "auth0|attacker",
    client_id: "victim-corp", // NOT the namespaced claim
    clientId: "victim-corp",
    tenant: "victim-corp",
    "https://evil.example/client_id": "victim-corp",
  };
  assert.equal(resolveClientId(hostile), "", "an unnamespaced client_id must not grant tenancy");
});

test("the claim namespace is the Iron City one", () => {
  assert.equal(CLIENT_CLAIM, "https://ironcityit.com/client_id");
});

// ---- slug agreement across functions ------------------------------------

test("exchange and store agree on the slug shape", () => {
  // A mismatch means a tenant signs in as one id and their scans are written
  // under another — they would see an empty dashboard forever.
  for (const value of [
    "Acme Corporation",
    "  ACME__Corp!!  ",
    "Globex Inc.",
    "org_ABC123",
    "a-b-c",
    "ÜmlautCo",
  ]) {
    assert.equal(
      toClientId(value),
      store.toClientId(value),
      `slug mismatch between exchange.js and index.js for ${JSON.stringify(value)}`
    );
  }
});

test("a tenant slug can never escape its Firestore path segment", () => {
  // client_id is interpolated into clients/{client_id}/scans/{scan_id}. A slug
  // containing a slash or a dot segment would address a different document.
  for (const hostile of [
    "../../etc/passwd",
    "a/b",
    "..",
    ".",
    "acme/../victim",
    "acme\\victim",
  ]) {
    const slug = toClientId(hostile);
    assert.ok(!slug.includes("/"), `${hostile} -> ${slug} contains a slash`);
    assert.ok(!slug.includes("\\"), `${hostile} -> ${slug} contains a backslash`);
    assert.ok(slug !== "." && slug !== "..", `${hostile} -> ${slug} is a path segment`);
  }
});

test("two different tenants never collapse to the same slug", () => {
  const a = toClientId("Acme Corporation");
  const b = toClientId("Globex Inc");
  assert.notEqual(a, b);
});

test("slugs are idempotent", () => {
  // The id is re-derived in several places; re-slugging must be a no-op or a
  // tenant's partition would drift on the second pass.
  for (const value of ["Acme Corporation", "org_ABC123", "a--b"]) {
    const once = toClientId(value);
    assert.equal(toClientId(once), once, `not idempotent for ${value}`);
  }
});

const failed = results.filter(([ok]) => !ok);
console.log(`\n${results.length - failed.length} passed, ${failed.length} failed\n`);
process.exit(failed.length ? 1 : 0);
