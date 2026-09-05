/**
 * firestore.rules — REAL behavioural tests against the Firestore emulator.
 *
 * tests/test_firestore_rules.py asserts the SHAPE of the rules file. This
 * asserts what the rules actually DO: it stands up the emulator, loads the
 * committed firestore.rules, seeds two tenants, and tries to read across them
 * with genuinely-signed contexts.
 *
 * This is the test that can prove "no cross-tenant leakage". The structural one
 * cannot.
 *
 * Run it via the emulator, which supplies FIRESTORE_EMULATOR_HOST:
 *
 *     npm run test:rules
 *
 * Skips (loudly, never silently passing) when the emulator is not running, so
 * an environment without Java or firebase-tools reports the check as unproven
 * rather than green.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const PROJECT_ID = "demo-threat-inspector"; // `demo-` prefix => emulator-only

const host = process.env.FIRESTORE_EMULATOR_HOST;
if (!host) {
  console.log("\nfirestore.rules (emulator)");
  console.log("  SKIPPED (NOT PROVEN): FIRESTORE_EMULATOR_HOST is unset.");
  console.log("  Start it with:  npm run test:rules");
  process.exit(0);
}

const { initializeTestEnvironment, assertFails, assertSucceeds } = await import(
  "@firebase/rules-unit-testing"
);
const { doc, getDoc, setDoc, collection, getDocs } = await import("firebase/firestore");

const [emulatorHost, emulatorPort] = host.split(":");

const testEnv = await initializeTestEnvironment({
  projectId: PROJECT_ID,
  firestore: {
    rules: fs.readFileSync(path.join(ROOT, "firestore.rules"), "utf8"),
    host: emulatorHost,
    port: Number(emulatorPort),
  },
});

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

/** A signed-in caller carrying the client_id claim exchangeAuth0Token mints. */
function asTenant(clientId) {
  return testEnv.authenticatedContext(`auth0|user-of-${clientId}`, { client_id: clientId })
    .firestore();
}

console.log("\nfirestore.rules (emulator)");

// ---- seed two tenants, bypassing rules like the Admin SDK does -----------

await testEnv.withSecurityRulesDisabled(async (ctx) => {
  const db = ctx.firestore();
  await setDoc(doc(db, "clients/acme"), { client_id: "acme", name: "Acme" });
  await setDoc(doc(db, "clients/acme/scans/scan-1"), {
    client_id: "acme",
    target: "acme.example",
    findings: [{ severity: "high", title: "acme finding" }],
  });
  await setDoc(doc(db, "clients/globex"), { client_id: "globex", name: "Globex" });
  await setDoc(doc(db, "clients/globex/scans/scan-1"), {
    client_id: "globex",
    target: "globex.example",
    findings: [{ severity: "critical", title: "globex secret finding" }],
  });
});

// ---- a tenant reads its own data ---------------------------------------

await test("a tenant can read its own client document", async () => {
  await assertSucceeds(getDoc(doc(asTenant("acme"), "clients/acme")));
});

await test("a tenant can read its own scan", async () => {
  const snap = await assertSucceeds(getDoc(doc(asTenant("acme"), "clients/acme/scans/scan-1")));
  assert.equal(snap.data().target, "acme.example");
});

await test("a tenant can list its own scans", async () => {
  await assertSucceeds(getDocs(collection(asTenant("acme"), "clients/acme/scans")));
});

// ---- and nobody else's --------------------------------------------------

await test("a tenant CANNOT read another tenant's client document", async () => {
  await assertFails(getDoc(doc(asTenant("acme"), "clients/globex")));
});

await test("a tenant CANNOT read another tenant's scan", async () => {
  await assertFails(getDoc(doc(asTenant("acme"), "clients/globex/scans/scan-1")));
});

await test("a tenant CANNOT list another tenant's scans", async () => {
  await assertFails(getDocs(collection(asTenant("acme"), "clients/globex/scans")));
});

await test("the isolation holds in both directions", async () => {
  await assertFails(getDoc(doc(asTenant("globex"), "clients/acme/scans/scan-1")));
});

// ---- unauthenticated and unassigned callers -----------------------------

await test("an unauthenticated caller can read nothing", async () => {
  const db = testEnv.unauthenticatedContext().firestore();
  await assertFails(getDoc(doc(db, "clients/acme")));
  await assertFails(getDoc(doc(db, "clients/acme/scans/scan-1")));
});

await test("a signed-in caller with NO client_id claim can read nothing", async () => {
  // exchangeAuth0Token returns 403 rather than minting such a token, but the
  // rules must not depend on that being the only way in.
  const db = testEnv.authenticatedContext("auth0|orphan").firestore();
  await assertFails(getDoc(doc(db, "clients/acme")));
  await assertFails(getDoc(doc(db, "clients/acme/scans/scan-1")));
});

await test("a forged client_id claim only grants that tenant, not others", async () => {
  const db = asTenant("attacker");
  await assertFails(getDoc(doc(db, "clients/acme/scans/scan-1")));
  await assertFails(getDoc(doc(db, "clients/globex/scans/scan-1")));
});

// ---- writes are Admin-SDK only -----------------------------------------

await test("a tenant CANNOT write its own scan", async () => {
  // All writes come from storeScanResults via the Admin SDK. A client write
  // path would let a tenant forge findings in their own report.
  await assertFails(
    setDoc(doc(asTenant("acme"), "clients/acme/scans/forged"), { findings: [] })
  );
});

await test("a tenant CANNOT write its own client document", async () => {
  await assertFails(setDoc(doc(asTenant("acme"), "clients/acme"), { name: "renamed" }));
});

await test("a tenant CANNOT write into another tenant", async () => {
  await assertFails(
    setDoc(doc(asTenant("acme"), "clients/globex/scans/injected"), { findings: [] })
  );
});

await test("an unauthenticated caller CANNOT write", async () => {
  const db = testEnv.unauthenticatedContext().firestore();
  await assertFails(setDoc(doc(db, "clients/acme/scans/anon"), { findings: [] }));
});

// ---- paths outside the tenant tree --------------------------------------

await test("collections outside clients/ are denied by default", async () => {
  const db = asTenant("acme");
  await assertFails(getDoc(doc(db, "secrets/master")));
  await assertFails(setDoc(doc(db, "secrets/master"), { x: 1 }));
});

await testEnv.cleanup();

const failed = results.filter(([ok]) => !ok);
console.log(`\n${results.length - failed.length} passed, ${failed.length} failed\n`);
process.exit(failed.length ? 1 : 0);
