/**
 * triggerScan — a client may only scan its verified domains and networks.
 *
 * Decided by Bill 2026-09-24. The allow-list is clients/{id}.allowed_targets,
 * operator-maintained (firestore.rules deny client writes). The real triggerScan
 * handler is exercised against an in-memory Firestore stand-in installed before
 * trigger.js loads, and fetch is stubbed, so nothing leaves the process.
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
process.env.GITHUB_DISPATCH_TOKEN = "test-dispatch-token";

const { targetScopeProblem } = require(path.join(ROOT, "functions", "target_scope.js"));

// In-memory Firestore stand-in for trigger.js.
const store = new Map();
const docRef = (p) => ({
  get: async () => ({ exists: store.has(p), get: (f) => (store.get(p) || {})[f] }),
  set: async (v, o) => store.set(p, o && o.merge ? { ...(store.get(p) || {}), ...v } : v),
  collection: (c) => col(`${p}/${c}`),
});
const col = (p) => ({ doc: (id) => docRef(`${p}/${id}`) });
let triggerScan;
try {
  const fsPath = require.resolve(path.join(ROOT, "functions", "node_modules", "firebase-admin", "lib", "firestore", "index.js"));
  const entry = require.resolve("firebase-admin/firestore", { paths: [path.join(ROOT, "functions")] });
  for (const p of new Set([fsPath, entry])) {
    require.cache[p] = { id: p, filename: p, loaded: true,
      exports: { getFirestore: () => ({ collection: col }), FieldValue: { serverTimestamp: () => "ts" } } };
  }
  ({ triggerScan } = require(path.join(ROOT, "functions", "trigger.js")));
} catch (e) {
  if (e.code === "MODULE_NOT_FOUND") {
    console.error("\nFunction dependencies are not installed.\n  cd functions && npm ci\n");
    process.exit(1);
  }
  throw e;
}
let dispatched = 0;
globalThis.fetch = async () => {
  dispatched++;
  return { ok: true, text: async () => "" };
};

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

const ALLOWED = ["acme.com", "203.0.113.0/24", "2001:db8::/32"];
const ok = (t, a = ALLOWED) => assert.equal(targetScopeProblem(t, a), null, t);
const no = (t, a = ALLOWED) => assert.notEqual(targetScopeProblem(t, a), null, t);

console.log("\ntarget scope rules");

await test("no allow-list means no scans (fail closed)", () => {
  for (const a of [undefined, null, [], ["intranet"]]) assert.match(targetScopeProblem("acme.com", a), /No verified domains/);
});
await test("domain covers subdomains; lookalikes and suffix tricks refused", () => {
  ok("acme.com"); ok("WWW.Acme.Com."); no("evil-acme.com"); no("acme.com.evil.com");
});
await test("URLs are judged by their real hostname", () => {
  ok("https://shop.acme.com:8443/x"); no("https://acme.com@evil.com/"); no("https://evil.com/?acme.com");
});
await test("networks must sit inside one allowed range", () => {
  ok("203.0.113.9"); ok("203.0.113.0/25"); no("203.0.112.0/23");
  no("10.0.0.0/22", ["10.0.0.0/24", "10.0.3.0/24"]);
  ok("2001:db8::1"); ok("http://[2001:db8::5]/"); no("2001:db9::1");
});
await test("host tokens must be plain hostnames (parser differential, PR #45 review)", () => {
  // Each ends in ".acme.com" but is not a hostname; built into a URL the first
  // two resolve to evil.com. Refused here rather than relying on targets.py.
  for (const t of [
    "evil.com#.acme.com",
    "evil.com?.acme.com",
    "evil.com\\.acme.com",
    "evil.com .acme.com",
    "evil.com@x.acme.com",
    "evil.com%23.acme.com",
    "evil.com:1.acme.com",
    "acme..com",
  ]) {
    assert.match(targetScopeProblem(t, ["acme.com"]), /not a valid hostname/, t);
  }
  ok("www.acme.com");
});
await test("every comma-separated token must be in scope", () => {
  ok("acme.com, 203.0.113.4"); no("acme.com, evil.com");
});

console.log("\ntriggerScan handler");

store.set("clients/acme", { allowed_targets: ALLOWED });
const call = (client, target, workflow = "scan") =>
  triggerScan.run({ auth: { uid: "u1", token: { client_id: client } }, data: { workflow, target } });

await test("in-scope target is queued and dispatched", async () => {
  const before = store.size, d0 = dispatched;
  const r = await call("acme", "www.acme.com");
  assert.match(r.scan_id, /^ti-acme-/);
  assert.equal(store.size - before, 1);
  assert.equal(dispatched - d0, 1);
});

for (const [client, target, workflow] of [
  ["acme", "evil.com", "scan"],
  ["acme", "https://acme.com@evil.com/", "scan"],
  ["acme", "203.0.112.0/23", "port-scan"],
  ["acme", "evil.com", "asset-discovery"],
  ["other", "acme.com", "scan"],
]) {
  await test(`refused without queueing or dispatch: ${client} → ${target} (${workflow})`, async () => {
    const before = store.size, d0 = dispatched;
    await assert.rejects(call(client, target, workflow), (e) => e.code === "permission-denied");
    assert.equal(store.size - before, 0);
    assert.equal(dispatched - d0, 0);
  });
}

const failed = results.filter(([ok]) => !ok).length;
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
