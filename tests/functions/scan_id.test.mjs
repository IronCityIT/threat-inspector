/**
 * storeScanResults — scan_id validation.
 *
 * scan_id is used verbatim as a Firestore document id under
 * clients/{client_id}/scans/. Only emptiness used to be checked, so an id
 * Firestore rejects ("a/b", "..", "__x__") made doc() throw and the caller got
 * 500 store_failed for what is a bad request. "x/sub/y" was worse: it is a
 * valid nested path, so the write succeeded somewhere other than scans/{id}.
 *
 * The handler cases stop at validation, so nothing here talks to Firestore.
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

let index;
try {
  index = require(path.join(ROOT, "functions", "index.js"));
} catch (e) {
  if (e.code === "MODULE_NOT_FOUND") {
    console.error("\nFunction dependencies are not installed.\n  cd functions && npm ci\n");
    process.exit(1);
  }
  throw e;
}
const { scanIdProblem } = index._internal;
const { MAX_ID_BYTES } = require(path.join(ROOT, "functions", "scan_id.js"));

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

/** POST to the real handler; returns { status, body }. */
async function post(body) {
  process.env.ALLOW_UNAUTHENTICATED_INGEST = "true";
  const out = {};
  const res = {
    status(code) {
      out.status = code;
      return this;
    },
    json(payload) {
      out.body = payload;
      return this;
    },
    set() {
      return this;
    },
    setHeader() {},
    getHeader() {},
    on() {},
  };
  const req = { method: "POST", body, headers: {}, get: () => undefined, header: () => undefined };
  try {
    await index.storeScanResults(req, res);
  } finally {
    delete process.env.ALLOW_UNAUTHENTICATED_INGEST;
  }
  return out;
}

console.log("\nstoreScanResults scan_id");

await test("accepts the ids the workflows and triggerScan mint", () => {
  for (const id of ["ti-acme-1727200000000", "ti-12345678901", "scan_2026-09-24.1", "Ünïcode-id"]) {
    assert.equal(scanIdProblem(id), null, id);
  }
});

await test("rejects an empty id", () => {
  assert.equal(scanIdProblem(""), "scan_id is required");
});

await test("rejects ids Firestore cannot use as a document id", () => {
  for (const id of ["a/b", "x/sub/y", "../x", ".", "..", "__name__", "__x__"]) {
    assert.notEqual(scanIdProblem(id), null, id);
  }
});

await test("the 1500-byte limit is counted in bytes, not characters", () => {
  assert.equal(scanIdProblem("a".repeat(MAX_ID_BYTES)), null);
  assert.notEqual(scanIdProblem("a".repeat(MAX_ID_BYTES + 1)), null);
  assert.notEqual(scanIdProblem("é".repeat(751)), null); // 751 chars, 1502 bytes
});

await test("underscores that do not wrap the whole id are allowed", () => {
  assert.equal(scanIdProblem("__not_reserved"), null);
  assert.equal(scanIdProblem("a__b__"), null);
});

for (const id of ["a/b", "x/sub/y", "..", "__x__"]) {
  await test(`the handler answers 400, not 500, for scan_id ${JSON.stringify(id)}`, async () => {
    const { status, body } = await post({ client_name: "acme", scan_id: id });
    assert.equal(status, 400);
    assert.match(body.error, /^scan_id /);
  });
}

await test("the handler still answers 400 for a missing scan_id", async () => {
  const { status, body } = await post({ client_name: "acme" });
  assert.equal(status, 400);
  assert.equal(body.error, "scan_id is required");
});

const failed = results.filter(([ok]) => !ok);
console.log(`\n${results.length - failed.length} passed, ${failed.length} failed\n`);
process.exit(failed.length ? 1 : 0);
