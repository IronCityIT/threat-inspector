/**
 * Browser tests for the Threat Inspector dashboard.
 *
 * These drive the real page in a real Chromium against a local static server —
 * no Auth0, no Firebase, no network beyond localhost. What they prove is the
 * part that must be right regardless of environment: the UI renders from
 * registry.catalog(), selection maps 1:1 onto the CLI contract, and no
 * underlying tool name reaches the DOM.
 *
 * What they deliberately do NOT prove: real Auth0 sign-in and real tenant
 * isolation against live Firestore. Those need a provisioned Auth0 SPA app and
 * two seeded tenants; the harness for them is icit-e2e-harness. See
 * PRODUCTIZE_NOTES.md.
 */

import { chromium } from "playwright";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const PUBLIC = path.join(ROOT, "dashboard", "public");
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".json": "application/json" };

const TOOL_NAMES = [
  "nessus", "qualys", "nmap", "nuclei", "subfinder",
  "zap", "openvas", "burp", "wazuh", "prowler",
];

function serve() {
  const server = http.createServer((req, res) => {
    const url = req.url.split("?")[0];
    const file = path.join(PUBLIC, url === "/" ? "index.html" : url);
    if (!file.startsWith(PUBLIC) || !fs.existsSync(file)) {
      res.writeHead(404).end("not found");
      return;
    }
    res.writeHead(200, { "Content-Type": TYPES[path.extname(file)] || "text/plain" });
    res.end(fs.readFileSync(file));
  });
  return new Promise((resolve) => server.listen(0, () => resolve(server)));
}

const results = [];
async function test(name, fn) {
  try {
    await fn();
    results.push([true, name]);
    console.log(`  ok   ${name}`);
  } catch (err) {
    results.push([false, name]);
    console.log(`  FAIL ${name}\n       ${err.message}`);
  }
}

const server = await serve();
const base = `http://127.0.0.1:${server.address().port}`;
// Prefer a browser the environment already has: CI images and this build box
// both ship Chrome, and downloading Playwright's own build is not always
// possible offline. CHROME_PATH overrides for anything unusual.
// Build containers commonly run as root, where Chrome's sandbox cannot start.
const SANDBOX_ARGS = ["--no-sandbox", "--disable-dev-shm-usage"];

async function launch() {
  if (process.env.CHROME_PATH) {
    return chromium.launch({ executablePath: process.env.CHROME_PATH, args: SANDBOX_ARGS });
  }
  try {
    return await chromium.launch({ args: SANDBOX_ARGS });
  } catch {
    return chromium.launch({ channel: "chrome", args: SANDBOX_ARGS });
  }
}
const browser = await launch();
const catalog = JSON.parse(fs.readFileSync(path.join(PUBLIC, "catalog.json"), "utf8"));

/** Page with config.js stubbed to configured-looking values. */
async function openConfigured() {
  const page = await browser.newPage();
  await page.route("**/config.js", (route) =>
    route.fulfill({
      contentType: "text/javascript",
      body: `window.ICIT_CONFIG={auth0:{domain:"t.auth0.com",clientId:"abc",audience:""},
             firebase:{apiKey:"k",authDomain:"a",projectId:"p"},
             exchangeUrl:"https://x/exchange",region:"us-east5"};`,
    })
  );
  // Block the SDK CDNs: this suite tests the page, not Auth0's uptime.
  await page.route(/cdn\.jsdelivr\.net|gstatic\.com/, (route) => route.abort());
  await page.goto(base, { waitUntil: "domcontentloaded" });
  // The catalog renders before auth runs, so wait on it being in the DOM rather
  // than on-screen — #app is still hidden at this point.
  await page.waitForSelector("[data-modules] .module", { state: "attached" });

  // Reveal the signed-in view. Real Auth0 sign-in is out of scope here (it needs
  // a provisioned SPA app and seeded tenants); what these tests exercise is the
  // signed-in UI itself, so the gate is opened directly.
  await page.evaluate(() => {
    document.getElementById("unconfigured").hidden = true;
    document.getElementById("gate").hidden = true;
    document.getElementById("app").hidden = false;
  });
  return page;
}

console.log("\ndashboard");

await test("placeholder config shows the not-configured state, not a crash", async () => {
  const page = await browser.newPage();
  await page.goto(base, { waitUntil: "domcontentloaded" });
  await page.waitForSelector("#unconfigured:not([hidden])");
  assert.equal(await page.isVisible("#gate"), false, "sign-in gate must stay hidden");
  await page.close();
});

await test("every catalog module renders as a check", async () => {
  const page = await openConfigured();
  const count = await page.locator("[data-modules] .module").count();
  assert.equal(count, catalog.modules.length);
  await page.close();
});

await test("no underlying tool name reaches the DOM", async () => {
  const page = await openConfigured();
  const text = (await page.locator("body").innerText()).toLowerCase();
  const html = (await page.content()).toLowerCase();
  for (const tool of TOOL_NAMES) {
    assert.ok(!text.includes(tool), `visible text names "${tool}"`);
    // Internal names live in input values; those are not client-visible copy,
    // but a tool name in rendered markup would be.
    assert.ok(!html.includes(`>${tool}`), `markup renders "${tool}"`);
  }
  await page.close();
});

await test("standard preset is selected on load", async () => {
  const page = await openConfigured();
  const pressed = page.locator('[data-groups] .preset[aria-pressed="true"]');
  assert.equal(await pressed.count(), 1);
  assert.equal(await pressed.getAttribute("data-group"), "standard");
  await page.close();
});

await test("preset selection maps 1:1 onto --group", async () => {
  const page = await openConfigured();
  for (const group of catalog.groups) {
    await page.click(`[data-groups] .preset[data-group="${group.name}"]`);
    const args = await page.evaluate(
      ([cat]) => window.__ti.selectionToArgs(document.getElementById("scan-form"), cat),
      [catalog]
    );
    assert.deepEqual(args, { group: group.name }, `preset ${group.name}`);

    const expected = catalog.modules.filter((m) => m.groups.includes(group.name)).length;
    const checked = await page.locator("[data-modules] input:checked").count();
    assert.equal(checked, expected, `preset ${group.name} check count`);
  }
  await page.close();
});

await test("ticking an extra check switches to an explicit --modules list", async () => {
  const page = await openConfigured();
  await page.click('[data-groups] .preset[data-group="quick"]');
  const unchecked = page.locator("[data-modules] input:not(:checked)").first();
  const extra = await unchecked.getAttribute("value");
  await unchecked.check();

  const args = await page.evaluate(
    ([cat]) => window.__ti.selectionToArgs(document.getElementById("scan-form"), cat),
    [catalog]
  );
  assert.ok(args.modules, "expected a modules list, got a group");
  assert.ok(args.modules.split(",").includes(extra), "the ticked module is missing");
  assert.equal(args.group, undefined, "a bespoke selection must not send a group");
  await page.close();
});

await test("every module the UI can send is a real registry module", async () => {
  const page = await openConfigured();
  const values = await page.$$eval("[data-modules] input", (els) => els.map((e) => e.value));
  const known = new Set(catalog.modules.map((m) => m.name));
  for (const v of values) assert.ok(known.has(v), `UI offers unknown module ${v}`);
  await page.close();
});

await test("start is disabled with nothing selected", async () => {
  const page = await openConfigured();
  await page.evaluate(() => {
    document.querySelectorAll("[data-modules] input").forEach((b) => {
      b.checked = false;
    });
    document.querySelector("[data-modules]").dispatchEvent(new Event("change", { bubbles: true }));
  });
  assert.equal(await page.locator("#start").isDisabled(), true);
  await page.close();
});

await test("scan history renders status, counts and an empty state", async () => {
  const page = await openConfigured();
  await page.evaluate(() => {
    window.__ti.renderScans(
      [
        { target: "a.example.com", status: "completed", summary: { total: 3, critical: 1, high: 2 } },
        { target: "b.example.com", status: "failed", summary: {} },
      ],
      document.getElementById("scans"),
      document.getElementById("scans-empty")
    );
  });
  assert.equal(await page.locator("#scans tr").count(), 2);
  assert.equal(await page.locator(".badge-completed").count(), 1);
  assert.equal(await page.locator(".badge-failed").count(), 1);
  assert.equal(await page.locator("#scans-empty").isVisible(), false);

  await page.evaluate(() =>
    window.__ti.renderScans([], document.getElementById("scans"), document.getElementById("scans-empty"))
  );
  assert.equal(await page.locator("#scans-empty").isVisible(), true);
  await page.close();
});

await test("an unknown status cannot inject a class or break the badge", async () => {
  const page = await openConfigured();
  await page.evaluate(() =>
    window.__ti.renderScans(
      [{ target: "x", status: "<script>evil</script>", summary: {} }],
      document.getElementById("scans"),
      document.getElementById("scans-empty")
    )
  );
  assert.equal(await page.locator("#scans .badge-queued").count(), 1, "unknown status must fall back");
  assert.equal(await page.locator("#scans script").count(), 0, "no script injected");
  await page.close();
});

await test("layout holds at mobile width", async () => {
  const page = await openConfigured();
  await page.setViewportSize({ width: 375, height: 720 });
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1
  );
  assert.equal(overflow, false, "page scrolls horizontally at 375px");
  await page.close();
});

await test("every form control is labelled", async () => {
  const page = await openConfigured();
  const unlabelled = await page.$$eval("input[type=text]", (els) =>
    els.filter((e) => !e.labels?.length && !e.getAttribute("aria-label")).length
  );
  assert.equal(unlabelled, 0);
  await page.close();
});

await browser.close();
server.close();

const failed = results.filter(([ok]) => !ok);
console.log(`\n${results.length - failed.length} passed, ${failed.length} failed\n`);
process.exit(failed.length ? 1 : 0);
