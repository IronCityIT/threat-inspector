/**
 * Threat Inspector dashboard — application logic.
 *
 * Split out of index.html so it can be unit-tested in a real browser without a
 * network: renderCatalog() and selectionToArgs() are pure, and the Playwright
 * suite in tests/ui drives them directly.
 *
 * WHITE-LABEL: this file renders `label` and `description` from catalog.json and
 * never `name` or `extensions`, which carry the underlying tools' identities.
 */

/* ------------------------------------------------------------------ catalog */

/** Render module checkboxes and group presets. Pure: DOM in, DOM out. */
export function renderCatalog(catalog, root) {
  const groups = root.querySelector("[data-groups]");
  const modules = root.querySelector("[data-modules]");
  groups.innerHTML = "";
  modules.innerHTML = "";

  for (const group of catalog.groups) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "preset";
    btn.dataset.group = group.name;
    btn.textContent = group.label;
    btn.setAttribute("aria-pressed", "false");
    groups.appendChild(btn);
  }

  for (const mod of catalog.modules) {
    const id = `mod-${mod.name}`;
    const row = document.createElement("label");
    row.className = "module";
    row.setAttribute("for", id);

    const box = document.createElement("input");
    box.type = "checkbox";
    box.id = id;
    box.value = mod.name;
    box.dataset.groups = mod.groups.join(",");

    const text = document.createElement("span");
    const name = document.createElement("span");
    name.className = "module-name";
    // label, never mod.name — the internal name identifies the tool.
    name.textContent = mod.label;
    const desc = document.createElement("span");
    desc.className = "module-desc";
    desc.textContent = mod.description;
    text.append(name, desc);

    row.append(box, text);
    modules.appendChild(row);
  }
  return { groups: catalog.groups.length, modules: catalog.modules.length };
}

/** Tick exactly the modules in a group preset. */
export function applyGroup(root, groupName) {
  for (const box of root.querySelectorAll("[data-modules] input[type=checkbox]")) {
    box.checked = box.dataset.groups.split(",").includes(groupName);
  }
  for (const btn of root.querySelectorAll("[data-groups] .preset")) {
    btn.setAttribute("aria-pressed", String(btn.dataset.group === groupName));
  }
}

/**
 * Map UI selection onto the CLI contract. This is the 1:1 guarantee: whatever
 * the boxes say is exactly what --modules receives, and a preset left untouched
 * passes --group instead. Precedence matches registry.select().
 */
export function selectionToArgs(root, catalog) {
  const checked = [...root.querySelectorAll("[data-modules] input:checked")].map((b) => b.value);
  const active = root.querySelector('[data-groups] .preset[aria-pressed="true"]');

  if (active) {
    const members = catalog.modules
      .filter((m) => m.groups.includes(active.dataset.group))
      .map((m) => m.name)
      .sort();
    // Only send `group` if the boxes still match the preset exactly. The moment
    // someone ticks one extra module the selection is bespoke, so send modules.
    if (JSON.stringify(members) === JSON.stringify([...checked].sort())) {
      return { group: active.dataset.group };
    }
  }
  return { modules: checked.join(",") };
}

/* ------------------------------------------------------------------- render */

export function renderScans(scans, tbody, emptyEl) {
  tbody.innerHTML = "";
  emptyEl.hidden = scans.length > 0;
  for (const scan of scans) {
    const tr = document.createElement("tr");
    const sev = scan.summary || {};
    const cells = [
      scan.target || "—",
      statusBadge(scan.status),
      String(sev.total ?? 0),
      String(sev.critical ?? 0),
      String(sev.high ?? 0),
      formatTime(scan.created_at),
    ];
    cells.forEach((value, i) => {
      const td = document.createElement("td");
      if (i === 1) td.appendChild(value);
      else td.textContent = value;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  }
}

function statusBadge(status) {
  const span = document.createElement("span");
  const known = ["queued", "running", "completed", "failed"];
  const value = known.includes(status) ? status : "queued";
  span.className = `badge badge-${value}`;
  span.textContent = value;
  return span;
}

function formatTime(value) {
  if (!value) return "—";
  const ms = value.seconds ? value.seconds * 1000 : Date.parse(value);
  if (Number.isNaN(ms)) return "—";
  return new Date(ms).toLocaleString();
}

/* ------------------------------------------------------------------- config */

/** True when config.js still holds its deploy-time placeholders. */
export function isConfigured(config) {
  if (!config) return false;
  const values = [
    config.auth0?.domain,
    config.auth0?.clientId,
    config.firebase?.apiKey,
    config.firebase?.projectId,
    config.exchangeUrl,
  ];
  return values.every((v) => typeof v === "string" && v && !v.startsWith("__"));
}
