/**
 * Per-client scan scope for triggerScan (Bill, 2026-09-24: "restrict to client
 * domains"). Kept free of Firebase so it can be unit-tested directly.
 *
 * The allow-list lives on clients/{client_id}.allowed_targets and is maintained by
 * ICIT operators only (firestore.rules deny every client write). Entries are:
 *   - a domain, e.g. "acme.com", which also covers its subdomains ("www.acme.com");
 *   - an IP, e.g. "203.0.113.7";
 *   - a CIDR, e.g. "203.0.113.0/24".
 *
 * A target string may hold several comma-separated tokens (the same grammar as
 * module_framework/targets.py). EVERY token must be in scope, otherwise the whole
 * request is refused. No allow-list means no scans: fail closed.
 */

const net = require("net");

/** Lower-case, trim, and drop one trailing dot so "Acme.COM." equals "acme.com". */
function normHost(value) {
  return String(value || "").trim().toLowerCase().replace(/\.$/, "");
}

/** Parse "a.b.c.d/nn" or "v6::/nn" into {type, first, last}, or null. */
function parseCidr(value) {
  const [addr, bitsRaw] = String(value).split("/");
  const type = net.isIP(addr);
  if (!type || bitsRaw === undefined || !/^\d+$/.test(bitsRaw)) return null;
  const bits = Number(bitsRaw);
  const width = type === 4 ? 32 : 128;
  if (bits > width) return null;
  const n = ipToBigInt(addr, type);
  const hostBits = BigInt(width - bits);
  const mask = ((1n << BigInt(width)) - 1n) ^ ((1n << hostBits) - 1n);
  const first = n & mask;
  const last = first | ((1n << hostBits) - 1n);
  return { type, first, last };
}

function ipToBigInt(addr, type) {
  if (type === 4) {
    return addr.split(".").reduce((acc, octet) => (acc << 8n) | BigInt(Number(octet)), 0n);
  }
  // Expand "::" and any embedded IPv4 tail into 8 groups.
  let [head, tail] = addr.includes("::") ? addr.split("::") : [addr, null];
  const parts = (s) => (s ? s.split(":") : []);
  let groups = parts(head);
  let rest = tail === null ? [] : parts(tail);
  const v4 = (arr) => {
    const lastPart = arr[arr.length - 1];
    if (lastPart && lastPart.includes(".")) {
      const o = lastPart.split(".").map(Number);
      arr.splice(arr.length - 1, 1, ((o[0] << 8) | o[1]).toString(16), ((o[2] << 8) | o[3]).toString(16));
    }
  };
  v4(groups);
  v4(rest);
  if (tail !== null) groups = groups.concat(Array(8 - groups.length - rest.length).fill("0"), rest);
  return groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g || "0", 16)), 0n);
}

/** Classify one allow-list entry; unknown shapes are ignored rather than widening scope. */
function parseEntry(entry) {
  const v = normHost(entry);
  if (!v) return null;
  if (v.includes("/")) {
    const c = parseCidr(v);
    return c ? { kind: "net", ...c } : null;
  }
  const type = net.isIP(v);
  if (type) {
    const n = ipToBigInt(v, type);
    return { kind: "net", type, first: n, last: n };
  }
  // A domain needs at least one dot; bare labels cannot be verified as owned.
  if (v.includes(".") && /^[a-z0-9.-]+$/.test(v)) return { kind: "domain", domain: v };
  return null;
}

/** Turn one target token into {kind:"host", host} or {kind:"net", ...}, or an error string. */
function parseToken(token) {
  const t = token.trim();
  if (t.includes("://")) {
    let host;
    try {
      host = new URL(t).hostname; // userinfo ("acme.com@evil.com") is stripped here
    } catch {
      return `unparseable URL: ${t}`;
    }
    host = normHost(host.replace(/^\[|\]$/g, ""));
    const type = net.isIP(host);
    if (type) {
      const n = ipToBigInt(host, type);
      return { kind: "net", type, first: n, last: n, shown: t };
    }
    return { kind: "host", host, shown: t };
  }
  if (t.includes("/")) {
    const c = parseCidr(t);
    return c ? { kind: "net", ...c, shown: t } : `unparseable network: ${t}`;
  }
  const type = net.isIP(t);
  if (type) {
    const n = ipToBigInt(t, type);
    return { kind: "net", type, first: n, last: n, shown: t };
  }
  return { kind: "host", host: normHost(t), shown: t };
}

function inScope(target, entries) {
  if (target.kind === "host") {
    if (!target.host.includes(".")) return false; // bare hostname: unverifiable
    return entries.some(
      (e) => e.kind === "domain" && (target.host === e.domain || target.host.endsWith("." + e.domain))
    );
  }
  // A network target must sit entirely inside ONE allowed range (ranges are contiguous).
  return entries.some(
    (e) => e.kind === "net" && e.type === target.type && e.first <= target.first && target.last <= e.last
  );
}

/**
 * Returns null when every token of `target` is within `allowedTargets`, otherwise
 * a message safe to show the client.
 */
function targetScopeProblem(target, allowedTargets) {
  const entries = (Array.isArray(allowedTargets) ? allowedTargets : []).map(parseEntry).filter(Boolean);
  if (!entries.length) {
    return "No verified domains are configured for your organisation yet. Contact Iron City IT.";
  }
  const tokens = String(target || "").split(",").map((s) => s.trim()).filter(Boolean);
  if (!tokens.length) return "A target is required.";
  for (const token of tokens) {
    const parsed = parseToken(token);
    if (typeof parsed === "string") return parsed;
    if (!inScope(parsed, entries)) {
      return `${parsed.shown} is not one of your organisation's verified domains or networks.`;
    }
  }
  return null;
}

module.exports = { targetScopeProblem, parseCidr, ipToBigInt };
