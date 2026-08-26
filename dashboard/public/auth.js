/**
 * Auth0 sign-in, tenant resolution, and the live scan feed.
 *
 * TENANCY: the browser never chooses its own client_id. Auth0 authenticates the
 * user, the exchange function verifies that token server-side and mints a
 * Firebase custom token carrying the client_id claim, and firestore.rules gates
 * every read on that claim. A tampered client-side value buys nothing — the
 * rules reject the read.
 *
 * Kept separate from app.js so the pure rendering logic stays testable without
 * pulling the SDKs (and the network) into the test.
 */

import { createAuth0Client } from "https://cdn.jsdelivr.net/npm/@auth0/auth0-spa-js@2.1.3/+esm";
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import {
  getAuth,
  signInWithCustomToken,
  signOut,
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";
import {
  getFirestore,
  collection,
  query,
  orderBy,
  limit,
  onSnapshot,
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js";
import {
  getFunctions,
  httpsCallable,
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-functions.js";

import { renderScans, selectionToArgs } from "/app.js";

const $ = (id) => document.getElementById(id);

function showError(message) {
  const el = $("app-error");
  el.textContent = message;
  el.hidden = false;
}

export async function startAuth(config, catalog) {
  const auth0 = await createAuth0Client({
    domain: config.auth0.domain,
    clientId: config.auth0.clientId,
    authorizationParams: {
      redirect_uri: window.location.origin,
      ...(config.auth0.audience ? { audience: config.auth0.audience } : {}),
    },
    cacheLocation: "localstorage",
  });

  // Returning from the Auth0 redirect.
  if (location.search.includes("code=") && location.search.includes("state=")) {
    try {
      await auth0.handleRedirectCallback();
      window.history.replaceState({}, document.title, window.location.pathname);
    } catch (err) {
      console.error(err);
    }
  }

  if (!(await auth0.isAuthenticated())) {
    $("gate").hidden = false;
    $("login").addEventListener("click", () => auth0.loginWithRedirect());
    return;
  }

  const profile = await auth0.getUser();
  const accessToken = await auth0.getTokenSilently();

  let session;
  try {
    session = await exchange(config, accessToken);
  } catch (err) {
    // A user with no tenant is an authorisation problem, not a crash. Say so.
    $("gate").hidden = false;
    const msg = $("gate-error");
    msg.textContent =
      "Your account is not linked to a client organisation. Contact your administrator.";
    msg.hidden = false;
    console.error(err);
    return;
  }

  const app = initializeApp(config.firebase);
  const auth = getAuth(app);
  await signInWithCustomToken(auth, session.firebase_token);

  $("app").hidden = false;
  $("user-email").textContent = profile?.email || "";
  $("client-label").textContent = session.client_name || session.client_id;

  $("logout").addEventListener("click", async () => {
    await signOut(auth);
    auth0.logout({ logoutParams: { returnTo: window.location.origin } });
  });

  subscribeScans(app, session.client_id);
  wireStart(app, catalog);
}

/** Swap a verified Auth0 token for a Firebase custom token. */
async function exchange(config, accessToken) {
  const res = await fetch(config.exchangeUrl, {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`exchange failed: ${res.status}`);
  return res.json();
}

/** Live tenant-scoped feed. The path is the tenant boundary. */
function subscribeScans(app, clientId) {
  const db = getFirestore(app);
  const q = query(
    collection(db, "clients", clientId, "scans"),
    orderBy("created_at", "desc"),
    limit(50)
  );
  onSnapshot(
    q,
    (snap) => renderScans(snap.docs.map((d) => d.data()), $("scans"), $("scans-empty")),
    (err) => {
      showError("Could not load assessment history.");
      console.error(err);
    }
  );
}

function wireStart(app, catalog) {
  const functions = getFunctions(app, window.ICIT_CONFIG.region);
  const triggerScan = httpsCallable(functions, "triggerScan");
  const form = $("scan-form");

  $("start").addEventListener("click", async () => {
    const target = $("target").value.trim();
    if (!target) {
      $("target").focus();
      showError("Enter a target to assess.");
      return;
    }
    $("app-error").hidden = true;
    $("start").disabled = true;
    $("start").textContent = "Starting…";
    try {
      await triggerScan({ workflow: "scan", target, ...selectionToArgs(form, catalog) });
      $("target").value = "";
    } catch (err) {
      showError("The assessment could not be started. Please try again.");
      console.error(err);
    } finally {
      $("start").disabled = false;
      $("start").textContent = "Start assessment";
    }
  });
}
