/**
 * Runtime configuration — REPLACED AT DEPLOY TIME.
 *
 * These are placeholders on purpose. Real values are injected by
 * .github/workflows/deploy-functions.yml from repo secrets, because the Firebase
 * web config and the Auth0 SPA client id are environment facts, not source.
 *
 * The dashboard detects the placeholders and renders an explicit
 * "not configured" state rather than failing with a console error.
 */
window.ICIT_CONFIG = {
  auth0: {
    domain: "__AUTH0_DOMAIN__",
    clientId: "__AUTH0_CLIENT_ID__",
    audience: "__AUTH0_AUDIENCE__",
  },
  firebase: {
    apiKey: "__FIREBASE_API_KEY__",
    authDomain: "__FIREBASE_AUTH_DOMAIN__",
    projectId: "__FIREBASE_PROJECT_ID__",
  },
  // Cloud Function that swaps a verified Auth0 token for a Firebase custom
  // token carrying the client_id claim the Firestore rules gate on.
  exchangeUrl: "__EXCHANGE_URL__",
  region: "us-east5",
};
