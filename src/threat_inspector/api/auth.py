"""
auth.py — who is calling, and which tenant they are allowed to see.

The API is multi-tenant: `_inspectors` holds one uploaded scan set per
client_id. Before this module existed the client_id arrived as a plain query
parameter with no credential anywhere in the request, so the isolation was
self-asserted. Demonstrated against the running app:

    POST /api/v1/scans/upload?client_id=acme     -> 8 vulnerabilities stored
    GET  /api/v1/vulnerabilities?client_id=acme  -> 200, all 8 returned

...with no token, header or session at any point. Any caller who knew (or
guessed) a client_id read that client's uploaded scan data.

The fix is the same property exchangeAuth0Token enforces on the Firestore side:
**the tenant is derived from the caller's credential, never from the request.**
A token maps to exactly one client_id. A request that also names a client_id
must name its own, or it is refused — so a stolen or shared token still cannot
reach across tenants.

Configuration (operator-supplied, never committed):

    TI_API_TOKENS='<token>:<client_id>,<token>:<client_id>'
    TI_API_TOKENS='{"<token>": "<client_id>"}'      # JSON also accepted

Secure by default: with nothing configured the API refuses to serve tenant data
at all. `TI_ALLOW_UNAUTHENTICATED=true` re-opens it for local development and
says so loudly in the logs — it must never be set on anything reachable.
"""

from __future__ import annotations

import hmac
import json
import logging
import os

from fastapi import Header, HTTPException, Query

log = logging.getLogger("threat_inspector.api.auth")

ENV_TOKENS = "TI_API_TOKENS"
ENV_ALLOW_ANON = "TI_ALLOW_UNAUTHENTICATED"

# Used as the tenant for every caller when authentication is switched off, so a
# dev instance still exercises the tenant-scoped code paths.
ANONYMOUS_CLIENT = "local-dev"


def _parse_tokens(raw: str) -> dict[str, str]:
    """token -> client_id. Accepts JSON or `token:client,token:client`."""
    raw = (raw or "").strip()
    if not raw:
        return {}
    if raw.startswith("{"):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            log.error("%s is not valid JSON — no tokens loaded", ENV_TOKENS)
            return {}
        return {str(k): str(v) for k, v in parsed.items() if k and v}

    tokens: dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        token, _, client = pair.partition(":")
        token, client = token.strip(), client.strip()
        if token and client:
            tokens[token] = client
    return tokens


def configured_tokens() -> dict[str, str]:
    """Read the token table fresh each call so tests and reloads see changes."""
    return _parse_tokens(os.environ.get(ENV_TOKENS, ""))


def anonymous_allowed() -> bool:
    return os.environ.get(ENV_ALLOW_ANON, "").lower() == "true"


def _match(presented: str, tokens: dict[str, str]) -> str | None:
    """Constant-time lookup of a presented token.

    Every configured token is compared, and the comparison itself is
    constant-time, so neither the match position nor the shared prefix length
    is observable through response timing.
    """
    found: str | None = None
    for token, client in tokens.items():
        if hmac.compare_digest(presented, token):
            found = client
    return found


def resolve_tenant(authorization: str | None, requested_client_id: str | None) -> str:
    """Return the client_id this caller may act on, or raise HTTPException.

    Pure with respect to the request: it takes the header and the (optional)
    requested id and nothing else, so it can be tested directly.
    """
    tokens = configured_tokens()

    if not tokens:
        if anonymous_allowed():
            log.error(
                "%s is not set and %s=true — the API is serving tenant data with NO "
                "authentication. This must never be set on a reachable instance.",
                ENV_TOKENS,
                ENV_ALLOW_ANON,
            )
            return (requested_client_id or ANONYMOUS_CLIENT).strip() or ANONYMOUS_CLIENT
        log.error("%s is not configured — refusing to serve tenant data", ENV_TOKENS)
        raise HTTPException(
            status_code=503,
            detail=(
                "api_not_configured: set TI_API_TOKENS to '<token>:<client_id>' pairs, "
                "or TI_ALLOW_UNAUTHENTICATED=true for local development only"
            ),
        )

    header = (authorization or "").strip()
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer" or not presented.strip():
        raise HTTPException(status_code=401, detail="missing_bearer_token")

    client_id = _match(presented.strip(), tokens)
    if client_id is None:
        log.warning("rejected an API call with an unrecognised token")
        raise HTTPException(status_code=401, detail="invalid_token")

    # A token names its tenant. Asking for a different one is a cross-tenant
    # attempt, and is refused rather than quietly served the caller's own data.
    if requested_client_id and requested_client_id.strip() != client_id:
        log.warning(
            "tenant mismatch: token for %r requested %r", client_id, requested_client_id.strip()
        )
        raise HTTPException(status_code=403, detail="client_id does not match the presented token")

    return client_id


async def current_tenant(
    authorization: str | None = Header(None),
    client_id: str | None = Query(
        None, description="Optional. Must match the tenant your token belongs to."
    ),
) -> str:
    """FastAPI dependency: the authorised tenant for this request."""
    return resolve_tenant(authorization, client_id)
