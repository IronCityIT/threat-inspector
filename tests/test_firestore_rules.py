"""Invariants of firestore.rules.

firestore.rules is the last line of the tenancy boundary: it decides whether a
signed-in user can read another client's scans. It is also the only part of the
product with NO executable test, because exercising rules for real needs the
Firestore emulator (Java + firebase-tools), which is not available in this
environment — see docs/SDLC_STATUS.md §4.

These are therefore STRUCTURAL assertions over the rules source, not behavioural
ones. They cannot prove the rules are correct. What they can do is fail loudly
if someone weakens them in the ways that matter: opening a write path, adding an
ungated read, or introducing a wildcard match that bypasses the tenant check.
That is worth having even though it is weaker than an emulator run.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

RULES = Path(__file__).resolve().parent.parent / "firestore.rules"


@pytest.fixture(scope="module")
def source() -> str:
    assert RULES.is_file(), "firestore.rules is missing"
    return RULES.read_text()


@pytest.fixture(scope="module")
def code(source: str) -> str:
    """Rules with comments stripped, so prose cannot satisfy an assertion."""
    return re.sub(r"//[^\n]*", "", source)


def allow_statements(code: str) -> list[tuple[str, str]]:
    """Every `allow <ops>: if <condition>;` as (ops, condition)."""
    return [
        (m.group(1).strip(), m.group(2).strip())
        for m in re.finditer(r"allow\s+([\w,\s]+?)\s*:\s*if\s+([^;]+);", code)
    ]


# ---- writes ------------------------------------------------------------


def test_no_rule_grants_client_write_access(code: str):
    """All writes go through the Admin SDK, which bypasses rules entirely.
    A client-side write path would let a tenant forge their own findings."""
    for ops, condition in allow_statements(code):
        if any(op in ops for op in ("write", "create", "update", "delete")):
            assert condition == "false", f"`allow {ops}` is not denied: {condition!r}"


def test_write_denial_is_explicit_at_every_level(code: str):
    """Relying on the default deny is fine until someone adds a broad match."""
    assert code.count("allow write: if false") >= 2, (
        "expected an explicit write denial on both clients/{clientId} and its scans"
    )


# ---- reads -------------------------------------------------------------


def test_every_read_is_gated_on_the_caller_tenant(code: str):
    reads = [(ops, cond) for ops, cond in allow_statements(code) if "read" in ops or "get" in ops]
    assert reads, "no read rules found — did the file change shape?"
    for ops, condition in reads:
        assert "callerClientId()" in condition, f"`allow {ops}` is not tenant-gated: {condition!r}"
        assert "clientId" in condition, f"`allow {ops}` does not compare to the path tenant"


def test_no_read_is_unconditionally_allowed(code: str):
    for ops, condition in allow_statements(code):
        if "read" in ops:
            assert condition.strip() != "true", "a read rule is unconditionally open"


def test_caller_tenant_comes_from_the_verified_token(code: str):
    """`request.auth.token.client_id` is minted by exchangeAuth0Token from a
    signature-verified Auth0 token. Anything else would be caller-controlled."""
    assert "request.auth.token.client_id" in code
    assert "request.auth != null" in code, "callerClientId() must null-check request.auth"


# ---- shape -------------------------------------------------------------


def test_no_recursive_wildcard_match(code: str):
    """`match /{document=**}` under an allow would apply to every collection and
    could silently re-open paths the tenant match is protecting."""
    assert "{document=**}" not in code, "recursive wildcard match present"


def test_rules_target_the_tenant_partitioned_path(code: str):
    assert re.search(r"match\s+/clients/\{clientId\}", code)
    assert re.search(r"match\s+/scans/\{scanId\}", code)


def test_rules_version_is_2(source: str):
    """v1 has different, looser matching semantics for nested paths."""
    assert re.search(r"rules_version\s*=\s*['\"]2['\"]", source)


def test_the_path_matches_what_the_function_writes(code: str):
    """storeScanResults writes clients/{client_id}/scans/{scan_id}. If the rules
    guarded a different path the data would be unreadable, or unguarded."""
    index_js = (RULES.parent / "functions" / "index.js").read_text()
    assert '.collection("clients")' in index_js
    assert '.collection("scans")' in index_js
    assert "match /clients/{clientId}" in code
