"""Self-hosted persistence for scan results.

This is the replacement for the Firestore document store, targeting MariaDB on
ICIT NAS-backed infrastructure. See docs/HANDOFF.md for the architectural
direction and for what is VERIFIED, TARGET and UNKNOWN about the target host.

**Nothing here is wired into the workflows and nothing is deployed.** It is
additive: the Firebase path is untouched and remains the live implementation
until a replacement is verified end to end.

Two things are exported:

    schema      the tables, written to be correct on MariaDB specifically
    repository  the ONLY way to read or write them — every entry point takes a
                client_id, because tenant scoping has to be structural rather
                than remembered
"""

from __future__ import annotations

from .repository import ScanRepository, TenantScopeError
from .schema import Client, Finding, Scan, metadata

__all__ = [
    "Client",
    "Finding",
    "Scan",
    "ScanRepository",
    "TenantScopeError",
    "metadata",
]
