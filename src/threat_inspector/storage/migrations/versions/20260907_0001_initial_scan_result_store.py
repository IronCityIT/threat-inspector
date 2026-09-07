"""initial scan result store

Creates the three tables that replace the Firestore document at
`clients/{client_id}/scans/{scan_id}`:

    ti_clients   tenants, keyed on the client_id slug
    ti_scans     one scan run per tenant, unique on (client_id, scan_id)
    ti_findings  one finding per ROW — not packed into a document

Every table is `ti_`-prefixed so this schema can live alongside the legacy
models and alongside ironcity-api's own tables on the shared MariaDB instance
without either being touched. env.py's include_object enforces that.

Revision ID: 0001_initial
Revises:
Created: 2026-09-07
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

# InnoDB for foreign keys and transactions; utf8mb4 because findings carry
# whatever bytes a client's estate emitted, and 3-byte utf8 would reject
# anything outside the BMP. Spelled out on each table rather than unpacked from
# a dict: op.create_table's trailing keyword arguments are typed, and **dict
# defeats that.


def upgrade() -> None:
    op.create_table(
        "ti_clients",
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("client_name", sa.String(length=255), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("client_id"),
        mysql_engine="InnoDB",
        mysql_charset="utf8mb4",
    )

    op.create_table(
        "ti_scans",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("scan_id", sa.String(length=128), nullable=False),
        sa.Column("scan_type", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=512), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("scan_status", sa.String(length=32), nullable=True),
        sa.Column("consensus_status", sa.String(length=32), nullable=True),
        sa.Column("summary", sa.JSON(), nullable=True),
        sa.Column("diagnostics", sa.JSON(), nullable=True),
        sa.Column("error", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["client_id"], ["ti_clients.client_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        # Scan ids are caller-supplied: two tenants choosing the same one must
        # not collide, still less overwrite each other.
        sa.UniqueConstraint("client_id", "scan_id", name="uq_ti_scans_client_scan"),
        # Referenced by ti_findings' composite foreign key below. Without this
        # unique constraint that key cannot exist.
        sa.UniqueConstraint("id", "client_id", name="uq_ti_scans_id_client"),
        mysql_engine="InnoDB",
        mysql_charset="utf8mb4",
    )
    op.create_index("ix_ti_scans_client_created", "ti_scans", ["client_id", "created_at"])

    op.create_table(
        "ti_findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_pk", sa.Integer(), nullable=False),
        sa.Column("client_id", sa.String(length=64), nullable=False),
        sa.Column("module", sa.String(length=64), nullable=True),
        sa.Column("target", sa.String(length=512), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("cve_id", sa.String(length=255), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("asset_ip", sa.String(length=64), nullable=True),
        sa.Column("asset_port", sa.Integer(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.CheckConstraint(
            "severity IN ('critical','high','medium','low','info')",
            name="ck_ti_findings_severity",
        ),
        # The tenancy guarantee, in the database rather than in the code: a
        # finding cannot be attached to a scan belonging to a different tenant.
        sa.ForeignKeyConstraint(
            ["scan_pk", "client_id"],
            ["ti_scans.id", "ti_scans.client_id"],
            name="fk_ti_findings_scan_tenant",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        mysql_engine="InnoDB",
        mysql_charset="utf8mb4",
    )
    op.create_index("ix_ti_findings_client_scan", "ti_findings", ["client_id", "scan_pk"])
    op.create_index("ix_ti_findings_client_severity", "ti_findings", ["client_id", "severity"])


def downgrade() -> None:
    # Dropped children-first so the foreign keys are satisfied at every step.
    op.drop_index("ix_ti_findings_client_severity", table_name="ti_findings")
    op.drop_index("ix_ti_findings_client_scan", table_name="ti_findings")
    op.drop_table("ti_findings")
    op.drop_index("ix_ti_scans_client_created", table_name="ti_scans")
    op.drop_table("ti_scans")
    op.drop_table("ti_clients")
