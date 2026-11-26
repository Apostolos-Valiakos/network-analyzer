"""Live DPI: role_snapshots.source and the tables live_roles writes.

Like the baseline, only creates what is absent: a database made by the old
start-up code from the current models already has all of it.

Revision ID: 0002
Revises: 0001
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())

    if "source" not in {c["name"] for c in inspector.get_columns("role_snapshots")}:
        op.add_column(
            "role_snapshots",
            sa.Column("source", sa.String(10), nullable=False, server_default="pcap"),
        )

    if "dpi_evidence_windows" not in tables:
        op.create_table(
            "dpi_evidence_windows",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("window_id", sa.String(64), unique=True, nullable=False),
            sa.Column("window_start", sa.DateTime, nullable=False),
            sa.Column("window_end", sa.DateTime, nullable=False),
            sa.Column("received_at", sa.DateTime, nullable=False),
            sa.Column("payload", sa.JSON, nullable=False),
        )
        op.create_index(
            "ix_dpi_evidence_windows_window_end", "dpi_evidence_windows", ["window_end"]
        )

    if "dpi_identities" not in tables:
        op.create_table(
            "dpi_identities",
            sa.Column("ip", sa.String(45), primary_key=True),
            sa.Column("kind", sa.String(20), primary_key=True),
            sa.Column("value", sa.String(160), primary_key=True),
            sa.Column("first_seen", sa.DateTime, nullable=False),
            sa.Column("last_seen", sa.DateTime, nullable=False),
        )
        op.create_index("ix_dpi_identities_last_seen", "dpi_identities", ["last_seen"])


def downgrade():
    op.drop_table("dpi_identities")
    op.drop_table("dpi_evidence_windows")
    with op.batch_alter_table("role_snapshots") as batch:
        batch.drop_column("source")
