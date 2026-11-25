"""Hubble: which pod or Service owned an IP when, and flows per minute.

Like the earlier migrations, only creates what is absent.

Revision ID: 0003
Revises: 0002
"""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade():
    tables = set(sa.inspect(op.get_bind()).get_table_names())

    if "pod_ip_sightings" not in tables:
        op.create_table(
            "pod_ip_sightings",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("ip", sa.String(45), nullable=False),
            sa.Column("namespace", sa.String(253), nullable=False),
            sa.Column("pod", sa.String(253), nullable=False),
            sa.Column("workload", sa.String(253)),
            sa.Column("workload_kind", sa.String(64)),
            sa.Column("labels", sa.JSON),
            sa.Column("identity", sa.Integer),
            sa.Column("node", sa.String(253)),
            sa.Column("source", sa.String(16), nullable=False, server_default="hubble"),
            sa.Column("first_seen", sa.DateTime, nullable=False),
            sa.Column("last_seen", sa.DateTime, nullable=False),
        )
        op.create_index("ix_pod_ip_sightings_ip", "pod_ip_sightings", ["ip"])
        op.create_index("ix_pod_ip_sightings_last_seen", "pod_ip_sightings", ["last_seen"])

    if "service_ip_sightings" not in tables:
        op.create_table(
            "service_ip_sightings",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("ip", sa.String(45), nullable=False),
            sa.Column("namespace", sa.String(253), nullable=False),
            sa.Column("service", sa.String(253), nullable=False),
            sa.Column("first_seen", sa.DateTime, nullable=False),
            sa.Column("last_seen", sa.DateTime, nullable=False),
        )
        op.create_index("ix_service_ip_sightings_ip", "service_ip_sightings", ["ip"])
        op.create_index("ix_service_ip_sightings_last_seen", "service_ip_sightings", ["last_seen"])

    if "hubble_flows" not in tables:
        op.create_table(
            "hubble_flows",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("minute", sa.DateTime, nullable=False),
            sa.Column("src_ip", sa.String(45), nullable=False),
            sa.Column("dst_ip", sa.String(45), nullable=False),
            sa.Column("dst_port", sa.Integer, nullable=False),
            sa.Column("protocol", sa.String(16), nullable=False),
            sa.Column("verdict", sa.String(16), nullable=False),
            sa.Column("src_pod", sa.String(507), nullable=False),
            sa.Column("dst_pod", sa.String(507), nullable=False),
            sa.Column("count", sa.Integer, nullable=False),
            sa.UniqueConstraint(
                "minute", "src_ip", "dst_ip", "dst_port", "protocol", "verdict",
                "src_pod", "dst_pod", name="uq_hubble_flows_key",
            ),
        )
        op.create_index("ix_hubble_flows_minute", "hubble_flows", ["minute"])


def downgrade():
    op.drop_table("hubble_flows")
    op.drop_table("service_ip_sightings")
    op.drop_table("pod_ip_sightings")
