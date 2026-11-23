"""Baseline: the schema as of the move to Alembic.

Must work on any database the old start-up code could have left behind: an empty
one, an up-to-date one, or an older one missing columns. It only ever creates
what is absent, so existing tables and rows are kept.

Table definitions are a frozen copy; later model changes need their own migration.

Revision ID: 0001
Revises:
"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

_metadata = sa.MetaData()

sa.Table(
    "users", _metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("username", sa.String(80), unique=True, nullable=False),
    sa.Column("password_hash", sa.String(256), nullable=False),
    sa.Column("is_admin", sa.Boolean, nullable=False),
    sa.Column("created_at", sa.DateTime),
)
sa.Table(
    "pcap_files", _metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id")),
    sa.Column("filename", sa.String(255), unique=True, nullable=False),
    sa.Column("original_filename", sa.String(255)),
    sa.Column("file_path", sa.String(512), nullable=False),
    sa.Column("file_size", sa.BigInteger),
    sa.Column("upload_time", sa.DateTime),
    sa.Column("status", sa.String(50)),
    sa.Column("source", sa.String(20)),
    sa.Column("analysis_result", sa.JSON),
)
sa.Table(
    "flow_statistics", _metadata,
    sa.Column("ts", sa.DateTime, primary_key=True, nullable=False),
    sa.Column("uid", sa.String(50), primary_key=True, nullable=False),
    sa.Column("id_orig_h", sa.String(45), index=True),
    sa.Column("id_resp_h", sa.String(45), index=True),
    sa.Column("proto", sa.String(45)),
    sa.Column("conn_state", sa.String(45)),
    sa.Column("orig_bytes", sa.BigInteger),
    sa.Column("resp_bytes", sa.BigInteger),
    sa.Column("orig_pkts", sa.BigInteger),
    sa.Column("resp_pkts", sa.BigInteger),
)
sa.Table(
    "role_snapshots", _metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("ts", sa.Float, index=True, nullable=False),
    sa.Column("ip_address", sa.String(45), nullable=False),
    sa.Column("role", sa.String(100)),
    sa.Column("confidence", sa.Float),
    sa.Column("reasoning", sa.Text),
)
sa.Table(
    "ip_roles", _metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("pcap_id", sa.String(36), sa.ForeignKey("pcap_files.id"), nullable=False),
    sa.Column("ip_address", sa.String(45), nullable=False),
    sa.Column("role", sa.String(100)),
    sa.Column("confidence", sa.Float),
    sa.Column("reasoning", sa.Text),
    sa.Column("engine_version", sa.String(20), nullable=False, server_default=""),
)
sa.Table(
    "ue_sessions", _metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("pcap_id", sa.String(36), sa.ForeignKey("pcap_files.id"), nullable=False),
    sa.Column("imsi", sa.String(50)),
    sa.Column("guti", sa.String(100)),
    sa.Column("suci", sa.String(100)),
    sa.Column("ip_address", sa.String(45)),
    sa.Column("details", sa.JSON),
)
sa.Table(
    "cluster_results", _metadata,
    sa.Column("id", sa.Integer, primary_key=True),
    sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
    sa.Column("filename", sa.String(255), unique=True, nullable=False),
    sa.Column("created_at", sa.DateTime),
    sa.Column("result_json", sa.JSON),
    sa.Column("pcap_id", sa.String(36), sa.ForeignKey("pcap_files.id", ondelete="SET NULL")),
    sa.Column("original_filename", sa.String(255)),
)

# Columns added to existing tables over time by the old start-up code.
# (table, column, definition on PostgreSQL, definition elsewhere)
_ADDED_COLUMNS = [
    ("users", "is_admin", "BOOLEAN NOT NULL DEFAULT FALSE", None),
    ("pcap_files", "source", "VARCHAR(20) NOT NULL DEFAULT 'upload'", None),
    ("pcap_files", "analysis_result", "JSONB", "JSON"),
    ("cluster_results", "result_json", "JSONB", "JSON"),
    ("cluster_results", "pcap_id", "VARCHAR(36) REFERENCES pcap_files(id) ON DELETE SET NULL", None),
    ("cluster_results", "original_filename", "VARCHAR(255)", None),
    ("ip_roles", "engine_version", "VARCHAR(20) NOT NULL DEFAULT ''", None),
]


def upgrade():
    bind = op.get_bind()
    _metadata.create_all(bind, checkfirst=True)

    inspector = sa.inspect(bind)
    is_postgres = bind.dialect.name == "postgresql"
    for table, column, pg_definition, other_definition in _ADDED_COLUMNS:
        existing = {c["name"] for c in inspector.get_columns(table)}
        if column not in existing:
            definition = pg_definition if is_postgres else (other_definition or pg_definition)
            op.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    if is_postgres:
        password_hash = next(
            c for c in inspector.get_columns("users") if c["name"] == "password_hash"
        )
        if getattr(password_hash["type"], "length", None) != 256:
            op.execute("ALTER TABLE users ALTER COLUMN password_hash TYPE VARCHAR(256)")


def downgrade():
    raise NotImplementedError("The baseline cannot be undone: it may describe an existing database.")
