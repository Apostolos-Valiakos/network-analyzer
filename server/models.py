from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import uuid

db = SQLAlchemy()


# Times are stored as naive UTC.
def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utc_from_timestamp(ts):
    return datetime.fromtimestamp(ts, timezone.utc).replace(tzinfo=None)


# ==========================================
# CORE & USER MODELS
# ==========================================


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now)

    pcaps = db.relationship("PcapFile", backref="uploader", lazy=True)
    cluster_results = db.relationship("ClusterResult", backref="owner", lazy=True)


class PcapFile(db.Model):
    __tablename__ = "pcap_files"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    filename = db.Column(db.String(255), unique=True, nullable=False)
    original_filename = db.Column(db.String(255), nullable=True)
    file_path = db.Column(db.String(512), nullable=False)
    file_size = db.Column(db.BigInteger)
    upload_time = db.Column(db.DateTime, default=utc_now)
    status = db.Column(db.String(50), default="PENDING")
    source = db.Column(db.String(20), default="upload")  # "upload" or "generated"
    analysis_result = db.Column(db.JSON, nullable=True)

    # Relationships (role cache in role_engine.py, UE sessions)
    roles = db.relationship(
        "IpRole", backref="pcap", lazy=True, cascade="all, delete-orphan"
    )
    ue_sessions = db.relationship(
        "UeSession", backref="pcap", lazy=True, cascade="all, delete-orphan"
    )


# ==========================================
# NEW: CONTINUOUS MONITORING (TIMESCALEDB)
# ==========================================


class FlowStatistic(db.Model):
    """
    Zeek conn.log mapped data.
    Will be converted to a TimescaleDB Hypertable.
    """

    __tablename__ = "flow_statistics"

    # CHANGED: Use DateTime instead of Float for TimescaleDB compatibility
    ts = db.Column(db.DateTime, primary_key=True, nullable=False)
    uid = db.Column(db.String(50), primary_key=True, nullable=False)

    id_orig_h = db.Column(db.String(45), index=True)
    id_resp_h = db.Column(db.String(45), index=True)
    proto = db.Column(db.String(45))  # Protocol (tcp, udp, icmp)
    conn_state = db.Column(db.String(45))  # State (S0, SF, REJ, etc.)

    orig_bytes = db.Column(db.BigInteger, default=0)  # Bytes Out
    resp_bytes = db.Column(db.BigInteger, default=0)  # Bytes In
    orig_pkts = db.Column(db.BigInteger, default=0)  # Packets Out
    resp_pkts = db.Column(db.BigInteger, default=0)  # Packets In


class RoleSnapshot(db.Model):
    """
    Stores the results of the 8-hour periodic snapshot.
    """

    __tablename__ = "role_snapshots"
    id = db.Column(db.Integer, primary_key=True)
    ts = db.Column(
        db.Float, index=True, nullable=False
    )  # Snapshot execution time (Unix Epoch)

    ip_address = db.Column(db.String(45), nullable=False)
    role = db.Column(db.String(100))
    confidence = db.Column(db.Float, default=0.0)
    reasoning = db.Column(db.Text)
    # "pcap": snapshot_scheduler (role engine on the sensor's last slice);
    # "dpi": live_roles (the sensor's live DPI windows).
    source = db.Column(db.String(10), nullable=False, default="pcap", server_default="pcap")


class DpiEvidenceWindow(db.Model):
    """One window of stage-1 role evidence from the sensor's dpi_agent
    (role_evidence.PcapObservations.to_dict()), kept for the retention period."""

    __tablename__ = "dpi_evidence_windows"
    id = db.Column(db.Integer, primary_key=True)
    # Chosen by the agent; a re-sent window is recognised and ignored.
    window_id = db.Column(db.String(64), unique=True, nullable=False)
    window_start = db.Column(db.DateTime, nullable=False)
    window_end = db.Column(db.DateTime, nullable=False, index=True)
    received_at = db.Column(db.DateTime, nullable=False)
    payload = db.Column(db.JSON, nullable=False)


class DpiIdentity(db.Model):
    """An identity an IP stated about itself in live traffic (NRF profile
    type, NG/E2 Setup name, PFCP Node ID). Setup messages are rare, so these
    are kept longer than the rolling evidence window."""

    __tablename__ = "dpi_identities"
    ip = db.Column(db.String(45), primary_key=True)
    kind = db.Column(db.String(20), primary_key=True)
    value = db.Column(db.String(160), primary_key=True)
    first_seen = db.Column(db.DateTime, nullable=False)
    last_seen = db.Column(db.DateTime, nullable=False, index=True)


class PodIpSighting(db.Model):
    """A time span during which a Kubernetes pod owned an IP, from Hubble
    flows (k8s_identity). A new row starts when another pod takes the IP."""

    __tablename__ = "pod_ip_sightings"
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), nullable=False, index=True)
    namespace = db.Column(db.String(253), nullable=False)
    pod = db.Column(db.String(253), nullable=False)
    workload = db.Column(db.String(253))
    workload_kind = db.Column(db.String(64))
    labels = db.Column(db.JSON)
    identity = db.Column(db.Integer)
    node = db.Column(db.String(253))
    source = db.Column(db.String(16), nullable=False, default="hubble", server_default="hubble")
    first_seen = db.Column(db.DateTime, nullable=False)
    last_seen = db.Column(db.DateTime, nullable=False, index=True)


class ServiceIpSighting(db.Model):
    """A time span during which an IP was a Kubernetes Service address."""

    __tablename__ = "service_ip_sightings"
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), nullable=False, index=True)
    namespace = db.Column(db.String(253), nullable=False)
    service = db.Column(db.String(253), nullable=False)
    first_seen = db.Column(db.DateTime, nullable=False)
    last_seen = db.Column(db.DateTime, nullable=False, index=True)


class HubbleFlow(db.Model):
    """Hubble flows counted per minute. Missing pods and ports are stored as
    "" and 0 so the key columns can be unique."""

    __tablename__ = "hubble_flows"
    __table_args__ = (
        db.UniqueConstraint(
            "minute", "src_ip", "dst_ip", "dst_port", "protocol", "verdict", "src_pod", "dst_pod",
            name="uq_hubble_flows_key",
        ),
    )
    id = db.Column(db.Integer, primary_key=True)
    minute = db.Column(db.DateTime, nullable=False, index=True)
    src_ip = db.Column(db.String(45), nullable=False)
    dst_ip = db.Column(db.String(45), nullable=False)
    dst_port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(16), nullable=False)
    verdict = db.Column(db.String(16), nullable=False)
    src_pod = db.Column(db.String(507), nullable=False)  # "namespace/pod" or ""
    dst_pod = db.Column(db.String(507), nullable=False)
    count = db.Column(db.Integer, nullable=False)


# ==========================================
# LEGACY: MANUAL ANALYSIS MODELS
# ==========================================


class IpRole(db.Model):
    """
    Role cache written by role_engine.get_or_compute_roles.
    """

    __tablename__ = "ip_roles"
    id = db.Column(db.Integer, primary_key=True)
    pcap_id = db.Column(db.String(36), db.ForeignKey("pcap_files.id"), nullable=False)

    ip_address = db.Column(db.String(45), nullable=False)
    role = db.Column(db.String(100))
    confidence = db.Column(db.Float, default=0.0)
    reasoning = db.Column(db.Text)
    # Engine version that produced this row; rows from older engines ("" for
    # legacy) are invalidated and re-analyzed on next lookup.
    engine_version = db.Column(
        db.String(20), nullable=False, server_default="", default=""
    )


class UeSession(db.Model):
    """
    Needed for ueAnalysis.py.
    """

    __tablename__ = "ue_sessions"
    id = db.Column(db.Integer, primary_key=True)
    pcap_id = db.Column(db.String(36), db.ForeignKey("pcap_files.id"), nullable=False)

    imsi = db.Column(db.String(50))
    guti = db.Column(db.String(100))
    suci = db.Column(db.String(100))
    ip_address = db.Column(db.String(45))
    details = db.Column(db.JSON)


class ClusterResult(db.Model):
    """Tracks clustering output files so ownership can be enforced."""

    __tablename__ = "cluster_results"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=utc_now)
    result_json = db.Column(db.JSON, nullable=True)
    pcap_id = db.Column(db.String(36), db.ForeignKey("pcap_files.id", ondelete="SET NULL"), nullable=True)
    original_filename = db.Column(db.String(255), nullable=True)
