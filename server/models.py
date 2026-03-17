from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid

db = SQLAlchemy()

# ==========================================
# CORE & USER MODELS
# ==========================================


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship: One user can upload many files
    pcaps = db.relationship("PcapFile", backref="uploader", lazy=True)


class PcapFile(db.Model):
    __tablename__ = "pcap_files"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    filename = db.Column(db.String(255), unique=True, nullable=False)
    original_filename = db.Column(db.String(255), nullable=True)
    file_path = db.Column(db.String(512), nullable=False)
    file_size = db.Column(db.BigInteger)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default="PENDING")

    # Relationships (Needed for rrc_utils.py and ueAnalysis.py)
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
    proto = db.Column(db.String(10))  # Protocol (tcp, udp, icmp)
    conn_state = db.Column(db.String(15))  # State (S0, SF, REJ, etc.)

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


# ==========================================
# LEGACY: MANUAL ANALYSIS MODELS
# ==========================================


class IpRole(db.Model):
    """
    Needed for rrc_utils.py caching.
    """

    __tablename__ = "ip_roles"
    id = db.Column(db.Integer, primary_key=True)
    pcap_id = db.Column(db.String(36), db.ForeignKey("pcap_files.id"), nullable=False)

    ip_address = db.Column(db.String(45), nullable=False)
    role = db.Column(db.String(100))
    confidence = db.Column(db.Float, default=0.0)
    reasoning = db.Column(db.Text)


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
