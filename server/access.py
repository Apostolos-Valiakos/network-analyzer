"""Who is calling, and may they touch this record?"""
from functools import wraps
from pathlib import Path

from flask import g, jsonify
from flask_jwt_extended import get_jwt_identity, jwt_required

from models import db, PcapFile, User
from settings import PCAP_GEN_OUTPUT_DIR


def current_user_id() -> int:
    return int(get_jwt_identity())


def check_pcap_ownership(filename: str, user_id: int):
    """Returns (pcap, None) or (None, (response, status_code))."""
    safe_name = Path(filename).name
    pcap = PcapFile.query.filter_by(filename=safe_name).first()
    if not pcap:
        return None, (jsonify({"error": "File not found"}), 404)
    if pcap.user_id != user_id:
        return None, (jsonify({"error": "Access denied"}), 403)
    return pcap, None


def owned_pcap(filename, missing_message="File not found"):
    """(pcap, path, None) for the caller's own pcap, else (None, None, error_response)."""
    pcap, err = check_pcap_ownership(filename, current_user_id())
    if err:
        return None, None, err
    path = Path(PCAP_GEN_OUTPUT_DIR) / pcap.filename
    if not path.exists():
        return None, None, (jsonify({"error": missing_message}), 404)
    return pcap, path, None


def is_admin(user_id: int) -> bool:
    u = db.session.get(User, user_id)
    return bool(u and u.is_admin)


def record_for_user(model, record_id):
    """(record, None) if the caller owns it or is an admin, else (None, error_response)."""
    uid = current_user_id()
    record = db.session.get(model, record_id)
    if not record:
        return None, (jsonify({"error": "Not found"}), 404)
    if not is_admin(uid) and record.user_id != uid:
        return None, (jsonify({"error": "Access denied"}), 403)
    return record, None


def admin_required(fn):
    """jwt_required plus an admin check; the admin User is available as g.current_user."""

    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        current = db.session.get(User, current_user_id())
        if not current or not current.is_admin:
            return jsonify({"error": "Admin access required"}), 403
        g.current_user = current
        return fn(*args, **kwargs)

    return wrapper
