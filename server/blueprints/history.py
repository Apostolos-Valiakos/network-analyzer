"""File history: stored results, re-analysis and deletion."""
import logging
import os
from pathlib import Path

from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required

from access import current_user_id, is_admin, record_for_user
from analysis_service import analysis_error_response, run_core_analysis
from extensions import limiter
from models import db, ClusterResult, PcapFile
from packet_table import CACHE_SUFFIX as PACKET_CACHE_SUFFIX
from rrc_utils import FEATURE_CACHE_SUFFIX
from settings import CLUSTERING_OUTPUT_DIR

logger = logging.getLogger(__name__)

bp = Blueprint("history", __name__)


def _pcap_to_dict(r):
    return {
        "id": r.id,
        "filename": r.filename,
        "original_filename": r.original_filename,
        "file_size": r.file_size,
        "upload_time": r.upload_time.isoformat() if r.upload_time else None,
        "status": r.status,
        "source": r.source,
        "has_result": r.analysis_result is not None,
        "username": r.uploader.username if r.uploader else None,
    }


def _cluster_to_dict(r):
    return {
        "id": r.id,
        "filename": r.filename,
        "original_filename": r.original_filename,
        "pcap_id": r.pcap_id,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "has_result": r.result_json is not None,
        "username": r.owner.username if r.owner else None,
    }


def _history_for_source(source):
    uid = current_user_id()
    q = PcapFile.query.filter_by(source=source)
    if not is_admin(uid):
        q = q.filter_by(user_id=uid)
    records = q.order_by(PcapFile.upload_time.desc()).all()
    return jsonify([_pcap_to_dict(r) for r in records])


@bp.route("/v1/history/pcaps", methods=["GET"])
@jwt_required()
def history_pcaps():
    return _history_for_source("upload")


@bp.route("/v1/history/generated", methods=["GET"])
@jwt_required()
def history_generated():
    return _history_for_source("generated")


@bp.route("/v1/history/clusters", methods=["GET"])
@jwt_required()
def history_clusters():
    uid = current_user_id()
    q = ClusterResult.query
    if not is_admin(uid):
        q = q.filter_by(user_id=uid)
    records = q.order_by(ClusterResult.created_at.desc()).all()
    return jsonify([_cluster_to_dict(r) for r in records])


@bp.route("/v1/history/pcap/<pcap_id>/result", methods=["GET"])
@jwt_required()
def get_pcap_history_result(pcap_id):
    record, err = record_for_user(PcapFile, pcap_id)
    if err:
        return err
    if not record.analysis_result:
        return jsonify({"error": "No results stored"}), 404
    return jsonify(record.analysis_result)


@bp.route("/v1/history/cluster/<int:cluster_id>/result", methods=["GET"])
@jwt_required()
def get_cluster_history_result(cluster_id):
    record, err = record_for_user(ClusterResult, cluster_id)
    if err:
        return err
    if not record.result_json:
        return jsonify({"error": "No results stored"}), 404
    return jsonify(record.result_json)


@bp.route("/v1/history/pcap/<pcap_id>/reanalyze", methods=["POST"])
@jwt_required()
@limiter.limit("5 per minute")
def reanalyze_pcap(pcap_id):
    record, err = record_for_user(PcapFile, pcap_id)
    if err:
        return err

    filepath = Path(record.file_path)
    if not filepath.exists():
        return jsonify({"error": "File no longer exists on disk"}), 410

    try:
        stored_result = run_core_analysis(str(filepath), "rule_based", "Role pipeline")
        record.analysis_result = stored_result
        record.status = "COMPLETED"
        db.session.commit()
        return jsonify(stored_result), 200
    except Exception as exc:
        return analysis_error_response(exc, pcap_id, "Analysis failed", "reanalyze_pcap")


@bp.route("/v1/history/pcap/<pcap_id>", methods=["DELETE"])
@jwt_required()
def delete_history_pcap(pcap_id):
    record, err = record_for_user(PcapFile, pcap_id)
    if err:
        return err

    if record.file_path:
        # The caches hold header data from the capture, so they go with it.
        for path in (
            record.file_path,
            record.file_path + PACKET_CACHE_SUFFIX,
            record.file_path + FEATURE_CACHE_SUFFIX,
        ):
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    logger.warning("Could not delete file: %s", path)

    db.session.delete(record)
    db.session.commit()
    return jsonify({"message": "Deleted"}), 200


@bp.route("/v1/history/cluster/<int:cluster_id>", methods=["DELETE"])
@jwt_required()
def delete_history_cluster(cluster_id):
    record, err = record_for_user(ClusterResult, cluster_id)
    if err:
        return err

    output_path = Path(CLUSTERING_OUTPUT_DIR) / record.filename
    if output_path.exists():
        try:
            output_path.unlink()
        except OSError:
            logger.warning("Could not delete cluster file: %s", record.filename)

    db.session.delete(record)
    db.session.commit()
    return jsonify({"message": "Deleted"}), 200
