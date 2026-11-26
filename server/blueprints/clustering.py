"""Traffic clustering and its saved results."""
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
from flasgger import swag_from
from flask import Blueprint, jsonify, request, send_from_directory
from flask_jwt_extended import jwt_required

from access import current_user_id, is_admin, owned_pcap
from agglomerative_clustering import (
    analyze_pcap_for_clustering,
    save_results as save_clustering_results,
)
from extensions import limiter
from models import db, ClusterResult
from settings import CLUSTERING_OUTPUT_DIR, doc

logger = logging.getLogger(__name__)

bp = Blueprint("clustering", __name__)


@bp.route("/clustering", methods=["POST"])
@jwt_required()
@limiter.limit("10 per minute")
@swag_from(doc("clustering.yml"))
def clustering_analysis():
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    data = request.get_json()
    filename = data.get("file")

    pcap, filepath, err = owned_pcap(filename, missing_message="PCAP not found")
    if err:
        return err

    max_clusters = data.get("clusters", 4)
    if not isinstance(max_clusters, int) or not (2 <= max_clusters <= 20):
        return jsonify({"error": "clusters must be an integer between 2 and 20"}), 400

    anomaly_threshold = data.get("anomaly_threshold", 2)
    if not isinstance(anomaly_threshold, (int, float)) or anomaly_threshold < 0:
        return jsonify({"error": "anomaly_threshold must be a non-negative number"}), 400

    try:
        result = analyze_pcap_for_clustering(
            str(filepath),
            max_clusters=max_clusters,
            anomaly_threshold=anomaly_threshold,
        )

        uid = current_user_id()
        existing = ClusterResult.query.filter_by(pcap_id=pcap.id).first()
        if existing:
            existing.result_json = result
            existing.created_at = datetime.now(timezone.utc)
        else:
            db.session.add(ClusterResult(
                user_id=uid,
                filename=f"cluster_{pcap.id}",
                result_json=result,
                pcap_id=pcap.id,
                original_filename=pcap.original_filename,
            ))
        try:
            db.session.commit()
        except Exception:
            logger.exception("Could not save the clustering result for pcap %s", pcap.id)
            db.session.rollback()
            # The result was computed, so return it, but say it is not in History.
            return jsonify({
                **result,
                "warnings": ["The clustering result could not be saved, so it will not appear in History."],
            }), 200

        return jsonify(result), 200
    except Exception:
        logger.exception("clustering_analysis failed")
        return jsonify({"error": "Internal server error"}), 500


@bp.route("/suggested_clusters", methods=["GET"])
@jwt_required()
@swag_from(doc("suggested_clusters.yml"))
def suggested_clusters():
    filename = request.args.get("file")
    if not filename:
        return jsonify({"error": "file required"}), 400

    pcap, filepath, err = owned_pcap(filename)
    if err:
        return err

    try:
        result = analyze_pcap_for_clustering(
            str(filepath), max_clusters=10, anomaly_threshold=2
        )
    except Exception:
        logger.exception("suggested_clusters: analysis failed for %s", filename)
        return jsonify({"error": "Clustering analysis failed"}), 500

    summary = result["clusterSummary"]
    return jsonify(
        {
            "best_k": summary["best_k"],
            "best_modularity": summary["best_modularity"],
            "modularity_scores": summary["modularity_scores"],
            "cluster_hierarchy": summary["cluster_hierarchy"],
            "mostImportantCluster": summary["mostImportantCluster"],
        }
    )


def _result_base_name(filename):
    """The name to save results under (extension removed), or None when it is
    not a plain file name: a path, "..", or a hidden/empty name would let the
    files land outside CLUSTERING_OUTPUT_DIR."""
    if not isinstance(filename, str) or "/" in filename or "\\" in filename or "\0" in filename:
        return None
    base = os.path.splitext(filename)[0].strip()
    if not base or base.startswith("."):
        return None
    root = os.path.realpath(CLUSTERING_OUTPUT_DIR)
    if os.path.dirname(os.path.realpath(os.path.join(root, base + ".json"))) != root:
        return None
    return base


@bp.route("/save-results", methods=["POST"])
@jwt_required()
@swag_from(doc("save_results.yml"))
def save_results_endpoint():
    data = request.get_json(silent=True)
    if not data or not data.get("filename"):
        return jsonify({"error": "Missing filename"}), 400

    base = _result_base_name(data["filename"])
    if base is None:
        return jsonify({"error": "Invalid filename"}), 400

    uid = current_user_id()
    names = [f"{base}.csv", f"{base}.json"]
    existing = ClusterResult.query.filter(ClusterResult.filename.in_(names)).all()
    if any(r.user_id != uid for r in existing):
        return jsonify({"error": "A result with this name belongs to another user"}), 409

    try:
        df = pd.DataFrame(data["results"])
        csv_path, json_path = save_clustering_results(df, base, CLUSTERING_OUTPUT_DIR)
        target = csv_path if data.get("type", "json") == "csv" else json_path
        name = Path(target).name

        known = {r.filename for r in existing}
        for fname in names:
            if fname not in known:
                db.session.add(ClusterResult(user_id=uid, filename=fname))
        db.session.commit()

        return (
            jsonify(
                {
                    "message": "Saved",
                    "saved_file": name,
                    "download_url": f"/clustering-output/{name}",
                }
            ),
            200,
        )
    except Exception:
        logger.exception("save_results_endpoint failed")
        db.session.rollback()
        return jsonify({"error": "Internal server error"}), 500


@bp.route("/clustering-output/<path:filename>")
@jwt_required()
@swag_from(doc("get_clustering_result.yml"))
def get_clustering_result(filename):
    safe_name = Path(filename).name
    result = ClusterResult.query.filter_by(filename=safe_name).first()
    if not result:
        return jsonify({"error": "File not found"}), 404
    uid = current_user_id()
    if result.user_id != uid and not is_admin(uid):
        return jsonify({"error": "Access denied"}), 403
    return send_from_directory(CLUSTERING_OUTPUT_DIR, safe_name)
