"""Privacy records and metrics."""
import logging

from flasgger import swag_from
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from access import owned_pcap
from privacy_metrics import (
    apply_transformations,
    build_privacy_suggestions,
    compute_privacy_metrics,
    compute_utility_metrics,
)
from privacy_records import records_from_pcap
from settings import doc

logger = logging.getLogger(__name__)

bp = Blueprint("privacy", __name__)


@bp.route("/privacy-records/<path:filename>", methods=["GET"])
@jwt_required()
@swag_from(doc("privacy_records.yml"))
def privacy_records_endpoint(filename: str):
    pcap, filepath, err = owned_pcap(filename)
    if err:
        return err
    pilot = request.args.get("pilot", "PUC#1")
    try:
        records = records_from_pcap(str(filepath), pilot=pilot)
    except RuntimeError:
        logger.exception("privacy_records failed")
        return jsonify({"error": "Internal server error"}), 500
    return jsonify({"filename": pcap.filename, "records": records}), 200


@bp.route("/privacy-metrics", methods=["POST"])
@jwt_required()
@swag_from(doc("privacy_metrics.yml"))
def privacy_metrics_endpoint():
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    data = request.get_json()
    records = data.get("records", [])
    identifiers = data.get("identifiers", [])
    sensitive_attribute = data.get("sensitive_attribute")
    transforms = data.get("transformations", {})

    if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
        return jsonify({"error": "records must be a list of objects"}), 400
    if not isinstance(identifiers, list):
        return jsonify({"error": "identifiers must be a list"}), 400

    pseudonymize = transforms.get("pseudonymize", []) or []
    generalize = transforms.get("generalize", []) or []
    suppress = transforms.get("suppress", []) or []
    pseudonymization_mode = transforms.get("pseudonymization_mode", "deterministic")
    pseudonymization_technique = transforms.get(
        "pseudonymization_technique", "hmac_sha256"
    )
    generalize_profiles = transforms.get("generalize_profiles", {}) or {}
    suppress_thresholds = transforms.get("suppress_thresholds", {}) or {}
    try:
        record_suppression_k = int(transforms.get("record_suppression_k", 0) or 0)
    except (TypeError, ValueError):
        return jsonify({"error": "record_suppression_k must be an integer"}), 400

    if not isinstance(generalize_profiles, dict):
        return jsonify({"error": "generalize_profiles must be an object"}), 400
    if not isinstance(suppress_thresholds, dict):
        return jsonify({"error": "suppress_thresholds must be an object"}), 400

    normalized_thresholds = {}
    for key, value in suppress_thresholds.items():
        try:
            normalized_thresholds[key] = int(value)
        except (TypeError, ValueError):
            return jsonify({"error": f"Invalid suppression threshold for '{key}'"}), 400

    if pseudonymization_mode not in ["deterministic", "per_run", "per_pilot"]:
        return jsonify({"error": "Invalid pseudonymization_mode"}), 400
    if pseudonymization_technique not in [
        "hmac_sha256",
        "sha256_salt",
        "random_token",
        "format_preserving_ip",
    ]:
        return jsonify({"error": "Invalid pseudonymization_technique"}), 400

    transformed = apply_transformations(
        records,
        pseudonymize,
        generalize,
        suppress,
        pseudonymization_mode=pseudonymization_mode,
        pseudonymization_technique=pseudonymization_technique,
        generalize_profiles=generalize_profiles,
        suppress_thresholds=normalized_thresholds,
        record_suppression_k=record_suppression_k,
        record_suppression_qi=identifiers,
    )
    metrics = compute_privacy_metrics(transformed, identifiers, sensitive_attribute)
    metrics.update(compute_utility_metrics(records, transformed, identifiers))
    suggestions = build_privacy_suggestions(metrics, identifiers, sensitive_attribute)

    return (
        jsonify(
            {
                "metrics": metrics,
                "records": transformed,
                "applied_transformations": {
                    "pseudonymize": pseudonymize,
                    "pseudonymization_mode": pseudonymization_mode,
                    "pseudonymization_technique": pseudonymization_technique,
                    "generalize": generalize,
                    "suppress": suppress,
                    "generalize_profiles": generalize_profiles,
                    "suppress_thresholds": normalized_thresholds,
                    "record_suppression_k": record_suppression_k,
                },
                "suggestions": suggestions,
            }
        ),
        200,
    )
