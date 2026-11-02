"""Role pipeline runs, role downloads and WebSocket captures."""
import logging
import os
from pathlib import Path

from flasgger import swag_from
from flask import Blueprint, jsonify, request, send_file
from flask_jwt_extended import jwt_required

import settings
from access import check_pcap_ownership, current_user_id, owned_pcap
from connectToWebsocket import startWebSocketClient
from extensions import limiter
from Preprocess import run_ip_role_pipeline
from settings import doc

logger = logging.getLogger(__name__)

bp = Blueprint("analysis", __name__)


@bp.route("/run_pipeline", methods=["POST"])
@jwt_required()
@limiter.limit("10 per minute")
@swag_from(doc("run_pipeline.yml"))
def run_pipeline_endpoint():
    data = request.get_json()
    pcap_file = data.get("pcap_file_path")
    model = data.get("model_name")

    pcap, full_path, err = owned_pcap(pcap_file, missing_message="PCAP not found")
    if err:
        return err

    try:
        report = run_ip_role_pipeline(str(full_path), model, data.get("selected_ips"))
        if report.get("status") == "success" and "ip_roles" in report:
            details = report.get("ip_role_details", {})
            report["ip_roles"] = {
                ip: {
                    "role": role,
                    "confidence": details.get(ip, {}).get("confidence", 0.0),
                    "reasoning": details.get(ip, {}).get("reasoning", ""),
                }
                for ip, role in report["ip_roles"].items()
            }
        status = 200 if report.get("status") == "success" else 500
        return jsonify(report), status
    except Exception:
        logger.exception("run_pipeline_endpoint failed")
        return jsonify({"status": "error", "message": "Internal server error"}), 500


@bp.route("/save_roles", methods=["GET"])
@jwt_required()
@swag_from(doc("save_roles.yml"))
def save_roles_endpoint():
    file = request.args.get("file")
    ftype = request.args.get("type", "json").lower()

    if ftype not in ("json", "csv"):
        return jsonify({"error": "type must be json or csv"}), 400

    safe_base = os.path.splitext(Path(file).name)[0]

    _, err = check_pcap_ownership(f"{safe_base}.pcap", current_user_id())
    if err:
        return err

    # Read at call time, like the pipeline worker that writes these files.
    path = Path(settings.RESULTS_OUTPUT_DIR) / f"{safe_base}.{ftype}"
    if not path.exists():
        return jsonify({"error": "File not found"}), 404
    return send_file(str(path), as_attachment=True)


@bp.route("/start-analysis-from-websocket", methods=["POST"])
@jwt_required()
@swag_from(doc("start_analysis_from_websocket.yml"))
def start_analysis_from_websocket():
    data = request.json or {}
    ws_url = data.get("ws_url")
    seconds = data.get("seconds")

    if not ws_url or seconds is None:
        return jsonify({"status": "Error", "message": "Missing parameters"}), 400

    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        return jsonify({"status": "Error", "message": "seconds must be an integer"}), 400

    if not (1 <= seconds <= 3600):
        return jsonify({"status": "Error", "message": "seconds must be between 1 and 3600"}), 400

    success = startWebSocketClient(ws_url, seconds)
    if success:
        return jsonify({"status": "Accepted", "message": "Pipeline started."}), 202
    return jsonify({"status": "Failed", "message": "Failed to start."}), 500
