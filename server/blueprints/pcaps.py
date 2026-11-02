"""Saving, downloading and uploading captures."""
import logging
import os
from datetime import datetime
from pathlib import Path

from flasgger import swag_from
from flask import Blueprint, jsonify, request, send_file
from flask_jwt_extended import jwt_required

from access import current_user_id, owned_pcap
from analysis_service import analysis_error_response, cleanup_packet_caches, run_core_analysis
from extensions import limiter
from graph_builder import build_graph_json
from models import db, PcapFile, UeSession
from pcap_analysis import initialize_analysis
from pcap_generator_service import handle_pcap_chunk
from pcap_repair import trim_incomplete_tail
from privacy_records import records_from_pcap
from settings import PCAP_GEN_OUTPUT_DIR, doc
from ueAnalysis import initialize_analysis_for_ue

logger = logging.getLogger(__name__)

bp = Blueprint("pcaps", __name__)


@bp.route("/save-pcap", methods=["POST"])
@jwt_required()
@limiter.limit("30 per minute")
@swag_from(doc("save_pcap.yml"))
def save_pcap_stream():
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    data = request.get_json()
    session_id = data.get("session_id")
    packets = data.get("packets", [])
    is_final = data.get("is_final_chunk", False)

    if not session_id or not isinstance(packets, list):
        return jsonify({"error": "Missing session_id or packets"}), 400

    success, filename, error = handle_pcap_chunk(session_id, packets, is_final)
    if not success:
        return jsonify({"success": False, "error": error}), 500

    try:
        pcap_record = PcapFile.query.filter_by(original_filename=session_id).first()
        if not pcap_record:
            file_path = os.path.join(PCAP_GEN_OUTPUT_DIR, filename)
            pcap_record = PcapFile(
                filename=filename,
                original_filename=session_id,
                file_path=file_path,
                status="PROCESSING",
                source="generated",
                user_id=current_user_id(),
            )
            db.session.add(pcap_record)

        if is_final:
            pcap_record.status = "COMPLETED"
            if os.path.exists(pcap_record.file_path):
                trim_incomplete_tail(pcap_record.file_path)
                pcap_record.file_size = os.path.getsize(pcap_record.file_path)

        db.session.commit()

        return (
            jsonify(
                {
                    "success": True,
                    "message": "Chunk processed",
                    "filename": filename if is_final else None,
                }
            ),
            200,
        )

    except Exception as e:
        logger.exception("save_pcap_stream failed")
        db.session.rollback()
        return jsonify({"success": False, "error": "Internal server error"}), 500


@bp.route("/generated_pcaps/<path:filename>", methods=["GET"])
@jwt_required()
@swag_from(doc("get_generated_pcap.yml"))
def get_generated_pcap(filename: str):
    pcap, safe_path, err = owned_pcap(filename)
    if err:
        return err
    return send_file(str(safe_path), as_attachment=True)


@bp.route("/analyze-saved-pcap/<path:filename>", methods=["GET"])
@jwt_required()
@swag_from(doc("analyze_saved_pcap.yml"))
def analyze_saved_pcap(filename: str):
    pcap, filepath, err = owned_pcap(filename)
    if err:
        return err

    result, error = initialize_analysis(str(filepath))
    if error:
        return jsonify({"error": error}), 500

    graph = build_graph_json(result["conversations"])

    return (
        jsonify(
            {
                "message": "Analysis successful",
                "analysis": {
                    "total_packets": result["total_packets"],
                    "ip_protocols": result["ip_protocols"],
                    "graph": graph,
                },
            }
        ),
        200,
    )


@bp.route("/automated-analysis", methods=["POST"])
@jwt_required()
@limiter.limit("5 per minute")
@swag_from(doc("automated_analysis.yml"))
def automated_analysis():
    if "file" not in request.files:
        return jsonify({"error": "Missing file part"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    safe_filename = Path(file.filename).name
    if not safe_filename.lower().endswith(".pcap"):
        return jsonify({"error": "Only .pcap files are accepted"}), 400

    cleanup_packet_caches()

    unique_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{safe_filename}"
    pcap_path = Path(PCAP_GEN_OUTPUT_DIR) / unique_name
    file.save(str(pcap_path))
    trim_incomplete_tail(str(pcap_path))

    pcap_id = None
    try:
        pcap_record = PcapFile(
            filename=unique_name,
            original_filename=file.filename,
            file_path=str(pcap_path),
            file_size=os.path.getsize(pcap_path),
            status="PROCESSING",
            source="upload",
            user_id=current_user_id(),
        )
        db.session.add(pcap_record)
        db.session.commit()
        pcap_id = pcap_record.id

        model_name = request.form.get("model_name", "rule_based")
        stored_result = run_core_analysis(str(pcap_path), model_name, "ML Pipeline")

        ue_data = initialize_analysis_for_ue(str(pcap_path))
        if ue_data:
            ue_objects = []
            for ue in ue_data:
                ue_objects.append(
                    UeSession(
                        pcap_id=pcap_record.id,
                        imsi=ue.get("imsi"),
                        guti=ue.get("guti"),
                        ip_address=ue.get("ue_ip_addr_ipv4"),
                        details=ue,
                    )
                )
            db.session.bulk_save_objects(ue_objects)

        try:
            privacy_records = records_from_pcap(str(pcap_path))
        except Exception:
            logger.exception("privacy records failed")
            privacy_records = []

        pcap_record.status = "COMPLETED"
        pcap_record.analysis_result = stored_result
        db.session.commit()

        response = {
            "filename": unique_name,
            "json": f"/save_roles?file={unique_name[:-5]}&type=json",
            "csv": f"/save_roles?file={unique_name[:-5]}&type=csv",
            "analysis": {
                "total_packets": stored_result["total_packets"],
                "graph": stored_result["graph"],
            },
            "roles": stored_result["roles"],
            "privacy_records": privacy_records,
        }
        return jsonify(response), 200

    except Exception as exc:
        return analysis_error_response(exc, pcap_id, "Internal server error", "automated_analysis")
