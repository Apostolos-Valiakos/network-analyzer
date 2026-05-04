"""
Network Traffic Analysis and PCAP Generation Service
===================================================
Refactored for PostgreSQL Integration & Streaming Analysis.
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime
import csv
import io
import subprocess
import glob
from flask_socketio import SocketIO, emit

from flask import Flask, request, jsonify, send_file, send_from_directory, Response
from flask_cors import CORS
from flasgger import Swagger, swag_from
import pandas as pd
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
import requests
import psycopg2
from psycopg2.extras import execute_values
import socketio

from models import db, PcapFile, FlowStatistic, RoleSnapshot, IpRole, UeSession

from pcap_analysis import initialize_analysis
from ueAnalysis import initialize_analysis_for_ue
from graph_builder import build_graph_json
from role_assessment import analyze_packets_and_assign_roles_optimized
from pcap_generator_service import handle_pcap_chunk
from agglomerative_clustering import (
    analyze_pcap_for_clustering,
    save_results as save_clustering_results,
)
from Preprocess import run_ip_role_pipeline
from connectToWebsocket import startWebSocketClient
from snapshot_scheduler import start_scheduler
import faulthandler
import requests


faulthandler.enable()

UPLOAD_FOLDER = "server/uploads"
PCAP_GEN_OUTPUT_DIR = "server/generated_pcaps"
CLUSTERING_OUTPUT_DIR = "server/cluster_analysis"
RESULTS_OUTPUT_DIR = "server/results"

for d in [
    UPLOAD_FOLDER,
    PCAP_GEN_OUTPUT_DIR,
    CLUSTERING_OUTPUT_DIR,
    RESULTS_OUTPUT_DIR,
]:
    os.makedirs(d, exist_ok=True)

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "super-secret-fallback-key")

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "Network Traffic Analysis API",
        "description": "API documentation for the Network Traffic Analysis and PCAP Generation Service.",
        "version": "1.0.0",
    },
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": 'JWT Authorization header using the Bearer scheme. Example: "Bearer {token}"',
        }
    },
    "security": [{"Bearer": []}],
}

swagger = Swagger(app, template=swagger_template)

jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")
# CORS Setup
CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)

# Database Setup (PostgreSQL)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", "postgresql://postgres:pass@localhost:5432/network_analyzer"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

# Initialize DB Tables
with app.app_context():
    db.create_all()

    # Enable TimescaleDB Hypertable for flow statistics
    try:
        db.session.execute(
            db.text("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;")
        )
        db.session.execute(
            db.text(
                "SELECT create_hypertable('flow_statistics', 'ts', if_not_exists => TRUE);"
            )
        )
        db.session.commit()
        print("TimescaleDB initialized successfully.")
    except Exception as e:
        print(f"TimescaleDB warning (ensure it is installed on PG server): {e}")
        db.session.rollback()

logger = logging.getLogger(__name__)


def generate_csv_response(data_list, filename):
    """Converts a list of dicts to a CSV Flask response."""
    if not data_list:
        return "No data available", 200, {"Content-Type": "text/plain"}

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=data_list[0].keys())
    writer.writeheader()
    writer.writerows(data_list)

    return (
        output.getvalue(),
        200,
        {
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Type": "text/csv",
        },
    )


# ==========================
#      PCAP MANAGEMENT
# ==========================


@app.route("/save-pcap", methods=["POST"])
@swag_from("docs/save_pcap.yml")
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
            )
            db.session.add(pcap_record)

        if is_final:
            pcap_record.status = "COMPLETED"
            if os.path.exists(pcap_record.file_path):
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
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/generated_pcaps/<path:filename>", methods=["GET"])
@swag_from("docs/get_generated_pcap.yml")
def get_generated_pcap(filename: str):
    safe_path = Path(PCAP_GEN_OUTPUT_DIR) / Path(filename).name
    if not safe_path.exists():
        return jsonify({"error": "File not found"}), 404
    return send_file(str(safe_path), as_attachment=True)


# ==========================
#      CORE ANALYSIS
# ==========================


@app.route("/analyze-saved-pcap/<path:filename>", methods=["GET"])
@swag_from("docs/analyze_saved_pcap.yml")
def analyze_saved_pcap(filename: str):
    filepath = Path(PCAP_GEN_OUTPUT_DIR) / Path(filename).name
    if not filepath.exists():
        return jsonify({"error": "File not found"}), 404

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


@app.route("/automated-analysis", methods=["POST"])
@swag_from("docs/automated_analysis.yml")
def automated_analysis():
    if "file" not in request.files:
        return jsonify({"error": "Missing file part"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    unique_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
    pcap_path = Path(PCAP_GEN_OUTPUT_DIR) / unique_name
    file.save(str(pcap_path))

    try:
        pcap_record = PcapFile(
            filename=unique_name,
            original_filename=file.filename,
            file_path=str(pcap_path),
            file_size=os.path.getsize(pcap_path),
            status="PROCESSING",
        )
        db.session.add(pcap_record)
        db.session.commit()

        analysis_result, err = initialize_analysis(str(pcap_path))
        if err:
            raise RuntimeError(f"Analysis failed: {err}")

        model_name = request.form.get("model_name", "rule_based")
        report = run_ip_role_pipeline(str(pcap_path), model_name)

        if report.get("status") != "success":
            raise RuntimeError(f"ML Pipeline failed: {report.get('message')}")

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

        pcap_record.status = "COMPLETED"
        db.session.commit()

        response = {
            "filename": unique_name,
            "json": f"/save_roles?file={unique_name[:-5]}&type=json",
            "csv": f"/save_roles?file={unique_name[:-5]}&type=csv",
            "analysis": {
                "total_packets": analysis_result["total_packets"],
                "graph": build_graph_json(analysis_result["conversations"]),
            },
            "roles": report.get("ip_roles", {}),
        }
        return jsonify(response), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# ==========================
#      CLUSTERING
# ==========================


@app.route("/clustering", methods=["POST"])
@swag_from("docs/clustering.yml")
def clustering_analysis():
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    data = request.get_json()
    filename = data.get("file")

    filepath = Path(PCAP_GEN_OUTPUT_DIR) / Path(filename).name
    if not filepath.exists():
        return jsonify({"error": "PCAP not found"}), 404

    try:
        result = analyze_pcap_for_clustering(
            str(filepath),
            max_clusters=data.get("clusters", 4),
            anomaly_threshold=data.get("anomaly_threshold", 2),
        )
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/suggested_clusters", methods=["GET"])
@swag_from("docs/suggested_clusters.yml")
def suggested_clusters():
    filename = request.args.get("file")
    if not filename:
        return jsonify({"error": "file required"}), 400

    filepath = Path(PCAP_GEN_OUTPUT_DIR) / filename
    if not filepath.exists():
        return jsonify({"error": "File not found"}), 404

    result = analyze_pcap_for_clustering(
        str(filepath), max_clusters=10, anomaly_threshold=2
    )
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


@app.route("/save-results", methods=["POST"])
@swag_from("docs/save_results.yml")
def save_results_endpoint():
    data = request.get_json()
    if not data or not data.get("filename"):
        return jsonify({"error": "Missing filename"}), 400

    try:
        df = pd.DataFrame(data["results"])
        csv_path, json_path = save_clustering_results(
            df, data["filename"], CLUSTERING_OUTPUT_DIR
        )
        target = csv_path if data.get("type", "json") == "csv" else json_path
        name = Path(target).name

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
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/clustering-output/<path:filename>")
@swag_from("docs/get_clustering_result.yml")
def get_clustering_result(filename):
    return send_from_directory(CLUSTERING_OUTPUT_DIR, filename)


@app.route("/run_pipeline", methods=["POST"])
@swag_from("docs/run_pipeline.yml")
def run_pipeline_endpoint():
    data = request.get_json()
    pcap_file = data.get("pcap_file_path")
    model = data.get("model_name")

    full_path = Path(PCAP_GEN_OUTPUT_DIR) / pcap_file
    if not full_path.exists():
        return jsonify({"error": "PCAP not found"}), 404

    try:
        report = run_ip_role_pipeline(str(full_path), model, data.get("selected_ips"))
        status = 200 if report.get("status") == "success" else 500
        return jsonify(report), status
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/save_roles", methods=["GET"])
@swag_from("docs/save_roles.yml")
def save_roles_endpoint():
    file = request.args.get("file")
    ftype = request.args.get("type", "json").lower()

    base = os.path.splitext(file)[0]
    path = Path(RESULTS_OUTPUT_DIR) / f"{base}.{ftype}"

    if not path.exists():
        return jsonify({"error": "File not found"}), 404
    return send_file(str(path), as_attachment=True)


@app.route("/start-analysis-from-websocket", methods=["POST"])
@swag_from("docs/start_analysis_from_websocket.yml")
def start_analysis_from_websocket():
    data = request.json
    ws_url = data.get("ws_url")
    seconds = data.get("seconds")

    if not ws_url or not seconds:
        return jsonify({"status": "Error", "message": "Missing parameters"}), 400

    success = startWebSocketClient(ws_url, int(seconds))
    if success:
        return jsonify({"status": "Accepted", "message": "Pipeline started."}), 202
    return jsonify({"status": "Failed", "message": "Failed to start."}), 500


# ==========================================
# CONTINUOUS MONITORING API ENDPOINTS
# ==========================================

# REMEMBER TO CHANGE THIS TO YOUR VM'S ACTUAL IP ADDRESS
VM_URL = "http://127.0.0.1:5005/get-pcap"
SECRET_TOKEN = "my-super-secret-internal-token-123"


@app.route("/v1/ingest/zeek", methods=["POST"])
@swag_from("docs/ingest_zeek.yml")
def ingest_zeek():
    """Receives JSON flow batches from the VM Zeek Agent."""
    if request.headers.get("X-Internal-Token") != SECRET_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

    flows = request.json.get("flows", [])
    if not flows:
        return jsonify({"status": "empty"}), 200

    ABNORMAL_BYTES_THRESHOLD = 5000000  # 5 MB in a single flow
    ABNORMAL_PKTS_THRESHOLD = 5000  # 5000 packets in a single flow

    conn = None
    try:
        conn = psycopg2.connect(app.config["SQLALCHEMY_DATABASE_URI"])
        cursor = conn.cursor()
        batch = []

        for data in flows:
            raw_ts = data.get("ts")
            # Standardize to UTC for DB storage
            dt_ts = datetime.utcfromtimestamp(raw_ts) if raw_ts else datetime.utcnow()

            orig_bytes = data.get("orig_bytes", 0)
            orig_pkts = data.get("orig_pkts", 0)
            src_ip = data.get("id.orig_h")
            dst_ip = data.get("id.resp_h")
            conn_state = data.get("conn_state")

            if orig_bytes > ABNORMAL_BYTES_THRESHOLD:
                socketio.emit(
                    "network_alert",
                    {
                        "level": "error",
                        "title": "Massive Data Transfer",
                        "message": f"IP {src_ip} sent {(orig_bytes/1024/1024):.2f} MB to {dst_ip}.",
                    },
                )

            elif orig_pkts > ABNORMAL_PKTS_THRESHOLD:
                socketio.emit(
                    "network_alert",
                    {
                        "level": "warning",
                        "title": "Packet Flood Detected",
                        "message": f"IP {src_ip} sent {orig_pkts} packets to {dst_ip}.",
                    },
                )

            elif conn_state == "REJ":
                socketio.emit(
                    "network_alert",
                    {
                        "level": "warning",
                        "title": "Connection Rejected",
                        "message": f"{src_ip} attempted to connect to a closed port on {dst_ip}.",
                    },
                )
            # ------------------------------------

            batch.append(
                (
                    dt_ts,
                    data.get("uid"),
                    src_ip,  # Reusing extracted variable
                    dst_ip,  # Reusing extracted variable
                    data.get("proto"),
                    conn_state,  # Reusing extracted variable
                    orig_bytes,  # Reusing extracted variable
                    data.get("resp_bytes", 0),
                    orig_pkts,  # Reusing extracted variable
                    data.get("resp_pkts", 0),
                )
            )

        insert_query = """
            INSERT INTO flow_statistics 
            (ts, uid, id_orig_h, id_resp_h, proto, conn_state, orig_bytes, resp_bytes, orig_pkts, resp_pkts) 
            VALUES %s ON CONFLICT DO NOTHING;
        """
        # FIXED: Removed duplicate execute_values call
        execute_values(cursor, insert_query, batch)
        conn.commit()

        socketio.emit("new_network_data", flows)

        return jsonify({"status": "success", "inserted": len(batch)}), 200
    except Exception as e:
        print(f"🚨 INGEST ERROR: {str(e)}")
        if conn:
            conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()


@app.route("/v1/network/statistics", methods=["GET"])
@swag_from("docs/get_network_statistics.yml")
def get_network_statistics():
    """Endpoint 1: Get Network Statistics (Grafana/Zeek Aligned)"""
    try:
        raw_start = float(request.args.get("start_time", 0))
        raw_end = float(request.args.get("end_time", datetime.utcnow().timestamp()))
        limit = int(request.args.get("limit", 1000))
        resp_format = request.args.get("format", "csv").lower()

        # FIXED: Query using UTC datetime objects to match the standardized DB storage
        start_dt = datetime.utcfromtimestamp(raw_start)
        end_dt = datetime.utcfromtimestamp(raw_end)

        query = (
            FlowStatistic.query.filter(
                FlowStatistic.ts >= start_dt, FlowStatistic.ts <= end_dt
            )
            .order_by(FlowStatistic.ts.desc())
            .limit(limit)
            .all()
        )

        results = []
        for row in query:
            results.append(
                {
                    "ts": row.ts.timestamp(),  # Convert back to float for ECharts
                    "id.orig_h": row.id_orig_h,
                    "id.resp_h": row.id_resp_h,
                    "proto": row.proto,
                    "conn_state": row.conn_state,
                    "orig_bytes": row.orig_bytes,
                    "resp_bytes": row.resp_bytes,
                    "orig_pkts": row.orig_pkts,
                    "resp_pkts": row.resp_pkts,
                }
            )

        if resp_format == "json":
            return jsonify(results), 200
        return generate_csv_response(results, "network_statistics.csv")

    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/v1/network/roles/latest", methods=["GET"])
@swag_from("docs/get_latest_roles.yml")
def get_latest_roles():
    """Endpoint 2: Get Latest Role Snapshot"""
    try:
        limit = int(request.args.get("limit", 1000))
        resp_format = request.args.get("format", "csv").lower()

        latest_ts = db.session.query(db.func.max(RoleSnapshot.ts)).scalar()

        if not latest_ts:
            return jsonify([]), 200 if resp_format == "json" else ("No data", 200)

        query = RoleSnapshot.query.filter_by(ts=latest_ts).limit(limit).all()

        results = []
        for row in query:
            results.append(
                {
                    "ts": row.ts,
                    "id.orig_h": row.ip_address,
                    "role": row.role,
                    "confidence": row.confidence,
                    "reasoning": row.reasoning,
                }
            )

        if resp_format == "json":
            return jsonify(results), 200
        return generate_csv_response(results, "latest_roles.csv")

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/v1/network/pcap/headers", methods=["GET"])
@swag_from("docs/get_pcap_headers.yml")
def get_pcap_headers_only():
    """Endpoint 3: Get Timeframe PCAP (Headers Only / No Payload)"""
    start_time = request.args.get("start_time")
    end_time = request.args.get("end_time")

    vm_response = requests.get(
        VM_URL,
        params={"start_time": start_time, "end_time": end_time, "headers_only": "true"},
        headers={"X-Internal-Token": SECRET_TOKEN},
        stream=True,
    )

    if vm_response.status_code != 200:
        return jsonify({"error": "Failed to retrieve PCAP from sensor"}), 500

    return Response(
        vm_response.iter_content(chunk_size=1024),
        content_type="application/vnd.tcpdump.pcap",
        headers={
            "Content-Disposition": f"attachment; filename=headers_{int(float(start_time))}.pcap"
        },
    )


@app.route("/v1/network/pcap/latest/full", methods=["GET"])
@swag_from("docs/get_latest_full_pcap.yml")
def get_latest_full_pcap():
    """Endpoint 4: Get Full Payload PCAP (Latest Snapshot)"""
    vm_response = requests.get(
        VM_URL, headers={"X-Internal-Token": SECRET_TOKEN}, stream=True
    )

    if vm_response.status_code != 200:
        return jsonify({"error": "Failed to retrieve PCAP from sensor"}), 500

    return Response(
        vm_response.iter_content(chunk_size=1024),
        content_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": "attachment; filename=latest_full.pcap"},
    )


@app.route("/v1/network/export", methods=["GET"])
@swag_from("docs/export_network_statistics.yml")
def export_network_statistics():
    """Endpoint 5: Export Analytics Data (CSV/JSON) with Zeek dot notation"""
    try:
        raw_start = float(request.args.get("start_time", 0))
        raw_end = float(request.args.get("end_time", datetime.utcnow().timestamp()))
        resp_format = request.args.get("format", "csv").lower()

        # 1. Handle Optional Limit Parameter
        limit_arg = request.args.get("limit")
        limit = int(limit_arg) if limit_arg and limit_arg.strip() else None

        start_dt = datetime.utcfromtimestamp(raw_start)
        end_dt = datetime.utcfromtimestamp(raw_end)

        query = FlowStatistic.query.filter(
            FlowStatistic.ts >= start_dt, FlowStatistic.ts <= end_dt
        ).order_by(FlowStatistic.ts.desc())

        if limit:
            query = query.limit(limit)

        records = query.all()

        # 2. Map to strict Zeek field names
        results = []
        for row in records:
            results.append(
                {
                    "ts": row.ts.timestamp(),
                    "id.orig_h": row.id_orig_h,
                    "id.resp_h": row.id_resp_h,
                    "proto": row.proto,
                    "conn_state": row.conn_state,
                    "orig_bytes": row.orig_bytes,
                    "resp_bytes": row.resp_bytes,
                    "orig_pkts": row.orig_pkts,
                    "resp_pkts": row.resp_pkts,
                    "conversations": f"{row.id_orig_h} <-> {row.id_resp_h}",  # Concatenated IP pair
                }
            )

        filename = f"network_analytics_{int(raw_start)}_{int(raw_end)}"

        # 3. Return JSON Download
        if resp_format == "json":
            return Response(
                json.dumps(results, indent=2),
                mimetype="application/json",
                headers={
                    "Content-Disposition": f"attachment; filename={filename}.json"
                },
            )

        # 4. Return CSV Download (Dictionary keys automatically become dot-notation headers)
        return generate_csv_response(results, f"{filename}.csv")

    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Add glob to your imports at the top of app.py if it isn't there already
import glob


@app.route("/v1/analyze_live", methods=["POST"])
def analyze_live():
    """Auto-grabs the latest PCAP, analyzes it, and deletes it."""
    results_dir = "server/results"

    # Auto-grab the newest PCAP file
    list_of_files = glob.glob(f"{results_dir}/*.pcap")
    if not list_of_files:
        return (
            jsonify(
                {
                    "message": "No PCAP snapshots available. Wait for the scheduler to fetch one."
                }
            ),
            404,
        )

    latest_file = max(list_of_files, key=os.path.getctime)

    try:
        # Run pipeline with an empty list for selected_ips (analyzes all)
        from Preprocess import run_ip_role_pipeline

        model_name = os.path.splitext(os.path.basename(latest_file))[0]

        results = run_ip_role_pipeline(latest_file, model_name, selected_ips=None)

        # Delete the file after the pipeline completes
        if os.path.exists(latest_file):
            os.remove(latest_file)

        return jsonify(results), 200

    except Exception as e:
        import traceback

        traceback.print_exc()
        return jsonify({"message": f"Pipeline error: {str(e)}"}), 500


@app.route("/v1/scan/start", methods=["POST"])
def start_scan():
    data = request.get_json()
    vm_url = "http://127.0.0.1:5005/run-nmap-async"
    headers = {
        "X-Internal-Token": "my-super-secret-internal-token-123",
        "Content-Type": "application/json",
    }

    try:
        response = requests.post(vm_url, json=data, headers=headers, timeout=10)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({"error": f"Failed to reach VM: {str(e)}"}), 500


@app.route("/v1/scan/results", methods=["GET"])
def get_scan_results():
    vm_url = "http://127.0.0.1:5005/get-nmap-results"
    headers = {"X-Internal-Token": "my-super-secret-internal-token-123"}

    try:
        response = requests.get(vm_url, headers=headers, timeout=10)
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({"error": f"Failed to reach VM: {str(e)}"}), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5555"))
    start_scheduler(app)
    # app.run(host="0.0.0.0", debug=True, port=port, use_reloader=False)
    socketio.run(app, host="0.0.0.0", debug=True, port=port, use_reloader=False)
