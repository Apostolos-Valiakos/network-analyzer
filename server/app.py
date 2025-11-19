"""
Network Traffic Analysis and PCAP Generation Service
===================================================

This module implements a Flask API server for handling PCAP file uploads,
performing network traffic analysis (conversation statistics, UE session
extraction, IP role assessment, and clustering), and managing the generation
and serving of dynamically created PCAP files.

The API relies on several external analysis modules (pcap_analysis, ueAnalysis,
role_assessment, agglomerative_clustering, etc.) to perform the core functions.

Configuration is managed via environment variables, defaulting to local
server directories for uploads and generated PCAPs.

:copyright: (c) 2025 by University of Thessaly.
:license: MIT License, see LICENSE for more details.
"""

import os
import json
import base64
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from flasgger import Swagger
from scapy.all import wrpcap
from scapy.error import Scapy_Exception
from threading import Lock
import pandas as pd

from pcap_analysis import initialize_analysis
from ueAnalysis import initialize_analysis_for_ue
from graph_builder import build_graph_json
from role_assessment import analyze_packets_and_assign_roles_optimized
from agglomerative_clustering import analyze_pcap, save_results
from Preprocess import run_ip_role_pipeline
from connectToWebsocket import convert_tuple_keys_to_str, startWebSocketClient


app = Flask(__name__)
CORS(app)

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "Network Traffic Analyzer API",
        "description": """
        Comprehensive API for **PCAP upload**, **network analysis**, **UE session extraction**, 
        **IP role classification**, **agglomerative clustering**, and **dynamic PCAP generation**.

        Supports:
        - File upload & analysis
        - Graph generation
        - Clustering with elbow method
        - Rule-based & ML role profiling
        - Streaming PCAP generation
        """,
        "version": "1.0.0",
        "contact": {
            "name": "Apostolos Valiakos",
            "email": "avaliakos@uth.gr"
        }
    },
    "host": "127.0.0.1:5000",
    "basePath": "/",
    "schemes": ["http"],
    "securityDefinitions": {}
}

swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": "apispec_1",
            "route": "/apispec_1.json",
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs/"
}

swagger = Swagger(app, template=swagger_template, config=swagger_config)

CONFIG = {
    "PCAP_OUTPUT_DIR": os.getenv("PCAP_OUTPUT_DIR", "server/generated_pcaps"),
    "MAX_CONTENT_LENGTH": int(os.getenv("MAX_CONTENT_LENGTH", 1024 * 1024 * 1024)),
}

UPLOAD_FOLDER = 'server/uploads'
PCAP_GEN_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "generated_pcaps")
CLUSTERING_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "cluster_analysis")
RESULTS_OUTPUT_DIR = os.path.join(os.getcwd(), "server", "results")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PCAP_GEN_OUTPUT_DIR, exist_ok=True)
os.makedirs(CLUSTERING_OUTPUT_DIR, exist_ok=True)
os.makedirs(RESULTS_OUTPUT_DIR, exist_ok=True)

TEMP_PACKET_BUFFERS: Dict[str, Dict[str, Any]] = {}
buffer_lock = Lock()
logger = logging.getLogger(__name__)


def save_streamed_packets_as_pcap(session_id: str, packets_base64: List[str], is_final_chunk: bool) -> Tuple[bool, str, Optional[str]]:
    """
    Buffer and assemble Base64-encoded packet chunks into a PCAP file.

    :param session_id: Unique session ID
    :param packets_base64: List of Base64 packet strings
    :param is_final_chunk: Whether this is the last chunk
    :return: (success, message, filename)
    """
    try:
        raw_packets = [base64.b64decode(p) for p in packets_base64]

        with buffer_lock:
            if session_id not in TEMP_PACKET_BUFFERS:
                TEMP_PACKET_BUFFERS[session_id] = {'data': [], 'timestamp': datetime.now()}
            TEMP_PACKET_BUFFERS[session_id]['data'].extend(raw_packets)
            TEMP_PACKET_BUFFERS[session_id]['timestamp'] = datetime.now()

        message = f"Chunk received. Buffer size: {len(TEMP_PACKET_BUFFERS[session_id]['data'])} packets."
        filename = None

        if is_final_chunk:
            final_packets = TEMP_PACKET_BUFFERS[session_id]['data']
            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"capture_{timestamp_str}_{session_id[:6]}.pcap"
            filepath = Path(PCAP_GEN_OUTPUT_DIR) / filename
            wrpcap(str(filepath), final_packets)
            message = f"PCAP assembled: {len(final_packets)} packets."

            del TEMP_PACKET_BUFFERS[session_id]

        return True, message, filename

    except Scapy_Exception as e:
        logger.error(f"Scapy error in session {session_id}: {e}")
        if session_id in TEMP_PACKET_BUFFERS:
            del TEMP_PACKET_BUFFERS[session_id]
        return False, f"PCAP assembly failed: {e}", None
    except Exception as e:
        logger.error(f"Error in save_streamed_packets_as_pcap: {e}")
        return False, f"Server error: {e}", None


@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Upload and analyze a PCAP file
    ---
    tags:
      - PCAP Analysis
    consumes:
      - multipart/form-data
    parameters:
      - name: file
        in: formData
        type: file
        required: true
        description: PCAP file to upload and analyze
    responses:
      200:
        description: Analysis completed
        schema:
          type: object
          properties:
            message:
              type: string
            analysis:
              type: object
              properties:
                total_packets:
                  type: integer
                ip_protocols:
                  type: object
                graph:
                  type: object
      400:
        description: Invalid file or format
      500:
        description: Analysis failed
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'No file selected'}), 400
    if not file.filename.lower().endswith('.pcap'):
        return jsonify({'error': 'File must be .pcap'}), 400

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    # UE Session Analysis
    ue_sessions_json = initialize_analysis_for_ue(filepath)
    with open(os.path.join(UPLOAD_FOLDER, 'ue_sessions.json'), 'w') as f:
        json.dump(ue_sessions_json, f, indent=2)

    # General Analysis
    analysis_result, error = initialize_analysis(filepath)
    if error:
        return jsonify({'error': f'Analysis failed: {error}'}), 500

    # Graph
    graph_json = build_graph_json(analysis_result['conversations'])
    with open(os.path.join(UPLOAD_FOLDER, 'conversations.json'), 'w') as f:
        json.dump(graph_json, f, indent=2)

    return jsonify({
        'message': 'Analysis successful',
        'analysis': {
            'total_packets': analysis_result['total_packets'],
            'ip_protocols': analysis_result['ip_protocols'],
            'graph': graph_json
        }
    }), 200


@app.route('/conversations.json')
def get_conversations():
    """
    Get network conversation graph (JSON)
    ---
    tags:
      - PCAP Analysis
    responses:
      200:
        description: Graph JSON
        content:
          application/json:
            schema:
              type: object
      404:
        description: File not found
    """
    return send_from_directory(UPLOAD_FOLDER, 'conversations.json')


@app.route('/ue_sessions')
def get_ue_sessions():
    """
    Get UE session analysis results
    ---
    tags:
      - UE Analysis
    responses:
      200:
        description: UE sessions in JSON
      404:
        description: Not analyzed yet
    """
    return send_from_directory(UPLOAD_FOLDER, 'ue_sessions.json')


@app.route('/role_assessment')
def get_role_assessment_data():
    """
    Run IP role assessment and return results
    ---
    tags:
      - Role Assessment
    responses:
      200:
        description: Role assessment JSON
      404:
        description: Packets not found (run /analyze first)
      500:
        description: IO error
    """
    input_file = os.path.join(UPLOAD_FOLDER, 'all_packets.json')
    output_file = os.path.join(UPLOAD_FOLDER, 'role_assessment.json')

    if not os.path.exists(input_file):
        return jsonify({'error': 'Run /analyze first'}), 404

    roles = analyze_packets_and_assign_roles_optimized(input_file)
    try:
        with open(output_file, 'w') as f:
            json.dump(roles, f, indent=2)
        return send_from_directory(UPLOAD_FOLDER, 'role_assessment.json')
    except Exception as e:
        return jsonify({'error': f'Write failed: {e}'}), 500


@app.route("/save-pcap", methods=["POST"])
def save_pcap_stream():
    """
    Stream Base64 packets and assemble into PCAP (chunked)
    ---
    tags:
      - PCAP Generation
    consumes:
      - application/json
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - session_id
            - packets
          properties:
            session_id:
              type: string
              example: sess_abc123
            packets:
              type: array
              items:
                type: string
              description: Base64-encoded raw packets
            is_final_chunk:
              type: boolean
              default: false
    responses:
      200:
        description: Chunk processed
        schema:
          type: object
          properties:
            success: {type: boolean}
            message: {type: string}
            filename: {type: string, nullable: true}
      400:
        description: Invalid JSON or missing fields
      500:
        description: Assembly error
    """
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    data = request.get_json()
    session_id = data.get("session_id")
    packets = data.get("packets", [])
    is_final = data.get("is_final_chunk", False)

    if not session_id or not isinstance(packets, list):
        return jsonify({"error": "Missing session_id or packets"}), 400

    success, msg, filename = save_streamed_packets_as_pcap(session_id, packets, is_final)
    status = 200 if success else 500
    return jsonify({"success": success, "message": msg, "filename": filename}), status


@app.route("/generated_pcaps/<path:filename>", methods=["GET"])
def get_generated_pcap(filename: str):
    """
    Download a generated PCAP file
    ---
    tags:
      - PCAP Generation
    parameters:
      - name: filename
        in: path
        type: string
        required: true
    responses:
      200:
        description: PCAP file
        content:
          application/vnd.tcpdump.pcap:
            schema:
              type: string
              format: binary
      404:
        description: File not found
    """
    safe_path = Path(PCAP_GEN_OUTPUT_DIR) / Path(filename).name
    if not safe_path.exists():
        return jsonify({"error": "File not found"}), 404
    return send_file(str(safe_path), as_attachment=True)


@app.route('/analyze-saved-pcap/<path:filename>', methods=['GET'])
def analyze_saved_pcap(filename: str):
    """
    Analyze an existing PCAP file from generated_pcaps
    ---
    tags:
      - PCAP Analysis
    parameters:
      - name: filename
        in: path
        type: string
        required: true
    responses:
      200:
        description: Analysis result
      404:
        description: File not found
    """
    filepath = Path(PCAP_GEN_OUTPUT_DIR) / Path(filename).name
    if not filepath.exists():
        return jsonify({'error': 'File not found'}), 404

    result, error = initialize_analysis(str(filepath))
    if error:
        return jsonify({'error': error}), 500

    graph = build_graph_json(result['conversations'])
    return jsonify({
        'message': 'Analysis successful',
        'analysis': {
            'total_packets': result['total_packets'],
            'ip_protocols': result['ip_protocols'],
            'graph': graph
        }
    }), 200


@app.route('/clustering', methods=['POST'])
def clustering_analysis():
    """
    Run agglomerative clustering on a PCAP
    ---
    tags:
      - Clustering
    consumes:
      - application/json
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required: [file]
          properties:
            file:
              type: string
            clusters:
              type: integer
              default: 4
            anomaly_threshold:
              type: number
              default: 2
            distance_threshold:
              type: number
    responses:
      200:
        description: Clustering result
      400:
        description: Invalid input
      404:
        description: PCAP not found
    """
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    data = request.get_json()
    filename = data.get("file")
    if not filename:
        return jsonify({"error": "Missing 'file'"}), 400

    filepath = Path(PCAP_GEN_OUTPUT_DIR) / Path(filename).name
    if not filepath.exists():
        return jsonify({"error": "PCAP not found"}), 404

    try:
        result = analyze_pcap(
            str(filepath),
            n_clusters=data.get("clusters", 4),
            distance_threshold=data.get("distance_threshold"),
            anomaly_threshold=data.get("anomaly_threshold", 2)
        )
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/save-results', methods=['POST'])
def save_results_endpoint():
    """
    Save clustering results as JSON or CSV
    ---
    tags:
      - Clustering
    consumes:
      - application/json
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required: [filename, results]
          properties:
            filename: {type: string}
            results: {type: array, items: {type: object}}
            type: {type: string, enum: [json, csv], default: json}
    responses:
      200:
        description: File saved
        schema:
          type: object
          properties:
            message: {type: string}
            saved_file: {type: string}
            download_url: {type: string}
    """
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    data = request.get_json()
    if not data.get("filename") or "results" not in data:
        return jsonify({"error": "Missing filename or results"}), 400

    try:
        df = pd.DataFrame(data["results"])
    except Exception as e:
        return jsonify({"error": f"Invalid results: {e}"}), 400

    try:
        csv_path, json_path = save_results(df, data["filename"], CLUSTERING_OUTPUT_DIR)
        target = csv_path if data.get("type", "json") == "csv" else json_path
        name = Path(target).name
        return jsonify({
            "message": "Saved",
            "saved_file": name,
            "download_url": f"/clustering-output/{name}"
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/clustering-output/<path:filename>', methods=['GET'])
def get_clustering_result(filename: str):
    """
    Download saved clustering result (JSON/CSV)
    ---
    tags:
      - Clustering
    parameters:
      - name: filename
        in: path
        type: string
        required: true
    responses:
      200:
        description: File download
      404:
        description: Not found
    """
    safe = Path(CLUSTERING_OUTPUT_DIR) / Path(filename).name
    if not safe.exists():
        return jsonify({"error": "File not found"}), 404
    return send_file(str(safe), as_attachment=True)


@app.route('/suggested_clusters', methods=['GET'])
def suggested_clusters():
    """
    Get elbow method cluster suggestion
    ---
    tags:
      - Clustering
    parameters:
      - name: file
        in: query
        type: string
        required: true
    responses:
      200:
        description: Elbow analysis
        schema:
          type: object
          properties:
            wcss_data: {type: array}
            elbow_point: {type: integer}
            cluster_hierarchy: {type: array}
            mostImportantCluster: {type: integer}
    """
    filename = request.args.get("file")
    if not filename:
        return jsonify({"error": "file required"}), 400

    filepath = Path(PCAP_GEN_OUTPUT_DIR) / filename
    if not filepath.exists():
        return jsonify({"error": "File not found"}), 404

    from agglomerative_clustering import (
        extract_features, suggest_clusters_elbow,
        cluster_nodes, compute_cluster_importance
    )

    df = extract_features(str(filepath))
    result = suggest_clusters_elbow(df, max_clusters=10)
    df_clustered = cluster_nodes(df.copy(), n_clusters=result["elbow_point"] or 4)
    hierarchy, most_important = compute_cluster_importance(df_clustered)

    return jsonify({
        "wcss_data": result["wcss_data"],
        "elbow_point": result["elbow_point"],
        "cluster_hierarchy": hierarchy,
        "mostImportantCluster": most_important
    })


@app.route('/run_pipeline', methods=['POST'])
def run_pipeline_endpoint():
    """
    Run ML-based IP role classification pipeline
    ---
    tags:
      - Machine Learning
    consumes:
      - application/json
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required: [pcap_file_path, model_name]
          properties:
            pcap_file_path: {type: string}
            model_name: {type: string}
            selected_ips:
              type: array
              items: {type: string}
    responses:
      200:
        description: Classification result
      400:
        description: Invalid input
      500:
        description: Pipeline error
    """
    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    data = request.get_json()
    pcap_file = data.get('pcap_file_path')
    model = data.get('model_name')
    if not pcap_file or not model:
        return jsonify({"error": "Missing pcap_file_path or model_name"}), 400

    full_path = Path(PCAP_GEN_OUTPUT_DIR) / pcap_file
    if not full_path.exists():
        return jsonify({"error": "PCAP not found"}), 404

    try:
        report = run_ip_role_pipeline(str(full_path), model, data.get('selected_ips'))
        return jsonify(report), 200 if report.get('status') == 'success' else 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/save_roles', methods=['GET'])
def save_roles_endpoint():
    """
    Download IP role classification results
    ---
    tags:
      - Machine Learning
    parameters:
      - name: file
        in: query
        type: string
        required: true
      - name: type
        in: query
        type: string
        enum: [json, csv]
        default: json
    responses:
      200:
        description: Results file
      400:
        description: Invalid parameters
      404:
        description: File not found
    """
    file = request.args.get("file")
    ftype = request.args.get("type", "json").lower()
    if not file:
        return jsonify({"error": "file required"}), 400
    if ftype not in ["json", "csv"]:
        return jsonify({"error": "type must be json or csv"}), 400

    base = os.path.splitext(file)[0]
    path = Path(RESULTS_OUTPUT_DIR) / f"{base}.{ftype}"
    if not path.exists():
        return jsonify({"error": f"{ftype.upper()} not found"}), 404

    return send_file(str(path), as_attachment=True)

@app.route('/automated-analysis', methods=['POST'])
def automated_analysis():
    """
    Fully Automated PCAP Analysis Pipeline
    ---
    tags:
      - Automated Pipeline
    summary: Upload a PCAP and get complete analysis in one call
    description: |
      Saves the PCAP in `generated_pcaps/`, runs:
      - General packet stats & protocol breakdown
      - UE session extraction
      - Network conversation graph
      - Elbow method cluster suggestion
      - Agglomerative clustering (4 clusters, anomaly_threshold=3)
      - ML-based IP role classification (`run_ip_role_pipeline`)
      
      **All steps are executed server-side. No additional frontend calls needed.**

    consumes:
      - multipart/form-data
    produces:
      - application/json

    parameters:
      - name: file
        in: formData
        type: file
        required: true
        description: PCAP file to analyze (.pcap only)
        example: capture.pcap

      - name: model_name
        in: formData
        type: string
        required: false
        default: rule_based
        description: Role classification model
        enum: [rule_based]
        example: rule_based

      - name: selected_ips
        in: formData
        type: string
        required: false
        description: Comma-separated list of IPs to classify (optional)
        example: 192.168.1.10,10.0.0.5

    responses:
      200:
        description: Full analysis results
        content:
          application/json:
            example:
              filename: "a1b2c3d4e5f6_capture.pcap"
              analysis:
                total_packets: 12453
                ip_protocols:
                  "192.168.1.10": ["TCP", "UDP"]
                  "10.0.0.5": ["TCP"]
                graph:
                  nodes:
                    - id: "192.168.1.10"
                      label: "Server"
                  links:
                    - source: "10.0.0.5"
                      target: "192.168.1.10"
                      value: 890
              ue_sessions:
                - ue_ip_addr_ipv4: "10.0.0.5"
                  imsi: "123456789012345"
                  sessions: 12
              roles:
                "192.168.1.10": "Server"
                "10.0.0.5": "Client"
              clustering:
                labels: [0, 0, 1, 2]
                anomalies: [false, false, true]
                centroids:
                  - [0.1, 0.9]
                  - [0.8, 0.2]
              suggested_clusters:
                elbow_point: 4
                wcss_data: [1000, 600, 400, 300, 290]

      400:
        description: Invalid input (missing file, wrong format, etc.)
        content:
          application/json:
            example:
              error: "File must be .pcap"

      500:
        description: Server error during processing
        content:
          application/json:
            example:
              error: "ML pipeline failed: Model not found"

    """
    if 'file' not in request.files:
        return jsonify({'error': 'Missing file part'}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'No file selected'}), 400
    if not file.filename.lower().endswith('.pcap'):
        return jsonify({'error': 'File must be .pcap'}), 400

    unique_name = file.filename
    pcap_path = Path(PCAP_GEN_OUTPUT_DIR) / unique_name
    file.save(str(pcap_path))

    try:
        analysis_result, err = initialize_analysis(str(pcap_path))
        print("Done analysis_result")
        if err:
            raise RuntimeError(f"General analysis failed: {err}")
        # graph_json = build_graph_json(analysis_result['conversations'])

        # ue_sessions = initialize_analysis_for_ue(str(pcap_path))

        # from agglomerative_clustering import extract_features, suggest_clusters_elbow
        # df_features = extract_features(str(pcap_path))
        # elbow_result = suggest_clusters_elbow(df_features, max_clusters=10)
        # print("Done elbow")

        # from agglomerative_clustering import analyze_pcap as run_clustering
        # clustering_result = run_clustering(
        #     str(pcap_path),
        #     n_clusters=4,
        #     anomaly_threshold=3,
        #     distance_threshold=None  # force n_clusters
        # )
        # print("Done clustering")

        model_name = request.form.get('model_name', 'rule_based')
        selected_ips_str = request.form.get('selected_ips', '')
        selected_ips = [ip.strip() for ip in selected_ips_str.split(',') if ip.strip()] if selected_ips_str else None
        name_only = unique_name[:-5]
        report = run_ip_role_pipeline(str(pcap_path), model_name, selected_ips)
        print("Done pipeline")
        if report.get('status') != 'success':
            raise RuntimeError(f"Role pipeline failed: {report.get('message', 'Unknown')}")

        response = {
            "filename": unique_name,
            "json": "http://127.0.0.1:5000/save_roles?file="+name_only+"&type=json",
            "csv": "http://127.0.0.1:5000/save_roles?file="+name_only+"&type=csv",
            "analysis": {
                "total_packets": analysis_result['total_packets'],
                # "ip_protocols": analysis_result['ip_protocols'],
                # "graph": graph_json
            },
            # "ue_sessions": ue_sessions,
            # "clustering": clustering_result,
            # "suggested_clusters": {
            #     "elbow_point": elbow_result.get("elbow_point"),
            #     "wcss_data": elbow_result.get("wcss_data")
            # }
        }

        return jsonify(response), 200

    except Exception as e:
        # Optional: clean up failed file
        if pcap_path.exists():
            pcap_path.unlink(missing_ok=True)
        return jsonify({"error": str(e)}), 500

@app.route('/start-analysis-from-websocket', methods=['POST']) 
def start_analysis_from_websocket():
    """
    Initiate Network Packet Capture and Automated Analysis Pipeline.
    ---
    tags:
      - Automated Pipeline
    summary: Starts a packet capture for a specified duration and runs full analysis on the server.
    description: |
      This endpoint immediately returns a 202 status, indicating that the 
      long-running capture, PCAP generation, and automated analysis 
      pipeline have been successfully started in a background thread.
      
      The client must monitor the WebSocket connection for the final analysis result.
      
    consumes: 
      - application/json 
    parameters: 
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - ws_url
            - seconds # <-- Added required field
          properties:
            ws_url:
              type: string
              example: ws://127.0.0.1:5001
              description: The WebSocket URL (e.g., the sniffer/publisher address) to connect to for packet capture.
            seconds:
              type: integer
              format: int32
              example: 15 # <-- Updated example to 15
              description: The duration in seconds for which packets should be captured. Must be a positive integer.

    responses:
      202:
        description: Pipeline successfully initiated in the background.
        content:
          application/json:
            schema:
              type: object
              properties:
                status:
                  type: string
                  example: Accepted
                message:
                  type: string
                  example: Packet capture and analysis pipeline started in the background.
      400:
        description: Missing required 'ws_url' or invalid 'seconds' in the JSON body.
      500:
        description: Failed to start the background thread.
        content:
          application/json:
            schema:
              type: object
              properties:
                status:
                  type: string
                  example: Failed
                message:
                  type: string
                  example: Failed to initiate pipeline.
    """
    
    data = request.json
    
    if not data:
        return jsonify({"status": "Error", "message": "Missing request body."}), 400
    if 'ws_url' not in data:
        return jsonify({"status": "Error", "message": "Missing 'ws_url' in request body."}), 400
    if 'seconds' not in data:
        return jsonify({"status": "Error", "message": "Missing 'seconds' in request body."}), 400

    ws_url = data['ws_url']
    
    try:
        capture_duration = int(data['seconds'])
        if capture_duration <= 0:
            raise ValueError("Duration must be a positive integer.")
    except ValueError as e:
        return jsonify({"status": "Error", "message": f"Invalid 'seconds' parameter: {e}"}), 400


    # The startWebSocketClient function runs non-blocking code in a daemon thread.
    success = startWebSocketClient(ws_url, capture_duration) # <-- Passed duration
    
    if success:
        return jsonify({
            "status": "Accepted",
            "message": f"Packet capture for {capture_duration} seconds and analysis pipeline started in the background. Results will be logged to the server console."
        }), 202
    else:
        return jsonify({"status": "Failed", "message": "Failed to initiate pipeline."}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)