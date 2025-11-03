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

:copyright: (c) 2024 by Example Corporation.
:license: MIT License, see LICENSE for more details.
"""

import os
import json
from pcap_analysis import initialize_analysis
from flask import send_from_directory
from graph_builder import build_graph_json
from ueAnalysis import initialize_analysis_for_ue
from role_assessment import analyze_packets_and_assign_roles_optimized
from pcap_generator_service import save_pcap_data
from agglomerative_clustering import analyze_pcap, save_results
from Preprocess import run_ip_role_pipeline
import base64
import time
import logging
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from scapy.error import Scapy_Exception
from scapy.all import wrpcap
from threading import Lock
from typing import List, Dict, Any, Tuple, Optional


# --- FLASK SETUP & CONFIGURATION ---

app = Flask(__name__)
CORS(app)

CONFIG = {
    "PCAP_OUTPUT_DIR": os.getenv("PCAP_OUTPUT_DIR", "server\\generated_pcaps"),
    "MAX_CONTENT_LENGTH": int(os.getenv("MAX_CONTENT_LENGTH", 1024 * 1024 * 1024)),
    "ALLOWED_ORIGINS": os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(","),
}

#: Temporary buffer for storing packet chunks during streaming PCAP generation.
TEMP_PACKET_BUFFERS: Dict[str, Dict[str, Any]] = {}
buffer_lock = Lock()
logger = logging.getLogger(__name__)

# Directory setup
UPLOAD_FOLDER = 'server/uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
PCAP_GEN_OUTPUT_DIR = os.getenv('PCAP_OUTPUT_DIR', 'server\\generated_pcaps')
os.makedirs(PCAP_GEN_OUTPUT_DIR, exist_ok=True)

CLUSTERING_OUTPUT_DIR = os.getenv('CLUSTERING_OUTPUT_DIR', 'server\\cluster_analysis')
os.makedirs(CLUSTERING_OUTPUT_DIR, exist_ok=True)


# --- UTILITY FUNCTIONS ---

def save_streamed_packets_as_pcap(session_id: str, packets_base64: List[str], is_final_chunk: bool) -> Tuple[bool, str, Optional[str]]:
    """
    Handles chunked upload: buffers Base64 encoded packets until the final chunk, 
    then decodes and assembles them into a PCAP file using Scapy's wrpcap.

    :param session_id: Unique identifier for the current PCAP generation session.
    :type session_id: str
    :param packets_base64: List of Base64 encoded packet strings for the current chunk.
    :type packets_base64: List[str]
    :param is_final_chunk: True if this is the last chunk of the session.
    :type is_final_chunk: bool
    :raises Scapy_Exception: If Scapy encounters an error during PCAP assembly.
    :return: A tuple containing (success: bool, message: str, filename: str | None).
    :rtype: Tuple[bool, str, Optional[str]]
    """
    try:
        # Decode and store raw packet bytes in the session buffer
        raw_packets = []
        for b64_packet in packets_base64:
            raw_packets.append(base64.b64decode(b64_packet))
            
        with buffer_lock:
            if session_id not in TEMP_PACKET_BUFFERS:
                TEMP_PACKET_BUFFERS[session_id] = {
                    'data': [],
                    'timestamp': datetime.now()
                }
            
            # Append this chunk's raw packets to the session buffer
            TEMP_PACKET_BUFFERS[session_id]['data'].extend(raw_packets)
            TEMP_PACKET_BUFFERS[session_id]['timestamp'] = datetime.now() # Update timestamp

        message = f"Chunk received. Current buffer size: {len(TEMP_PACKET_BUFFERS[session_id]['data'])} packets."
        filename = None
        
        if is_final_chunk:
            # --- Final assembly ---
            final_packets = TEMP_PACKET_BUFFERS[session_id]['data']
            logger.info(f"Final chunk received. Assembling PCAP for session {session_id} with {len(final_packets)} packets.")
            
            # Use a deterministic filename based on timestamp
            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"capture_{timestamp_str}_{session_id[:6]}.pcap"
            filepath = Path(CONFIG["PCAP_OUTPUT_DIR"]) / filename
            
            # Scapy's wrpcap expects a list of raw byte strings or packet objects
            wrpcap(str(filepath), final_packets)
            
            message = f"PCAP file assembled successfully with {len(final_packets)} packets."
            
            # Clean up the buffer after assembly
            with buffer_lock:
                del TEMP_PACKET_BUFFERS[session_id]

        return True, message, filename

    except Scapy_Exception as e:
        logger.error(f"Scapy exception during PCAP assembly for session {session_id}: {e}")
        # Clean up buffer on major failure
        with buffer_lock:
             if session_id in TEMP_PACKET_BUFFERS:
                 del TEMP_PACKET_BUFFERS[session_id]
        return False, f"PCAP assembly error: {str(e)}", None
    except Exception as e:
        logger.error(f"General error in save_streamed_packets_as_pcap for session {session_id}: {e}")
        return False, f"Internal server error: {str(e)}", None


def serialize_conversations(conversations: Dict[Tuple[str, str], Any]) -> Dict[str, Any]:
    """
    Serializes conversation data for JSON output by converting tuple keys (ip1, ip2) 
    into string keys (e.g., "ip1-ip2").

    :param conversations: A dictionary where keys are conversation tuples (ip1, ip2)
                          and values are conversation statistics.
    :type conversations: Dict[Tuple[str, str], Any]
    :return: A dictionary with string keys suitable for JSON serialization.
    :rtype: Dict[str, Any]
    """
    return {f"{k[0]}-{k[1]}": v for k, v in conversations.items()}


# --- API ENDPOINTS ---

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    API endpoint to upload a PCAP file, perform initial network analysis 
    (conversation stats, total packets, protocol breakdown), extract UE session
    information, and generate a network graph JSON.

    :status 400: If no file is provided, no filename is selected, or the file is not a PCAP.
    :status 200: If the analysis is successful.
    :return: JSON response containing analysis results or an error message.
    :rtype: :class:`flask.Response`
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not file.filename.lower().endswith('.pcap'):
        return jsonify({'error': 'File is not a PCAP'}), 400

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    
    # 1. UE Session Analysis
    ue_sessions_json = initialize_analysis_for_ue(filepath)
    ue_sessions_json_path = os.path.join(UPLOAD_FOLDER, 'ue_sessions.json')
    with open(ue_sessions_json_path, 'w') as f:
        json.dump(ue_sessions_json, f, indent=2)

    # 2. General Conversation/Protocol Analysis
    analysis_result, error = initialize_analysis(filepath)
    if error:
        return jsonify({'error': 'Failed to analyze PCAP: ' + error}), 400

    # 3. Graph JSON Generation
    graph_json = build_graph_json(analysis_result['conversations'])
    graph_json_path = os.path.join(UPLOAD_FOLDER, 'conversations.json')
    with open(graph_json_path, 'w') as f:
        json.dump(graph_json, f, indent=2)

    response_data = {
        "total_packets": analysis_result['total_packets'],
        "ip_protocols": analysis_result['ip_protocols'],
        "graph": graph_json
    }

    return jsonify({'message': 'File analyzed successfully', 'analysis': response_data}), 200


@app.route('/conversations.json')
def get_conversations():
    """
    Serves the generated network conversation graph JSON file.

    :return: The 'conversations.json' file.
    :rtype: :class:`flask.Response`
    """
    return send_from_directory(UPLOAD_FOLDER, 'conversations.json')


@app.route('/ue_sessions') 
def get_ue_sessions():
    """
    Serves the User Equipment (UE) session analysis JSON file.

    :return: The 'ue_sessions.json' file.
    :rtype: :class:`flask.Response`
    """
    return send_from_directory(UPLOAD_FOLDER, 'ue_sessions.json')


@app.route('/role_assessment') 
def get_role_assessment_data():
    """
    Performs IP role assessment on the extracted packet data (from the prior 
    :func:`analyze` call's 'all_packets.json') and serves the results.

    :status 404: If the required 'all_packets.json' file is not found.
    :status 500: If there is an error writing the output file.
    :return: The 'role_assessment.json' file.
    :rtype: :class:`flask.Response`
    """
    input_packets_file = os.path.join(UPLOAD_FOLDER, 'all_packets.json')
    output_roles_file = os.path.join(UPLOAD_FOLDER, 'role_assessment.json')

    if not os.path.exists(input_packets_file):
        return jsonify({'error': f"Required file '{os.path.basename(input_packets_file)}' not found. Please upload a PCAP first via /analyze."}), 404

    # Call the imported analysis function
    inferred_roles = analyze_packets_and_assign_roles_optimized(input_packets_file)

    try:
        with open(output_roles_file, 'w') as f:
            json.dump(inferred_roles, f, indent=2)
        print(f"Successfully wrote inferred IP roles to '{output_roles_file}'")
    except IOError as e:
        return jsonify({'error': f"Error writing role assessment to file: {e}"}), 500

    return send_from_directory(UPLOAD_FOLDER, 'role_assessment.json')


@app.route("/save-pcap", methods=["POST"])
def save_pcap_stream():
    """
    API endpoint to receive chunked Base64-encoded packet data and assemble 
    the final PCAP file on the server. Used for real-time capture and generation.

    The request payload must contain 'session_id', a list of 'packets' (Base64 strings), 
    and an optional 'is_final_chunk' flag.

    :status 400: If the payload is invalid or missing required fields.
    :status 500: If a server error occurs during assembly.
    :return: JSON indicating success, message, and the final filename if applicable.
    :rtype: :class:`flask.Response`
    """
    logger.info("--- Received POST request for /save-pcap ---") 
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "Invalid JSON payload"}), 400

        session_id = data.get("session_id")
        packets = data.get("packets", [])
        is_final_chunk = data.get("is_final_chunk", False)

        if not session_id or not isinstance(packets, list):
            return jsonify({"success": False, "error": "Missing session_id or packets list"}), 400

        logger.info(f"Processing {len(packets)} packets for session {session_id}, final={is_final_chunk}")
        success, message, filename = save_streamed_packets_as_pcap(session_id, packets, is_final_chunk)

        if not success:
            return jsonify({"success": False, "error": message}), 500

        return jsonify({
            "success": True,
            "message": message,
            "filename": filename,
            "session_id": session_id
        }), 200

    except Exception as e:
        logger.error(f"Unhandled error in /save-pcap: {e}")
        return jsonify({"success": False, "error": f"Internal server error: {str(e)}"}), 500


@app.route("/generated_pcaps/<filename>", methods=["GET"])
def get_generated_pcap(filename: str):
    """
    Serves a generated PCAP file to the client for download from the 
    :data:`PCAP_GEN_OUTPUT_DIR`.

    :param filename: The name of the PCAP file to serve.
    :type filename: str
    :status 500: If there is an error serving the file.
    :return: The PCAP file as an attachment or an error JSON.
    :rtype: :class:`flask.Response`
    """
    try:
        # Prevent path traversal
        safe_filename = Path(filename).name
        filepath = os.path.join(PCAP_GEN_OUTPUT_DIR, safe_filename)

        logger.info(f"Serving PCAP file: {safe_filename}")
        return send_file(filepath, as_attachment=True)

    except Exception as e:
        logger.error(f"Error serving file {filename}: {e}")
        return jsonify({"success": False, "error": "Could not serve file."}), 500


@app.route('/analyze-saved-pcap/<filename>', methods=['GET'])
def analyze_saved_pcap(filename: str):
    """
    Analyzes a PCAP file that has already been saved on the server (typically 
    from a real-time capture).

    :param filename: The name of the PCAP file saved in :data:`PCAP_GEN_OUTPUT_DIR`.
    :type filename: str
    :status 404: If the file is not found on the server.
    :status 400: If the underlying PCAP analysis fails.
    :return: JSON response containing analysis results (including graph data) or an error message.
    :rtype: :class:`flask.Response`
    """
    # 1. Construct the secure file path
    filepath = os.path.join(PCAP_GEN_OUTPUT_DIR, filename)

    # 2. Verify the file exists
    if not os.path.exists(filepath):
        return jsonify({'error': 'File not found'}), 404
        
    # 3. Perform the analysis using the file path
    analysis_result, error = initialize_analysis(filepath)
    if error:
        return jsonify({'error': 'Failed to analyze PCAP: ' + error}), 400

    # 4. Build the graph and other analysis results
    graph_json = build_graph_json(analysis_result['conversations'])

    response_data = {
        "total_packets": analysis_result['total_packets'],
        "ip_protocols": analysis_result['ip_protocols'],
        "graph": graph_json
    }

    # 5. Return the analysis data
    return jsonify({'message': 'Analysis completed successfully', 'analysis': response_data}), 200


@app.route('/clustering', methods=['GET'])
def clusteringAnalysis():
    """
    Performs agglomerative clustering analysis on a specified PCAP file using node features.

    :query file: The filename of the PCAP to analyze (required query parameter).
    :query clusters: The desired number of clusters (optional, default=4).
    :query anomaly_threshold: Distance threshold for flagging anomalies (optional, default=2).
    :query distance_threshold: Max distance for clustering (optional query parameter).
    :type file: str
    :type clusters: int
    :type anomaly_threshold: int
    :type distance_threshold: float
    :status 400: If the 'file' parameter is missing.
    :status 404: If the specified file is not found.
    :return: JSON response containing the clustering results.
    :rtype: :class:`flask.Response`
    """
    filename = request.args.get("file")
    if not filename:
        return jsonify({"error": "file parameter is required"}), 400

    filepath = os.path.join(PCAP_GEN_OUTPUT_DIR, filename)

    if not os.path.exists(filepath):
        return jsonify({"error": "file not found"}), 404

    # Optional query params
    n_clusters = request.args.get("clusters", default=4, type=int)
    anomaly_threshold = request.args.get("anomaly_threshold", default=2, type=int)
    distance_threshold = request.args.get("distance_threshold", default=None, type=float)

    # Run analysis
    results = analyze_pcap(
        filepath,
        n_clusters=n_clusters,
        distance_threshold=distance_threshold,
        anomaly_threshold=anomaly_threshold
    )
    return jsonify(results)


@app.route('/save_results', methods=['GET'])
def save_results_endpoint():
    """
    Serves the saved results (JSON or CSV) of a clustering analysis from the 
    :data:`CLUSTERING_OUTPUT_DIR`.

    :query file: The base filename of the PCAP used for the analysis (required query parameter).
    :query type: The desired output format ("json" or "csv", optional query parameter, default="json").
    :type file: str
    :type type: str
    :status 400: If the 'file' parameter is missing.
    :status 404: If the requested result file is not found.
    :return: The requested analysis results file as an attachment.
    :rtype: :class:`flask.Response`
    """
    filename = request.args.get("file")
    filetype = request.args.get("type", default="json") 
    if not filename:
        return jsonify({"error": "file parameter is required"}), 400

    # Build the filename as save_results does
    base_name = os.path.splitext(filename)[0]
    send_file = base_name + (".csv" if filetype.lower() == "csv" else ".json")

    # Use the configured clustering output directory
    output_dir = CLUSTERING_OUTPUT_DIR 

    full_path = os.path.join(output_dir, send_file)

    if not os.path.exists(full_path):
        return jsonify({"error": f"{filetype.upper()} file not found: {send_file}", "path_checked": full_path}), 404

    # Send the requested file
    return send_from_directory(output_dir, send_file, as_attachment=True)


@app.route('/suggested_clusters', methods=['GET'])
def suggested_clusters():
    """
    Calculates and returns suggested cluster numbers using the Elbow method,
    and provides initial clustering and importance metrics based on the suggested number.

    :query file: The filename of the PCAP to analyze (required query parameter).
    :type file: str
    :status 400: If the 'file' parameter is missing.
    :status 404: If the specified file is not found.
    :return: JSON containing WCSS data, the elbow point, and cluster importance.
    :rtype: :class:`flask.Response`
    """
    filename = request.args.get("file")
    if not filename:
        return jsonify({"error": "file parameter is required"}), 400

    filepath = os.path.join(PCAP_GEN_OUTPUT_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "file not found"}), 404

    from agglomerative_clustering import (
        extract_features,
        suggest_clusters_elbow,
        cluster_nodes,
        compute_cluster_importance
    )

    df = extract_features(filepath)

    # Get elbow results
    result = suggest_clusters_elbow(df, max_clusters=10)
    wcss_data = result["wcss_data"]
    elbow_point = result["elbow_point"]

    # Cluster using elbow point
    n_clusters = elbow_point if elbow_point else 4
    df = cluster_nodes(df.copy(), n_clusters=n_clusters)

    # Compute cluster importance
    importance_sorted, most_important = compute_cluster_importance(df)

    return jsonify({
        "wcss_data": wcss_data,
        "elbow_point": elbow_point,
        "cluster_hierarchy": importance_sorted,
        "mostImportantCluster": most_important
    })


@app.route('/run_pipeline', methods=['POST'])
def run_pipeline_endpoint():
    """
    Runs the full IP role identification pipeline using a specified PCAP file and 
    a trained machine learning model.

    The request payload must contain 'pcap_file_path' (filename), 'model_name', 
    and optionally a list of 'selected_ips'.

    :json pcap_file_path: The filename of the PCAP file located in :data:`PCAP_GEN_OUTPUT_DIR`.
    :json model_name: The name of the machine learning model to use.
    :json selected_ips: A list of specific IPs to include in the analysis (optional).
    :type pcap_file_path: str
    :type model_name: str
    :type selected_ips: List[str]
    :status 400: If the payload is invalid or required fields are missing.
    :status 500: If a critical error occurs during pipeline execution.
    :return: JSON response containing the analysis report or an error message.
    :rtype: :class:`flask.Response`
    """
    if not request.is_json:
        return jsonify({"error": "Missing JSON in request"}), 400

    data = request.get_json()
    # The client sends the filename, we prepend the directory
    pcap_filename = data.get('pcap_file_path')
    model_name = data.get('model_name')

    if not pcap_filename or not model_name:
        return jsonify({"error": "Missing 'pcap_file_path' or 'model_name' in JSON body"}), 400

    pcap_file_path = os.path.join(PCAP_GEN_OUTPUT_DIR, pcap_filename)

    print(f"\n[API] Received request to run pipeline (Synchronous):")
    print(f"[API] PCAP Path: {pcap_file_path}")
    print(f"[API] Model Name: {model_name}")

    try:
        selected_ips = data.get('selected_ips', None)  # Expecting a list of IP strings
        if selected_ips is not None and not isinstance(selected_ips, list):
            return jsonify({"error": "'selected_ips' must be a list of IP addresses"}), 400

        analysis_report = run_ip_role_pipeline(pcap_file_path, model_name, selected_ips)
        
        if analysis_report.get('status') == 'success':
            response_data = {
                "pcap_file": pcap_filename,
                **analysis_report # Python 3.5+ dictionary merging
            }
            return jsonify(response_data), 200
        else:
            return jsonify(analysis_report), 500

    except Exception as e:
        error_message = f"Critical error during pipeline execution: {str(e)}"
        print(f"[API] Pipeline failed with error: {error_message}")
        return jsonify({"status": "error", "message": error_message}), 500
    

@app.route('/save_roles', methods=['GET'])
def save_roles_endpoint():
    """
    Serves the saved results (JSON or CSV) from the IP role identification pipeline.

    The results are typically saved in 'server/results' by the 
    :func:`~Preprocess.run_ip_role_pipeline` function.

    :query file: The base filename of the PCAP used for the analysis (required query parameter).
    :query type: The desired output format ("json" or "csv", optional query parameter, default="json").
    :type file: str
    :type type: str
    :status 400: If the 'file' parameter is missing or 'type' is invalid.
    :status 404: If the requested result file is not found.
    :return: The requested role assessment results file as an attachment.
    :rtype: :class:`flask.Response`
    """
    filename = request.args.get("file")
    filetype = request.args.get("type", default="json").lower()

    if not filename:
        return jsonify({"error": "file parameter is required"}), 400

    if filetype not in ["json", "csv"]:
        return jsonify({"error": "Invalid type, must be 'json' or 'csv'"}), 400

    base_name = os.path.splitext(filename)[0]
    output_filename = f"{base_name}.{filetype}"
    output_dir = os.path.join(os.getcwd(), "server", "results")  # Assuming fixed output dir for roles

    full_path = os.path.join(output_dir, output_filename)

    if not os.path.exists(full_path):
        return jsonify({"error": f"{filetype.upper()} file not found: {output_filename}", "path_checked": full_path}), 404

    return send_from_directory(output_dir, output_filename, as_attachment=True)


if __name__ == '__main__':
    # Use a specific port and configuration suitable for development/production
    # The default is (debug=True, threaded=False) which is fine for development.
    app.run(debug=True, threaded=False)