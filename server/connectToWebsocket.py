import websocket
import json
import base64
import requests
import time
import uuid
import threading
import os

# --- Configuration (Dynamic parameters removed from here) ---
API_URL = "http://127.0.0.1:5000"
CHUNK_SIZE = 1000  # Number of packets to send per HTTP chunk
MAX_RETRIES = 3  # Max retry attempts for API calls
# CAPTURE_DURATION is now passed dynamically

# --- Global State ---
raw_packets = []
is_capturing = False
session_id = None
filename = None

# --- Utility Functions ---


def generate_unique_id():
    """Generates a unique ID for the PCAP session."""
    return f"pcap_{uuid.uuid4().hex}"


def convert_tuple_keys_to_str(obj):
    """Recursively converts all tuple keys in a dictionary to string keys."""
    if isinstance(obj, dict):
        new_dict = {}
        for k, v in obj.items():
            v = convert_tuple_keys_to_str(v)
            if isinstance(k, tuple):
                new_key = "|".join(map(str, k))
            else:
                new_key = k
            new_dict[new_key] = v
        return new_dict

    elif isinstance(obj, list):
        return [convert_tuple_keys_to_str(item) for item in obj]

    else:
        return obj


# --- WebSocket Handlers (Unchanged) ---


def on_message(ws, message):
    global is_capturing
    try:
        msg_obj = json.loads(message)
    except json.JSONDecodeError:
        return

    if msg_obj.get("type") == "STATUS":
        status = msg_obj.get("status")
        if status == "CAPTURE_STARTED":
            is_capturing = True
            print("Capture started on server.")
        elif status == "CAPTURE_STOPPED":
            is_capturing = False
            print("Capture stopped on server.")
        return

    if msg_obj.get("type") == "PACKET_DATA" and isinstance(msg_obj.get("packet"), str):
        base64_packet = msg_obj["packet"]
        try:
            packet_length = len(base64.b64decode(base64_packet))
            if packet_length < 4:
                return
            raw_packets.append(base64_packet)
        except Exception:
            return


def on_error(ws, error):
    print(f"WebSocket Error: {error}")


def on_close(ws, close_status_code, close_msg):
    global is_capturing
    is_capturing = False
    print(
        f"WebSocket Connection Closed. Status: {close_status_code}, Message: {close_msg}"
    )


def on_open(ws):
    print(f"WebSocket connection established.")
    send_control_command(ws, "START_CAPTURE")


def send_control_command(ws, command):
    if ws.sock and ws.sock.connected:
        payload = json.dumps({"command": command, "timestamp": int(time.time() * 1000)})
        ws.send(payload)
    else:
        print(f"Cannot send command {command}: WebSocket not connected.")


# --- API Interaction Functions (Unchanged) ---


def send_packets_to_flask(
    chunk, chunk_index, total_chunks, is_final_chunk, current_session_id
):
    """Sends a chunk of Base64 packets to the Flask API's /save-pcap endpoint."""
    global filename
    attempt = 0

    payload = {
        "session_id": current_session_id,
        "packets": chunk,
        "is_final_chunk": is_final_chunk,
    }

    while attempt < MAX_RETRIES:
        attempt += 1
        try:
            print(
                f"Sending chunk {chunk_index + 1}/{total_chunks} (Attempt {attempt})..."
            )
            response = requests.post(f"{API_URL}/save-pcap", json=payload, timeout=30)
            if not response.content:
                raise Exception(f"Empty response received from API.")
            data = response.json()

            if response.ok and data.get("success"):
                if is_final_chunk and data.get("filename"):
                    filename = data["filename"]
                return data
            else:
                error_message = (
                    data.get("error") or f"Unknown API error: {response.status_code}"
                )
                print(f"API error (attempt {attempt}): {error_message}")
                raise Exception(error_message)

        except (requests.exceptions.RequestException, Exception) as e:
            print(f"Error processing chunk {chunk_index + 1} (Attempt {attempt}): {e}")
            if attempt == MAX_RETRIES:
                raise Exception(
                    f"Failed to process chunk {chunk_index + 1} after {MAX_RETRIES} attempts. Last error: {e}"
                )
            time.sleep(1 * (2**attempt))


def call_automated_analysis_endpoint_server_side(ws, pcap_filename):
    """
    Calls the new server-side analysis endpoint using the saved filename
    and sends a completion message back through the WebSocket.
    """
    analysis_url = f"{API_URL}/analyze-saved-pcap-full/{pcap_filename}"
    params = {"model_name": "rule_based"}

    print(f"\nPhase 2: Calling server-side analysis on '{pcap_filename}'...")

    notification = {
        "type": "ANALYSIS_STATUS",
        "status": "FAILED",
        "filename": pcap_filename,
        "message": "Analysis started but failed unexpectedly.",
    }

    headers = {
        "Accept": "application/json",
    }

    try:
        response = requests.get(
            analysis_url, params=params, headers=headers, timeout=180
        )
        analysis_data = None

        if response.status_code == 200:
            analysis_data = response.json()
            print("\nServer-Side Automated Analysis Complete!")
            print(json.dumps(analysis_data, indent=4))

            notification["status"] = "COMPLETE"
            notification["message"] = f"Analysis complete for {pcap_filename}."
        else:
            error_details = f"Status {response.status_code}"
            try:
                error_details += f": {response.json().get('error', response.text[:50])}"
            except:
                error_details += f": {response.text[:50]}..."

            print(f"\nServer-Side Analysis Failed: {error_details}")
            notification["message"] = f"Analysis failed: {error_details}"

    except requests.exceptions.RequestException as e:
        print(f"\nRequest to /analyze-saved-pcap-full failed: {e}")
        notification["message"] = f"Network request failed: {str(e)}"

    # --- FINAL NOTIFICATION VIA WEBSOCKET ---
    if ws.sock and ws.sock.connected:
        ws.send(json.dumps(notification))
        print(f"Sent WebSocket notification: {notification['status']}")


# --- Core Pipeline Logic ---


def execute_pipeline(ws_url, ws, capture_duration):  # USED capture_duration
    """
    The main logic to run inside the background thread.
    1. Wait for capture.
    2. Stop capture.
    3. Upload and trigger analysis.
    """
    global session_id

    # Wait for the defined duration (using capture_duration argument)
    print(f"\nCapturing packets for {capture_duration} seconds...")
    try:
        time.sleep(capture_duration)  # USED capture_duration
    except KeyboardInterrupt:
        print("Capture interrupted by user.")

    # 1. Stop Capture
    send_control_command(ws, "STOP_CAPTURE")
    time.sleep(0.5)

    if not raw_packets:
        print("No packets captured to upload.")
        return

    # --- Phase 1: Upload Packets to /save-pcap (PCAP GENERATION) ---
    session_id = generate_unique_id()
    total_packets = len(raw_packets)
    total_chunks = (total_packets + CHUNK_SIZE - 1) // CHUNK_SIZE
    print(f"\nPhase 1: Uploading {total_packets} packets to /save-pcap...")

    try:
        for i in range(total_chunks):
            start = i * CHUNK_SIZE
            end = min(start + CHUNK_SIZE, total_packets)
            chunk = raw_packets[start:end]
            is_final_chunk = i == total_chunks - 1

            send_packets_to_flask(chunk, i, total_chunks, is_final_chunk, session_id)

        if not filename:
            raise Exception(
                "PCAP file was not created on the server (no filename returned)."
            )

    except Exception as e:
        print(f"\nPhase 1 (PCAP Save) Failed: {e}")
        # Send failure notification before closing
        if ws.sock and ws.sock.connected:
            failure_notification = {
                "type": "ANALYSIS_STATUS",
                "status": "FAILED",
                "message": f"PCAP Generation failed: {str(e)}",
            }
            ws.send(json.dumps(failure_notification))
            print("Sent WebSocket notification: FAILED (Phase 1)")
        return

    # --- Phase 2: Call Server-Side Automated Analysis and NOTIFY ---
    call_automated_analysis_endpoint_server_side(ws, filename)

    # Close the WebSocket connection gracefully
    print("\nClosing connection...")
    ws.close()


# --- Public Entry Point for Flask ---


def startWebSocketClient(ws_url, capture_duration):  # ADDED capture_duration
    """
    Initializes the WebSocket client and spawns the execution pipeline in a background thread.
    This function returns immediately (non-blocking).
    """
    global raw_packets, filename
    # Reset state for a new run
    raw_packets.clear()
    filename = None
    print(f"Starting WebSocket client for URL: {ws_url}...")

    # 1. Setup WebSocket client
    ws = websocket.WebSocketApp(
        ws_url,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
    )

    # 2. Run WebSocket client in a thread
    wst = threading.Thread(target=ws.run_forever, daemon=True)
    wst.start()

    # 3. Start the execution pipeline (timing, upload, analysis) in a separate thread
    # PASSED capture_duration to execute_pipeline
    pipeline_thread = threading.Thread(
        target=execute_pipeline,
        args=(
            ws_url,
            ws,
            capture_duration,
        ),
        daemon=True,
    )
    pipeline_thread.start()

    print("Background pipeline started. Check server logs for progress.")
    return True


if __name__ == "__main__":
    # Test execution when run directly (using a default URL and duration)
    # The default duration must be passed here
    startWebSocketClient("ws://127.0.0.1:5001", 30)
    # Keep the main thread alive so the daemon threads can run
    while True:
        time.sleep(1)
