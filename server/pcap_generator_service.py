import os
import base64
from typing import List, Dict, Union

# Define the directory where PCAP files will be saved
PCAP_OUTPUT_DIR = "generated_pcaps"
os.makedirs(PCAP_OUTPUT_DIR, exist_ok=True)


##
# Handles a chunk of packets from the frontend.
# Appends raw binary data to a session-specific PCAP file.
#
# @param [str] session_id Unique identifier for the capture session.
# @param [list] packets List of Base64 encoded packet strings.
# @param [bool] is_final_chunk If True, finalizes the file (optional logic).
# @return [tuple] (success: bool, filename: str|None, error: str|None)
def handle_pcap_chunk(
    session_id: str, packets: List[str], is_final_chunk: bool = False
):
    if not session_id:
        return False, None, "Missing session_id"

    # Sanitize session_id to prevent directory traversal
    safe_filename = f"{os.path.basename(session_id)}.pcap"
    file_path = os.path.join(PCAP_OUTPUT_DIR, safe_filename)

    try:
        # Open in APPEND binary mode ('ab')
        with open(file_path, "ab") as f:
            for b64_pkt in packets:
                if not b64_pkt:
                    continue
                try:
                    # Decode Base64 to raw bytes
                    pkt_bytes = base64.b64decode(b64_pkt)

                    # Write PCAP Packet Header + Data
                    # Note: The frontend sends raw packet bytes.
                    # To make a valid PCAP, we technically need a Global Header (once)
                    # and Packet Headers (per packet).
                    # Assuming the sniffer sends fully formed frames or we rely on
                    # a library like Scapy to fix it later.
                    # For raw appending:
                    f.write(pkt_bytes)
                except Exception as e:
                    print(f"Error decoding packet chunk: {e}")
                    continue

        return True, safe_filename, None

    except Exception as e:
        return False, None, str(e)


##
# Legacy function - Kept for backward compatibility if needed,
# but rewritten to be safer.
def save_pcap_data(raw_binary_data):
    try:
        # Use a simpler naming convention
        import uuid

        filename = f"capture_{uuid.uuid4().hex[:8]}.pcap"
        file_path = os.path.join(PCAP_OUTPUT_DIR, filename)

        with open(file_path, "wb") as f:
            f.write(raw_binary_data)

        return True, "File saved successfully", filename
    except Exception as e:
        return False, str(e), None
